from __future__ import annotations

from datetime import datetime, timedelta
from secrets import compare_digest

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.api.endpoints.endpoints import _endpoint_payload
from app.agent_protocol import (
    UnsupportedAgentProtocol,
    protocol_compatibility_payload,
    require_supported_agent_protocol,
)
from app.auth import Principal, current_principal, require_device_principal
from app.authorization import record_audit_event, require_permission, require_scope, scope_clause
from app.db import DatabaseStore, get_store
from app.device_identity import (
    device_secret_hash,
    enrollment_secret_hash,
    exchange_request_hash,
    generate_enrollment_token,
    parse_enrollment_token,
)
from app.hierarchy import load_scope, validate_scope_filter
from app.models import (
    Client,
    DeviceCredential,
    Endpoint,
    EnrollmentRedemption,
    EnrollmentToken,
    InstallerProfile,
    Location,
)
from app.schemas.contracts import (
    AgentMeResponse,
    DeviceCredentialMaterialRequest,
    DeviceCredentialResponse,
    EnrollmentExchangeRequest,
    EnrollmentExchangeResponse,
    EnrollmentTokenCreateRequest,
    EnrollmentTokenCreateResponse,
    EnrollmentTokenListResponse,
    EnrollmentTokenResponse,
)
from app.utils import (
    generate_prefixed_id,
    normalize_agent_fingerprint,
    normalize_optional_string,
    normalize_platform,
    normalize_required_string,
    to_utc_z,
    utc_now,
)

router = APIRouter(tags=["device-identity"])

_HASH_KEY_ID = "primary"


def _hmac_key(request: Request) -> bytes:
    key = getattr(request.app.state, "credential_hmac_key", None)
    if not isinstance(key, bytes):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="device credential service is not configured",
        )
    return key


def _invalid_enrollment_credentials() -> HTTPException:
    return HTTPException(status_code=401, detail="authentication required")


def _token_state(token: EnrollmentToken, *, now: str) -> str:
    if token.revoked_at is not None:
        return "revoked"
    if token.expires_at <= now:
        return "expired"
    if token.use_count >= token.max_uses:
        return "exhausted"
    return "active"


def _token_payload(token: EnrollmentToken, *, now: str) -> dict[str, object]:
    return {
        "token_id": token.token_id,
        "client_id": token.client_id,
        "location_id": token.location_id,
        "installer_profile_id": token.installer_profile_id,
        "platform": token.platform,
        "approval_policy": token.approval_policy,
        "state": _token_state(token, now=now),
        "expires_at": token.expires_at,
        "max_uses": token.max_uses,
        "use_count": token.use_count,
        "revoked_at": token.revoked_at,
        "created_by": token.created_by,
        "created_at": token.created_at,
        "updated_at": token.updated_at,
    }


def _credential_payload(credential: DeviceCredential) -> dict[str, object]:
    return {
        "credential_id": credential.credential_id,
        "endpoint_id": credential.endpoint_id,
        "status": credential.status,
        "replaced_by_credential_id": credential.replaced_by_credential_id,
        "last_used_at": credential.last_used_at,
        "expires_at": credential.expires_at,
        "created_at": credential.created_at,
        "updated_at": credential.updated_at,
        "replaced_at": credential.replaced_at,
        "revoked_at": credential.revoked_at,
    }


def _device_endpoint_payload(endpoint: Endpoint) -> dict[str, object]:
    payload = _endpoint_payload(endpoint)
    payload.update(
        {
            "installation_id": endpoint.installation_id,
            "credential_mode": endpoint.credential_mode,
            "enrollment_token_id": endpoint.enrollment_token_id,
        }
    )
    return payload


def _exchange_payload(
    endpoint: Endpoint,
    credential: DeviceCredential,
    *,
    replayed: bool,
) -> dict[str, object]:
    return {
        "endpoint": _device_endpoint_payload(endpoint),
        "credential": _credential_payload(credential),
        "protocol": protocol_compatibility_payload(endpoint.protocol_version),
        "replayed": replayed,
    }


def _credential_expiry(request: Request, now_dt: datetime) -> str:
    lifetime_days = int(getattr(request.app.state, "device_credential_lifetime_days", 90))
    return to_utc_z(now_dt + timedelta(days=lifetime_days))


@router.post(
    "/api/enrollment-tokens",
    status_code=status.HTTP_201_CREATED,
    response_model=EnrollmentTokenCreateResponse,
)
def create_enrollment_token(
    payload: EnrollmentTokenCreateRequest,
    request: Request,
    response: Response,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("enrollment.manage")),
) -> dict[str, object]:
    key = _hmac_key(request)
    now_dt = utc_now()
    now = to_utc_z(now_dt)
    expires_at = to_utc_z(now_dt + timedelta(minutes=payload.expires_in_minutes))
    client_id = normalize_required_string(payload.client_id, "client_id")
    location_id = normalize_required_string(payload.location_id, "location_id")
    requested_platform = payload.platform.value if payload.platform is not None else None

    with store.session() as session:
        with session.begin():
            client, location = load_scope(session, client_id, location_id)
            require_scope(
                principal,
                "enrollment.manage",
                client_id=client.client_id,
                location_id=location.location_id,
            )
            if client.state != "active" or location.state != "active":
                raise HTTPException(status_code=409, detail="client and location must be active")

            installer_profile_id = None
            platform = requested_platform
            if payload.installer_profile_id is not None:
                installer_profile_id = normalize_required_string(
                    payload.installer_profile_id,
                    "installer_profile_id",
                )
                profile = session.get(InstallerProfile, installer_profile_id)
                if profile is None:
                    raise HTTPException(status_code=404, detail="installer profile not found")
                if profile.client_id != client_id or profile.location_id != location_id:
                    raise HTTPException(
                        status_code=422,
                        detail="installer profile does not belong to client and location",
                    )
                if platform is not None and profile.platform != platform:
                    raise HTTPException(
                        status_code=422,
                        detail="installer profile platform does not match platform",
                    )
                platform = profile.platform

            token_id = generate_prefixed_id("et")
            plaintext_token, secret = generate_enrollment_token(token_id)
            token = EnrollmentToken(
                token_id=token_id,
                secret_hash=enrollment_secret_hash(key, token_id, secret),
                hash_key_id=_HASH_KEY_ID,
                client_id=client.client_id,
                location_id=location.location_id,
                installer_profile_id=installer_profile_id,
                platform=platform,
                approval_policy=payload.approval_policy.value,
                expires_at=expires_at,
                max_uses=payload.max_uses,
                use_count=0,
                revoked_at=None,
                created_by=principal.audit_actor,
                created_at=now,
                updated_at=now,
            )
            session.add(token)
            session.flush()
            record_audit_event(
                session,
                event_type="enrollment_token_created",
                principal=principal,
                client_id=token.client_id,
                location_id=token.location_id,
                target_type="enrollment_token",
                target_id=token.token_id,
                metadata={
                    "approval_policy": token.approval_policy,
                    "expires_at": token.expires_at,
                    "max_uses": token.max_uses,
                },
                created_at=now,
            )
            result = _token_payload(token, now=now)
            result["token"] = plaintext_token

    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    return result


@router.get("/api/enrollment-tokens", response_model=EnrollmentTokenListResponse)
def list_enrollment_tokens(
    client_id: str | None = Query(None),
    location_id: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("enrollment.read")),
) -> dict[str, list[dict[str, object]]]:
    now_dt = utc_now()
    now = to_utc_z(now_dt)
    with store.session() as session:
        normalized_client_id, normalized_location_id = validate_scope_filter(
            session,
            client_id=client_id,
            location_id=location_id,
        )
        if normalized_client_id is not None:
            require_scope(
                principal,
                "enrollment.read",
                client_id=normalized_client_id,
                location_id=normalized_location_id,
            )
        statement = select(EnrollmentToken).where(
            scope_clause(
                principal,
                "enrollment.read",
                EnrollmentToken.client_id,
                EnrollmentToken.location_id,
            )
        )
        if normalized_client_id is not None:
            statement = statement.where(EnrollmentToken.client_id == normalized_client_id)
        if normalized_location_id is not None:
            statement = statement.where(EnrollmentToken.location_id == normalized_location_id)
        tokens = session.scalars(
            statement.order_by(EnrollmentToken.created_at.desc(), EnrollmentToken.token_id.desc())
        ).all()
        return {"items": [_token_payload(token, now=now) for token in tokens]}


@router.post(
    "/api/enrollment-tokens/{token_id}/revoke",
    response_model=EnrollmentTokenResponse,
)
def revoke_enrollment_token(
    token_id: str,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("enrollment.manage")),
) -> dict[str, object]:
    normalized_token_id = normalize_required_string(token_id, "token_id")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            token = session.scalar(
                select(EnrollmentToken)
                .where(
                    EnrollmentToken.token_id == normalized_token_id,
                    scope_clause(
                        principal,
                        "enrollment.manage",
                        EnrollmentToken.client_id,
                        EnrollmentToken.location_id,
                    ),
                )
                .with_for_update()
            )
            if token is None:
                raise HTTPException(status_code=404, detail="enrollment token not found")
            if token.revoked_at is None:
                token.revoked_at = now
                token.updated_at = now
                session.flush()
            record_audit_event(
                session,
                event_type="enrollment_token_revoked",
                principal=principal,
                client_id=token.client_id,
                location_id=token.location_id,
                target_type="enrollment_token",
                target_id=token.token_id,
                created_at=now,
            )
            return _token_payload(token, now=now)


@router.post(
    "/api/agent/bootstrap",
    status_code=status.HTTP_201_CREATED,
    response_model=EnrollmentExchangeResponse,
    responses={200: {"model": EnrollmentExchangeResponse}},
)
def exchange_enrollment_token(
    payload: EnrollmentExchangeRequest,
    request: Request,
    response: Response,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(current_principal),
) -> dict[str, object]:
    key = _hmac_key(request)
    try:
        require_supported_agent_protocol(payload.protocol_version)
    except UnsupportedAgentProtocol as exc:
        raise HTTPException(
            status_code=status.HTTP_426_UPGRADE_REQUIRED,
            detail={
                "code": "unsupported_agent_protocol",
                "received_version": exc.protocol_version,
                "minimum_version": "sha-agent-v1",
                "supported_versions": ["sha-agent-v1"],
            },
            headers={"X-SHA-Supported-Protocol-Versions": "sha-agent-v1"},
        ) from exc
    bearer = request.headers.get("authorization", "")
    raw_token = bearer[7:].strip() if bearer.lower().startswith("bearer ") else ""
    parsed_token = parse_enrollment_token(raw_token)
    if (
        parsed_token is None
        or principal.auth_method != "enrollment_token"
        or principal.enrollment_token_id != parsed_token[0]
    ):
        raise _invalid_enrollment_credentials()
    token_id, enrollment_secret = parsed_token

    installation_id = payload.installation_id
    credential_id = payload.credential_id
    credential_secret = payload.credential_secret.get_secret_value()
    agent_fingerprint = normalize_agent_fingerprint(payload.agent_fingerprint)
    hostname = normalize_required_string(payload.hostname, "hostname")
    platform = normalize_platform(payload.platform.value)
    platform_version = (
        normalize_optional_string(payload.platform_version, "platform_version")
        if payload.platform_version is not None
        else None
    )
    agent_version = normalize_required_string(payload.agent_version, "agent_version")
    request_values: dict[str, object] = {
        "installation_id": installation_id,
        "credential_id": credential_id,
        "credential_secret": credential_secret,
        "agent_fingerprint": agent_fingerprint,
        "hostname": hostname,
        "platform": platform,
        "platform_version": platform_version,
        "agent_version": agent_version,
        "protocol_version": payload.protocol_version,
        "architecture": payload.architecture,
    }
    request_hash = exchange_request_hash(key, token_id, request_values)
    now_dt = utc_now()
    now = to_utc_z(now_dt)

    try:
        with store.session() as session:
            with session.begin():
                token = session.scalar(
                    select(EnrollmentToken)
                    .where(EnrollmentToken.token_id == token_id)
                    .with_for_update()
                )
                supplied_token_hash = enrollment_secret_hash(key, token_id, enrollment_secret)
                expected_token_hash = token.secret_hash if token is not None else "0" * 64
                token_secret_matches = compare_digest(supplied_token_hash, expected_token_hash)
                if (
                    token is None
                    or not token_secret_matches
                    or token.hash_key_id != _HASH_KEY_ID
                ):
                    raise _invalid_enrollment_credentials()

                redemption = session.scalar(
                    select(EnrollmentRedemption).where(
                        EnrollmentRedemption.enrollment_token_id == token_id,
                        EnrollmentRedemption.installation_id == installation_id,
                    )
                )
                if redemption is not None:
                    request_matches = compare_digest(request_hash, redemption.request_hash)
                    credential = session.get(DeviceCredential, redemption.credential_id)
                    endpoint = session.get(Endpoint, redemption.endpoint_id)
                    supplied_credential_hash = device_secret_hash(
                        key,
                        credential_id,
                        credential_secret,
                    )
                    expected_credential_hash = (
                        credential.secret_hash if credential is not None else "0" * 64
                    )
                    credential_matches = compare_digest(
                        supplied_credential_hash,
                        expected_credential_hash,
                    )
                    if not request_matches:
                        raise HTTPException(
                            status_code=409,
                            detail="enrollment exchange conflicts with an existing installation",
                        )
                    if (
                        credential is None
                        or endpoint is None
                        or credential.credential_id != credential_id
                        or credential.status != "active"
                        or (credential.expires_at is not None and credential.expires_at <= now)
                        or not credential_matches
                    ):
                        raise _invalid_enrollment_credentials()
                    response.status_code = status.HTTP_200_OK
                    response.headers["Cache-Control"] = "private, no-store"
                    response.headers["Pragma"] = "no-cache"
                    record_audit_event(
                        session,
                        event_type="enrollment_token_redeemed",
                        principal=principal,
                        client_id=endpoint.client_id,
                        location_id=endpoint.location_id,
                        endpoint_id=endpoint.endpoint_id,
                        target_type="enrollment_token",
                        target_id=token.token_id,
                        metadata={"replayed": True},
                        created_at=now,
                    )
                    return _exchange_payload(endpoint, credential, replayed=True)

                if (
                    token.revoked_at is not None
                    or token.expires_at <= now
                    or token.use_count >= token.max_uses
                ):
                    raise _invalid_enrollment_credentials()
                if token.platform is not None and token.platform != platform:
                    raise HTTPException(
                        status_code=422,
                        detail="endpoint platform does not match enrollment token",
                    )

                client = session.get(Client, token.client_id)
                location = session.scalar(
                    select(Location).where(
                        Location.location_id == token.location_id,
                        Location.client_id == token.client_id,
                    )
                )
                if (
                    client is None
                    or location is None
                    or client.state != "active"
                    or location.state != "active"
                ):
                    raise _invalid_enrollment_credentials()

                if (
                    session.scalar(
                        select(Endpoint.endpoint_id).where(
                            Endpoint.installation_id == installation_id
                        )
                    )
                    is not None
                    or session.get(DeviceCredential, credential_id) is not None
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="enrollment exchange conflicts with an existing installation",
                    )
                legacy_endpoint = session.scalar(
                    select(Endpoint)
                    .where(Endpoint.agent_fingerprint == agent_fingerprint)
                    .with_for_update()
                )
                if legacy_endpoint is not None and (
                    legacy_endpoint.credential_mode != "legacy_shared"
                    or legacy_endpoint.client_id != client.client_id
                    or legacy_endpoint.location_id != location.location_id
                    or legacy_endpoint.platform != platform
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="enrollment exchange conflicts with an existing installation",
                    )

                consumed_use_count = session.scalar(
                    update(EnrollmentToken)
                    .where(
                        EnrollmentToken.token_id == token.token_id,
                        EnrollmentToken.revoked_at.is_(None),
                        EnrollmentToken.expires_at > now,
                        EnrollmentToken.use_count < EnrollmentToken.max_uses,
                    )
                    .values(
                        use_count=EnrollmentToken.use_count + 1,
                        updated_at=now,
                    )
                    .returning(EnrollmentToken.use_count)
                )
                if consumed_use_count is None:
                    raise _invalid_enrollment_credentials()
                token.use_count = consumed_use_count
                token.updated_at = now
                if legacy_endpoint is None:
                    endpoint = Endpoint(
                        endpoint_id=generate_prefixed_id("ep"),
                        agent_fingerprint=agent_fingerprint,
                        hostname=hostname,
                        platform=platform,
                        platform_version=platform_version,
                        platform_profile=None,
                        agent_version=agent_version,
                        protocol_version=payload.protocol_version,
                        architecture=payload.architecture,
                        installation_id=installation_id,
                        credential_mode="device",
                        enrollment_token_id=token.token_id,
                        client_id=client.client_id,
                        location_id=location.location_id,
                        tenant_id=client.key,
                        site_id=location.key,
                        status="active" if token.approval_policy == "approved" else "pending",
                        connectivity_status=None,
                        declared_capabilities_json=None,
                        capability_manifest_json=None,
                        execution_hooks_json=None,
                        last_seen_at=now,
                        last_heartbeat_at=None,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(endpoint)
                else:
                    endpoint = legacy_endpoint
                    endpoint.hostname = hostname
                    endpoint.platform_version = platform_version
                    endpoint.platform_profile = None
                    endpoint.agent_version = agent_version
                    endpoint.protocol_version = payload.protocol_version
                    endpoint.architecture = payload.architecture
                    endpoint.installation_id = installation_id
                    endpoint.credential_mode = "device"
                    endpoint.enrollment_token_id = token.token_id
                    endpoint.status = (
                        "active" if token.approval_policy == "approved" else "pending"
                    )
                    endpoint.connectivity_status = None
                    endpoint.declared_capabilities_json = None
                    endpoint.capability_manifest_json = None
                    endpoint.execution_hooks_json = None
                    endpoint.last_seen_at = now
                    endpoint.last_heartbeat_at = None
                    endpoint.updated_at = now
                session.flush()

                credential = DeviceCredential(
                    credential_id=credential_id,
                    endpoint_id=endpoint.endpoint_id,
                    secret_hash=device_secret_hash(key, credential_id, credential_secret),
                    hash_key_id=_HASH_KEY_ID,
                    status="active",
                    replaced_by_credential_id=None,
                    last_used_at=None,
                    expires_at=_credential_expiry(request, now_dt),
                    created_at=now,
                    updated_at=now,
                    replaced_at=None,
                    revoked_at=None,
                )
                session.add(credential)
                session.flush()
                session.add(
                    EnrollmentRedemption(
                        redemption_id=generate_prefixed_id("er"),
                        enrollment_token_id=token.token_id,
                        installation_id=installation_id,
                        endpoint_id=endpoint.endpoint_id,
                        credential_id=credential.credential_id,
                        request_hash=request_hash,
                        created_at=now,
                    )
                )
                session.flush()
                record_audit_event(
                    session,
                    event_type="enrollment_token_redeemed",
                    principal=principal,
                    client_id=endpoint.client_id,
                    location_id=endpoint.location_id,
                    endpoint_id=endpoint.endpoint_id,
                    target_type="enrollment_token",
                    target_id=token.token_id,
                    metadata={"replayed": False},
                    created_at=now,
                )
                if legacy_endpoint is not None:
                    record_audit_event(
                        session,
                        event_type="legacy_reporter_migrated",
                        principal=principal,
                        client_id=endpoint.client_id,
                        location_id=endpoint.location_id,
                        endpoint_id=endpoint.endpoint_id,
                        target_type="endpoint",
                        target_id=endpoint.endpoint_id,
                        metadata={"protocol_version": payload.protocol_version},
                        created_at=now,
                    )
                result = _exchange_payload(endpoint, credential, replayed=False)
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="enrollment exchange conflicts with an existing installation",
        ) from exc

    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Pragma"] = "no-cache"
    return result


@router.get("/api/agent/me", response_model=AgentMeResponse)
def get_agent_identity(
    response: Response,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_device_principal),
) -> dict[str, object]:
    with store.session() as session:
        endpoint = session.get(Endpoint, principal.endpoint_id)
        credential = session.get(DeviceCredential, principal.credential_id)
        if endpoint is None or credential is None or credential.status != "active":
            raise HTTPException(status_code=401, detail="authentication required")
        result: dict[str, object] = {
            "endpoint": _device_endpoint_payload(endpoint),
            "credential": _credential_payload(credential),
            "protocol": protocol_compatibility_payload(endpoint.protocol_version),
        }
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Pragma"] = "no-cache"
    return result


@router.post(
    "/api/agent/credentials/rotate",
    response_model=DeviceCredentialResponse,
)
def rotate_device_credential(
    payload: DeviceCredentialMaterialRequest,
    request: Request,
    response: Response,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_device_principal),
) -> dict[str, object]:
    key = _hmac_key(request)
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Pragma"] = "no-cache"
    new_credential_id = payload.credential_id
    new_secret = payload.credential_secret.get_secret_value()
    new_hash = device_secret_hash(key, new_credential_id, new_secret)
    now_dt = utc_now()
    now = to_utc_z(now_dt)
    try:
        with store.session() as session:
            with session.begin():
                current = session.scalar(
                    select(DeviceCredential)
                    .where(DeviceCredential.credential_id == principal.credential_id)
                    .with_for_update()
                )
                if (
                    current is None
                    or current.endpoint_id != principal.endpoint_id
                    or current.status != "active"
                ):
                    raise HTTPException(status_code=401, detail="authentication required")
                if new_credential_id == current.credential_id:
                    if compare_digest(new_hash, current.secret_hash):
                        return _credential_payload(current)
                    raise HTTPException(
                        status_code=409,
                        detail="credential_id is already in use",
                    )
                if session.get(DeviceCredential, new_credential_id) is not None:
                    raise HTTPException(
                        status_code=409,
                        detail="credential_id is already in use",
                    )

                current.status = "replaced"
                current.updated_at = now
                current.replaced_at = now
                session.flush()
                replacement = DeviceCredential(
                    credential_id=new_credential_id,
                    endpoint_id=current.endpoint_id,
                    secret_hash=new_hash,
                    hash_key_id=_HASH_KEY_ID,
                    status="active",
                    replaced_by_credential_id=None,
                    last_used_at=None,
                    expires_at=_credential_expiry(request, now_dt),
                    created_at=now,
                    updated_at=now,
                    replaced_at=None,
                    revoked_at=None,
                )
                session.add(replacement)
                session.flush()
                current.replaced_by_credential_id = replacement.credential_id
                session.flush()
                endpoint = session.get(Endpoint, current.endpoint_id)
                if endpoint is None:
                    raise HTTPException(status_code=401, detail="authentication required")
                record_audit_event(
                    session,
                    event_type="device_credential_rotated",
                    principal=principal,
                    client_id=endpoint.client_id,
                    location_id=endpoint.location_id,
                    endpoint_id=endpoint.endpoint_id,
                    target_type="device_credential",
                    target_id=replacement.credential_id,
                    metadata={"replaced_credential_id": current.credential_id},
                    created_at=now,
                )
                result = _credential_payload(replacement)
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="credential_id is already in use") from exc

    return result


@router.post(
    "/api/device-credentials/{credential_id}/revoke",
    response_model=DeviceCredentialResponse,
)
def revoke_device_credential(
    credential_id: str,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("device_credential.manage")),
) -> dict[str, object]:
    normalized_credential_id = normalize_required_string(credential_id, "credential_id")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            credential = session.scalar(
                select(DeviceCredential)
                .join(Endpoint, Endpoint.endpoint_id == DeviceCredential.endpoint_id)
                .where(
                    DeviceCredential.credential_id == normalized_credential_id,
                    scope_clause(
                        principal,
                        "device_credential.manage",
                        Endpoint.client_id,
                        Endpoint.location_id,
                    ),
                )
                .with_for_update()
            )
            if credential is None:
                raise HTTPException(status_code=404, detail="device credential not found")
            if credential.status != "revoked":
                credential.status = "revoked"
                credential.revoked_at = now
                credential.updated_at = now
                session.flush()
            endpoint = session.get(Endpoint, credential.endpoint_id)
            if endpoint is None:
                raise HTTPException(status_code=404, detail="device credential not found")
            record_audit_event(
                session,
                event_type="device_credential_revoked",
                principal=principal,
                client_id=endpoint.client_id,
                location_id=endpoint.location_id,
                endpoint_id=endpoint.endpoint_id,
                target_type="device_credential",
                target_id=credential.credential_id,
                created_at=now,
            )
            return _credential_payload(credential)
