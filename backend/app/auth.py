from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from secrets import compare_digest
from typing import Awaitable, Callable, Literal
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response
from sqlalchemy import select
from starlette.responses import JSONResponse

from app.authorization import (
    ALL_PERMISSIONS,
    LEGACY_OPERATOR_PERMISSIONS,
    READONLY_PERMISSIONS,
    ScopeGrant,
    load_user_grants,
    synthetic_global_grant,
)
from app.agent_protocol import LegacyReporterPolicy
from app.browser_auth import OidcClientConfig, SESSION_COOKIE_NAME, csrf_token, keyed_hash
from app.db import DatabaseStore
from app.device_identity import device_secret_hash, parse_device_credential, parse_enrollment_token
from app.models import BrowserSession, DeviceCredential, Endpoint, OidcIdentity, User
from app.utils import to_utc_z, utc_now

_OPEN_PATHS = {
    "/health",
    "/api/auth/oidc/login",
    "/api/auth/oidc/callback",
}
_EXTERNAL_ROLES = {"operator", "readonly"}


@dataclass(frozen=True)
class Principal:
    subject: str
    display_name: str
    role: Literal["operator", "readonly", "human", "agent", "enrollment"]
    auth_method: Literal[
        "development_open",
        "operator_token",
        "readonly_token",
        "agent_token",
        "device_credential",
        "enrollment_token",
        "external_proxy",
        "oidc_session",
    ]
    user_id: str | None = None
    identity_id: str | None = None
    session_id: str | None = None
    grants: tuple[ScopeGrant, ...] = ()
    endpoint_id: str | None = None
    credential_id: str | None = None
    enrollment_token_id: str | None = None

    @property
    def audit_actor(self) -> str:
        return self.subject


def current_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        raise HTTPException(status_code=401, detail="authenticated principal is required")
    return principal


def require_operator_principal(request: Request) -> Principal:
    principal = current_principal(request)
    if principal.role == "operator":
        return principal
    if principal.role == "human" and any(
        grant.scope_type == "global" and "identity.manage" in grant.permissions
        for grant in principal.grants
    ):
        return principal
    raise HTTPException(status_code=403, detail="operator role is required")


def require_device_principal(request: Request) -> Principal:
    principal = current_principal(request)
    if (
        principal.auth_method != "device_credential"
        or principal.endpoint_id is None
        or principal.credential_id is None
    ):
        raise HTTPException(status_code=403, detail="device credential is required")
    return principal


def enforce_device_endpoint(principal: Principal, endpoint_id: str) -> None:
    if principal.auth_method == "device_credential" and principal.endpoint_id != endpoint_id:
        raise HTTPException(
            status_code=403,
            detail="device credential is not authorized for this endpoint",
        )


def enforce_endpoint_credential_mode(principal: Principal, credential_mode: str) -> None:
    if credential_mode == "device" and principal.auth_method != "device_credential":
        raise HTTPException(
            status_code=403,
            detail="device credential is required for this endpoint",
        )


def _request_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get("x-sha-api-token", "").strip()


def _request_bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _is_existing_agent_path(request: Request) -> bool:
    method = request.method
    parts = request.url.path.strip("/").split("/")
    if method == "POST" and parts == ["api", "endpoints", "enroll"]:
        return True
    if method == "POST" and parts == ["api", "posture-snapshots"]:
        return True
    if len(parts) == 4 and parts[:2] == ["api", "endpoints"] and parts[3] == "heartbeat":
        return method == "POST"
    if (
        len(parts) == 5
        and parts[:2] == ["api", "endpoints"]
        and parts[3:] == ["response-actions", "claim"]
    ):
        return method == "POST"
    if len(parts) == 4 and parts[:2] == ["api", "response-actions"] and parts[3] == "result":
        return method == "POST"
    return False


def _is_bootstrap_path(request: Request) -> bool:
    return request.method == "POST" and request.url.path == "/api/agent/bootstrap"


def _is_device_only_path(request: Request) -> bool:
    if request.url.path == "/api/agent/me":
        return request.method == "GET"
    if request.url.path == "/api/agent/credentials/rotate":
        return request.method == "POST"
    return False


def _is_agent_path(request: Request) -> bool:
    return _is_existing_agent_path(request) or _is_bootstrap_path(request) or _is_device_only_path(request)


def _is_readonly_path(request: Request) -> bool:
    if request.method not in {"GET", "HEAD", "OPTIONS"} or _is_agent_path(request):
        return False
    parts = request.url.path.strip("/").split("/")
    if len(parts) == 4 and parts[:2] == ["api", "installer-profiles"] and parts[3] == "artifact":
        return False
    return request.url.path.startswith("/api/")


async def _authorize(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
    principal: Principal,
) -> Response:
    request.state.principal = principal
    if principal.role == "enrollment":
        if _is_bootstrap_path(request):
            return await call_next(request)
        return JSONResponse({"detail": "forbidden for enrollment token"}, status_code=403)
    if principal.role == "agent":
        if principal.auth_method == "device_credential":
            if (_is_existing_agent_path(request) and request.url.path != "/api/endpoints/enroll") or _is_device_only_path(
                request
            ):
                return await call_next(request)
            return JSONResponse({"detail": "forbidden for device credential"}, status_code=403)
        if _is_existing_agent_path(request):
            return await call_next(request)
        return JSONResponse({"detail": "forbidden for agent token"}, status_code=403)
    if _is_agent_path(request):
        role_label = "read-only" if principal.role == "readonly" else principal.role
        return JSONResponse({"detail": f"forbidden for {role_label} principal"}, status_code=403)
    if principal.role == "human":
        return await call_next(request)
    if principal.role == "operator":
        return await call_next(request)
    if _is_readonly_path(request):
        return await call_next(request)
    return JSONResponse({"detail": "forbidden for read-only principal"}, status_code=403)


def _browser_session_principal(request: Request) -> Principal | None:
    raw_session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    key = getattr(request.app.state, "browser_session_key", None)
    store = getattr(request.app.state, "store", None)
    if not raw_session_token or not isinstance(key, bytes) or not isinstance(store, DatabaseStore):
        return None
    token_hash = keyed_hash(key, "session-token", raw_session_token)
    now_dt = utc_now()
    now = to_utc_z(now_dt)
    with store.session() as session:
        with session.begin():
            browser_session = session.scalar(
                select(BrowserSession).where(BrowserSession.token_hash == token_hash)
            )
            if (
                browser_session is None
                or browser_session.hash_key_id != "primary"
                or browser_session.revoked_at is not None
                or browser_session.idle_expires_at <= now
                or browser_session.absolute_expires_at <= now
            ):
                return None
            user = session.get(User, browser_session.user_id)
            identity = session.get(OidcIdentity, browser_session.identity_id)
            oidc_config = getattr(request.app.state, "oidc_config", None)
            if (
                user is None
                or identity is None
                or user.status == "disabled"
                or (
                    isinstance(oidc_config, OidcClientConfig)
                    and identity.issuer != oidc_config.issuer
                )
            ):
                return None
            browser_session.last_seen_at = now
            browser_session.idle_expires_at = min(
                to_utc_z(
                    now_dt
                    + timedelta(minutes=int(getattr(request.app.state, "session_idle_minutes", 30)))
                ),
                browser_session.absolute_expires_at,
            )
            browser_session.updated_at = now
            grants = load_user_grants(session, user.user_id) if user.status == "active" else ()
            principal = Principal(
                subject=f"user:{user.user_id}",
                display_name=user.display_name,
                role="human",
                auth_method="oidc_session",
                user_id=user.user_id,
                identity_id=identity.identity_id,
                session_id=browser_session.session_id,
                grants=grants,
            )
    request.state.session_token = raw_session_token
    request.state.browser_session_id = principal.session_id
    return principal


def _origin_matches(request: Request) -> bool:
    public_base_url = getattr(request.app.state, "public_base_url", None)
    if not isinstance(public_base_url, str) or not public_base_url:
        return False
    target = urlsplit(public_base_url)
    expected_origin = f"{target.scheme}://{target.netloc}"
    origin = request.headers.get("origin")
    if origin:
        return compare_digest(origin.rstrip("/"), expected_origin.rstrip("/"))
    referer = request.headers.get("referer")
    if not referer:
        return False
    parsed_referer = urlsplit(referer)
    referer_origin = f"{parsed_referer.scheme}://{parsed_referer.netloc}"
    return compare_digest(referer_origin.rstrip("/"), expected_origin.rstrip("/"))


def _browser_csrf_valid(request: Request) -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return False
    key = getattr(request.app.state, "browser_session_key", None)
    raw_session_token = getattr(request.state, "session_token", None)
    supplied = request.headers.get("x-sha-csrf", "")
    if not isinstance(key, bytes) or not isinstance(raw_session_token, str) or not supplied:
        return False
    return _origin_matches(request) and compare_digest(
        supplied,
        csrf_token(key, raw_session_token),
    )


def _authenticate_device_principal(request: Request, credential_id: str, secret: str) -> Principal | None:
    key = getattr(request.app.state, "credential_hmac_key", None)
    store = getattr(request.app.state, "store", None)
    if not isinstance(key, bytes) or not isinstance(store, DatabaseStore):
        return None
    supplied_hash = device_secret_hash(key, credential_id, secret)
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            credential = session.scalar(
                select(DeviceCredential).where(DeviceCredential.credential_id == credential_id)
            )
            expected_hash = credential.secret_hash if credential is not None else "0" * 64
            secret_matches = compare_digest(supplied_hash, expected_hash)
            if (
                credential is None
                or not secret_matches
                or credential.status != "active"
                or credential.hash_key_id != "primary"
                or (credential.expires_at is not None and credential.expires_at <= now)
            ):
                return None
            endpoint = session.get(Endpoint, credential.endpoint_id)
            if endpoint is None or endpoint.credential_mode != "device":
                return None
            credential.last_used_at = now
            credential.updated_at = now
            return Principal(
                subject=f"device:{endpoint.endpoint_id}",
                display_name=endpoint.hostname,
                role="agent",
                auth_method="device_credential",
                endpoint_id=endpoint.endpoint_id,
                credential_id=credential.credential_id,
            )


async def api_token_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if request.url.path in _OPEN_PATHS:
        return await call_next(request)

    operator_token = getattr(request.app.state, "api_token", None)
    agent_token = getattr(request.app.state, "agent_api_token", None)
    readonly_token = getattr(request.app.state, "readonly_api_token", None)
    external_auth_token = getattr(request.app.state, "external_auth_trusted_token", None)
    auth_mode = getattr(request.app.state, "auth_mode", "protected")
    authentication_configured = bool(
        operator_token
        or agent_token
        or readonly_token
        or external_auth_token
        or getattr(request.app.state, "credential_hmac_key", None)
        or getattr(request.app.state, "oidc_client", None)
    )

    if not authentication_configured:
        if auth_mode != "development_open":
            return JSONResponse({"detail": "authentication is not configured"}, status_code=503)
        request.state.principal = Principal(
            subject="development:operator",
            display_name="Development operator",
            role="operator",
            auth_method="development_open",
            grants=(synthetic_global_grant("development_admin", ALL_PERMISSIONS),),
        )
        return await call_next(request)

    browser_principal = _browser_session_principal(request)
    if browser_principal is not None:
        if not _browser_csrf_valid(request):
            return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
        return await _authorize(request, call_next, browser_principal)
    if request.cookies.get(SESSION_COOKIE_NAME):
        response = JSONResponse(
            {"detail": "authentication required"},
            status_code=401,
            headers={"Cache-Control": "no-store"},
        )
        response.delete_cookie(
            SESSION_COOKIE_NAME,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

    external_header_token = request.headers.get("x-sha-external-auth", "").strip()
    if external_header_token and external_auth_token and compare_digest(external_header_token, external_auth_token):
        if getattr(request.app.state, "oidc_client", None) is not None:
            return JSONResponse(
                {"detail": "external proxy roles are disabled when scoped OIDC is enabled"},
                status_code=403,
            )
        external_role = request.headers.get("x-sha-external-role", "").strip().lower()
        external_user = request.headers.get("x-sha-external-user", "").strip()
        if external_role not in _EXTERNAL_ROLES:
            return JSONResponse({"detail": "forbidden for external auth role"}, status_code=403)
        if not external_user:
            return JSONResponse({"detail": "external auth user is required"}, status_code=403)
        trusted_role: Literal["operator", "readonly"] = (
            "operator" if external_role == "operator" else "readonly"
        )
        return await _authorize(
            request,
            call_next,
            Principal(
                subject=f"external:{external_user.lower()}",
                display_name=external_user,
                role=trusted_role,
                auth_method="external_proxy",
                grants=(
                    synthetic_global_grant(
                        f"external_{trusted_role}",
                        LEGACY_OPERATOR_PERMISSIONS
                        if trusted_role == "operator"
                        else READONLY_PERMISSIONS,
                    ),
                ),
            ),
        )

    bearer_token = _request_bearer_token(request)
    parsed_device_credential = parse_device_credential(bearer_token)
    if parsed_device_credential is not None:
        device_principal = _authenticate_device_principal(request, *parsed_device_credential)
        if device_principal is None:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        return await _authorize(request, call_next, device_principal)

    parsed_enrollment_token = parse_enrollment_token(bearer_token)
    if parsed_enrollment_token is not None:
        if not _is_bootstrap_path(request):
            return JSONResponse({"detail": "forbidden for enrollment token"}, status_code=403)
        return await _authorize(
            request,
            call_next,
            Principal(
                subject=f"enrollment:{parsed_enrollment_token[0]}",
                display_name="Enrollment token",
                role="enrollment",
                auth_method="enrollment_token",
                enrollment_token_id=parsed_enrollment_token[0],
            ),
        )

    request_token = _request_token(request)
    if operator_token and compare_digest(request_token, operator_token):
        return await _authorize(
            request,
            call_next,
            Principal(
                subject="api-token:operator",
                display_name="Operator API token",
                role="operator",
                auth_method="operator_token",
                grants=(synthetic_global_grant("legacy_operator", LEGACY_OPERATOR_PERMISSIONS),),
            ),
        )
    if agent_token and compare_digest(request_token, agent_token):
        legacy_policy = getattr(request.app.state, "legacy_reporter_policy", None)
        if not isinstance(legacy_policy, LegacyReporterPolicy) or not legacy_policy.allows():
            return JSONResponse(
                {"detail": "legacy reporter compatibility is disabled or expired"},
                status_code=403,
            )
        return await _authorize(
            request,
            call_next,
            Principal(
                subject="api-token:agent",
                display_name="Agent API token",
                role="agent",
                auth_method="agent_token",
            ),
        )
    if readonly_token and compare_digest(request_token, readonly_token):
        return await _authorize(
            request,
            call_next,
            Principal(
                subject="api-token:readonly",
                display_name="Read-only API token",
                role="readonly",
                auth_method="readonly_token",
                grants=(synthetic_global_grant("viewer", READONLY_PERMISSIONS),),
            ),
        )
    return JSONResponse({"detail": "authentication required"}, status_code=401)
