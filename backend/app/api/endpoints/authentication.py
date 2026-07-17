from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from authlib.common.errors import AuthlibBaseError
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
import httpx
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from starlette.responses import JSONResponse, RedirectResponse

from app.auth import Principal, current_principal
from app.authorization import record_audit_event
from app.browser_auth import (
    KEY_ID,
    OIDC_TRANSACTION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    OidcClientConfig,
    csrf_token,
    decrypt_code_verifier,
    encrypt_code_verifier,
    generate_browser_secret,
    keyed_hash,
    validate_return_to,
)
from app.db import DatabaseStore, get_store
from app.models import BrowserSession, OidcIdentity, OidcLoginTransaction, User
from app.schemas.contracts import AuthSessionResponse
from app.utils import generate_prefixed_id, to_utc_z, utc_now

router = APIRouter(prefix="/api/auth", tags=["authentication"])


class _DisabledOidcUser(Exception):
    def __init__(self, user_id: str | None) -> None:
        self.user_id = user_id


def _record_oidc_failure(
    store: DatabaseStore,
    *,
    reason: str,
    created_at: str,
    outcome: Literal["success", "denied", "failure"] = "failure",
    actor: str = "oidc:unknown",
) -> None:
    with store.session() as session:
        with session.begin():
            record_audit_event(
                session,
                event_type="oidc_login",
                outcome=outcome,
                actor=actor,
                auth_method="oidc_session",
                metadata={"reason": reason},
                created_at=created_at,
            )


def _oidc_state(request: Request) -> tuple[Any, OidcClientConfig, bytes]:
    client = getattr(request.app.state, "oidc_client", None)
    config = getattr(request.app.state, "oidc_config", None)
    key = getattr(request.app.state, "browser_session_key", None)
    if client is None or not isinstance(config, OidcClientConfig) or not isinstance(key, bytes):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not configured",
        )
    return client, config, key


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"


@router.get("/oidc/login")
async def begin_oidc_login(
    request: Request,
    return_to: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
) -> Response:
    client, config, key = _oidc_state(request)
    try:
        safe_return_to = validate_return_to(return_to)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        metadata = await client.load_server_metadata()
    except (AuthlibBaseError, httpx.HTTPError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=503, detail="OIDC provider metadata is unavailable") from None
    if metadata.get("issuer") != config.issuer:
        raise HTTPException(status_code=503, detail="OIDC discovery issuer mismatch")
    if "code" not in metadata.get("response_types_supported", []):
        raise HTTPException(status_code=503, detail="OIDC provider does not support authorization code flow")
    if "S256" not in metadata.get("code_challenge_methods_supported", []):
        raise HTTPException(status_code=503, detail="OIDC provider does not advertise PKCE S256")

    try:
        authorization = await client.create_authorization_url(config.callback_uri)
    except (AuthlibBaseError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=503, detail="OIDC authorization could not be initialized") from None
    state_value = authorization.get("state")
    nonce = authorization.get("nonce")
    code_verifier = authorization.get("code_verifier")
    authorization_url = authorization.get("url")
    if not all(isinstance(item, str) and item for item in (state_value, nonce, code_verifier, authorization_url)):
        raise HTTPException(status_code=503, detail="OIDC provider authorization could not be initialized")

    transaction_id = generate_prefixed_id("oidctx")
    browser_binding = generate_browser_secret()
    now_dt = utc_now()
    now = to_utc_z(now_dt)
    expires_at = to_utc_z(
        now_dt
        + timedelta(minutes=int(getattr(request.app.state, "oidc_login_ttl_minutes", 10)))
    )
    with store.session() as session:
        with session.begin():
            session.add(
                OidcLoginTransaction(
                    transaction_id=transaction_id,
                    state_hash=keyed_hash(key, "oidc-state", state_value),
                    browser_binding_hash=keyed_hash(
                        key,
                        "oidc-browser-binding",
                        browser_binding,
                    ),
                    hash_key_id=KEY_ID,
                    nonce=nonce,
                    encrypted_code_verifier=encrypt_code_verifier(
                        key,
                        transaction_id,
                        code_verifier,
                    ),
                    issuer=config.issuer,
                    redirect_uri=config.callback_uri,
                    return_to=safe_return_to,
                    expires_at=expires_at,
                    consumed_at=None,
                    created_at=now,
                )
            )

    response = RedirectResponse(authorization_url, status_code=302)
    response.set_cookie(
        OIDC_TRANSACTION_COOKIE_NAME,
        browser_binding,
        max_age=max(60, int(getattr(request.app.state, "oidc_login_ttl_minutes", 10)) * 60),
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
    )
    _no_store(response)
    return response


@router.get("/oidc/callback")
async def complete_oidc_login(
    request: Request,
    state_value: str | None = Query(None, alias="state"),
    code: str | None = Query(None),
    error: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
) -> Response:
    client, config, key = _oidc_state(request)
    browser_binding = request.cookies.get(OIDC_TRANSACTION_COOKIE_NAME, "")
    if not state_value or not browser_binding:
        raise HTTPException(status_code=401, detail="OIDC login transaction is invalid")
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            transaction = session.scalar(
                select(OidcLoginTransaction)
                .where(
                    OidcLoginTransaction.state_hash
                    == keyed_hash(key, "oidc-state", state_value),
                    OidcLoginTransaction.browser_binding_hash
                    == keyed_hash(key, "oidc-browser-binding", browser_binding),
                )
                .with_for_update()
            )
            if (
                transaction is None
                or transaction.hash_key_id != KEY_ID
                or transaction.consumed_at is not None
                or transaction.expires_at <= now
                or transaction.issuer != config.issuer
                or transaction.redirect_uri != config.callback_uri
            ):
                raise HTTPException(status_code=401, detail="OIDC login transaction is invalid")
            transaction.consumed_at = now
            transaction_id = transaction.transaction_id
            nonce = transaction.nonce
            encrypted_verifier = transaction.encrypted_code_verifier
            redirect_uri = transaction.redirect_uri
            return_to = transaction.return_to

    if error or not code:
        _record_oidc_failure(
            store,
            reason="provider_error" if error else "authorization_code_missing",
            created_at=now,
        )
        raise HTTPException(status_code=401, detail="OIDC authentication was not completed")
    try:
        code_verifier = decrypt_code_verifier(key, transaction_id, encrypted_verifier)
        token = await client.fetch_access_token(
            redirect_uri=redirect_uri,
            code=code,
            code_verifier=code_verifier,
        )
        claims = await client.parse_id_token(
            token,
            nonce=nonce,
            claims_options={"iss": {"values": [config.issuer]}},
        )
    except (AuthlibBaseError, httpx.HTTPError, InvalidTag, KeyError, TypeError, ValueError) as exc:
        _record_oidc_failure(
            store,
            reason=type(exc).__name__,
            created_at=now,
        )
        raise HTTPException(status_code=401, detail="OIDC authentication failed") from None

    issuer = claims.get("iss")
    subject = claims.get("sub")
    if issuer != config.issuer or not isinstance(subject, str) or not subject or len(subject) > 255:
        _record_oidc_failure(
            store,
            reason="invalid_identity_claims",
            created_at=now,
        )
        raise HTTPException(status_code=401, detail="OIDC identity is invalid")
    display_name_value = claims.get("name") or claims.get("preferred_username") or subject
    display_name = str(display_name_value)[:255]
    email_value = claims.get("email")
    email = str(email_value)[:320] if isinstance(email_value, str) and email_value else None

    raw_session_token = generate_browser_secret()
    now_dt = utc_now()
    now = to_utc_z(now_dt)
    absolute_expires_at = to_utc_z(
        now_dt
        + timedelta(hours=int(getattr(request.app.state, "session_absolute_hours", 12)))
    )
    idle_expires_at = min(
        to_utc_z(
            now_dt
            + timedelta(minutes=int(getattr(request.app.state, "session_idle_minutes", 30)))
        ),
        absolute_expires_at,
    )
    try:
        with store.session() as session:
            with session.begin():
                identity = session.scalar(
                    select(OidcIdentity).where(
                        OidcIdentity.issuer == issuer,
                        OidcIdentity.subject == subject,
                    )
                )
                if identity is None:
                    savepoint = session.begin_nested()
                    try:
                        user = User(
                            user_id=generate_prefixed_id("usr"),
                            status="pending",
                            display_name=display_name,
                            email_snapshot=email,
                            last_login_at=now,
                            disabled_at=None,
                            created_at=now,
                            updated_at=now,
                        )
                        session.add(user)
                        session.flush()
                        identity = OidcIdentity(
                            identity_id=generate_prefixed_id("oidc"),
                            user_id=user.user_id,
                            issuer=issuer,
                            subject=subject,
                            display_name_snapshot=display_name,
                            email_snapshot=email,
                            created_at=now,
                            updated_at=now,
                            last_seen_at=now,
                        )
                        session.add(identity)
                        session.flush()
                    except IntegrityError:
                        savepoint.rollback()
                        identity = session.scalar(
                            select(OidcIdentity).where(
                                OidcIdentity.issuer == issuer,
                                OidcIdentity.subject == subject,
                            )
                        )
                        if identity is None:
                            raise
                        user = session.get(User, identity.user_id)
                        if user is None or user.status == "disabled":
                            raise _DisabledOidcUser(
                                user.user_id if user is not None else None
                            )
                        identity.display_name_snapshot = display_name
                        identity.email_snapshot = email
                        identity.updated_at = now
                        identity.last_seen_at = now
                        user.display_name = display_name
                        user.email_snapshot = email
                        user.last_login_at = now
                        user.updated_at = now
                    else:
                        savepoint.commit()
                else:
                    user = session.get(User, identity.user_id)
                    if user is None or user.status == "disabled":
                        raise _DisabledOidcUser(user.user_id if user is not None else None)
                    identity.display_name_snapshot = display_name
                    identity.email_snapshot = email
                    identity.updated_at = now
                    identity.last_seen_at = now
                    user.display_name = display_name
                    user.email_snapshot = email
                    user.last_login_at = now
                    user.updated_at = now
                browser_session = BrowserSession(
                    session_id=generate_prefixed_id("sess"),
                    user_id=user.user_id,
                    identity_id=identity.identity_id,
                    token_hash=keyed_hash(key, "session-token", raw_session_token),
                    hash_key_id=KEY_ID,
                    authenticated_at=now,
                    last_seen_at=now,
                    idle_expires_at=idle_expires_at,
                    absolute_expires_at=absolute_expires_at,
                    revoked_at=None,
                    created_at=now,
                    updated_at=now,
                )
                session.add(browser_session)
                record_audit_event(
                    session,
                    event_type="oidc_login",
                    actor=f"user:{user.user_id}",
                    auth_method="oidc_session",
                    target_type="browser_session",
                    target_id=browser_session.session_id,
                    metadata={"user_status": user.status},
                    created_at=now,
                )
    except _DisabledOidcUser as exc:
        _record_oidc_failure(
            store,
            reason="user_disabled",
            created_at=now,
            outcome="denied",
            actor=f"user:{exc.user_id}" if exc.user_id is not None else "oidc:unknown",
        )
        raise HTTPException(status_code=403, detail="user is disabled") from None

    response = RedirectResponse(return_to, status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_session_token,
        max_age=max(60, int(getattr(request.app.state, "session_absolute_hours", 12)) * 3600),
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(
        OIDC_TRANSACTION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    _no_store(response)
    return response


@router.get("/session", response_model=AuthSessionResponse)
def get_auth_session(
    request: Request,
    response: Response,
    principal: Principal = Depends(current_principal),
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    _no_store(response)
    status_value = "active"
    if principal.user_id is not None:
        with store.session() as session:
            user = session.get(User, principal.user_id)
            if user is None:
                raise HTTPException(status_code=401, detail="authentication required")
            status_value = user.status
    key = getattr(request.app.state, "browser_session_key", None)
    raw_session_token = getattr(request.state, "session_token", None)
    csrf_value = (
        csrf_token(key, raw_session_token)
        if isinstance(key, bytes) and isinstance(raw_session_token, str)
        else None
    )
    return {
        "subject": principal.subject,
        "display_name": principal.display_name,
        "status": status_value,
        "authentication_method": principal.auth_method,
        "bindings": [
            {
                "binding_id": grant.binding_id,
                "role": grant.role_key,
                "scope_type": grant.scope_type,
                "client_id": grant.client_id,
                "location_id": grant.location_id,
                "permissions": sorted(grant.permissions),
            }
            for grant in principal.grants
        ],
        "csrf_token": csrf_value,
    }


def _logout_response() -> JSONResponse:
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    _no_store(response)
    return response


@router.post("/logout")
def logout_current_session(
    principal: Principal = Depends(current_principal),
    store: DatabaseStore = Depends(get_store),
) -> Response:
    if principal.auth_method != "oidc_session" or principal.session_id is None:
        raise HTTPException(status_code=403, detail="OIDC browser session is required")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            browser_session = session.get(BrowserSession, principal.session_id)
            if browser_session is not None and browser_session.revoked_at is None:
                browser_session.revoked_at = now
                browser_session.updated_at = now
            record_audit_event(
                session,
                event_type="browser_session_logout",
                principal=principal,
                target_type="browser_session",
                target_id=principal.session_id,
                created_at=now,
            )
    return _logout_response()


@router.post("/logout-all")
def logout_all_sessions(
    principal: Principal = Depends(current_principal),
    store: DatabaseStore = Depends(get_store),
) -> Response:
    if principal.auth_method != "oidc_session" or principal.user_id is None:
        raise HTTPException(status_code=403, detail="OIDC browser session is required")
    now = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            session.execute(
                update(BrowserSession)
                .where(
                    BrowserSession.user_id == principal.user_id,
                    BrowserSession.revoked_at.is_(None),
                )
                .values(revoked_at=now, updated_at=now)
            )
            record_audit_event(
                session,
                event_type="browser_session_logout_all",
                principal=principal,
                target_type="user",
                target_id=principal.user_id,
                created_at=now,
            )
    return _logout_response()
