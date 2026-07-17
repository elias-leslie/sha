from __future__ import annotations

from dataclasses import dataclass
from secrets import compare_digest
from typing import Awaitable, Callable, Literal

from fastapi import HTTPException, Request, Response
from starlette.responses import JSONResponse

_OPEN_PATHS = {"/health"}
_EXTERNAL_ROLES = {"operator", "readonly"}


@dataclass(frozen=True)
class Principal:
    subject: str
    display_name: str
    role: Literal["operator", "readonly", "agent"]
    auth_method: Literal["development_open", "operator_token", "readonly_token", "agent_token", "external_proxy"]

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
    if principal.role != "operator":
        raise HTTPException(status_code=403, detail="operator role is required")
    return principal


def _request_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get("x-sha-api-token", "").strip()


def _is_agent_path(request: Request) -> bool:
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
    if principal.role == "agent":
        if _is_agent_path(request):
            return await call_next(request)
        return JSONResponse({"detail": "forbidden for agent token"}, status_code=403)
    if _is_agent_path(request):
        role_label = "read-only" if principal.role == "readonly" else principal.role
        return JSONResponse({"detail": f"forbidden for {role_label} principal"}, status_code=403)
    if principal.role == "operator":
        return await call_next(request)
    if _is_readonly_path(request):
        return await call_next(request)
    return JSONResponse({"detail": "forbidden for read-only principal"}, status_code=403)


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
        operator_token or agent_token or readonly_token or external_auth_token
    )

    if not authentication_configured:
        if auth_mode != "development_open":
            return JSONResponse({"detail": "authentication is not configured"}, status_code=503)
        request.state.principal = Principal(
            subject="development:operator",
            display_name="Development operator",
            role="operator",
            auth_method="development_open",
        )
        return await call_next(request)

    external_header_token = request.headers.get("x-sha-external-auth", "").strip()
    if external_header_token and external_auth_token and compare_digest(external_header_token, external_auth_token):
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
            ),
        )
    if agent_token and compare_digest(request_token, agent_token):
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
            ),
        )
    return JSONResponse({"detail": "authentication required"}, status_code=401)
