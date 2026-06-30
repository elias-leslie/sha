from __future__ import annotations

from secrets import compare_digest
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.responses import JSONResponse

_OPEN_PATHS = {"/health"}


def _request_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get("x-sha-api-token", "").strip()


def _external_auth_role(request: Request, trusted_token: str | None) -> str | None:
    if not trusted_token:
        return None
    header_token = request.headers.get("x-sha-external-auth", "").strip()
    if not header_token or not compare_digest(header_token, trusted_token):
        return None
    return request.headers.get("x-sha-external-role", "").strip().lower()


def _is_agent_path(method: str, path: str) -> bool:
    parts = path.strip("/").split("/")
    if method == "POST" and parts == ["api", "endpoints", "enroll"]:
        return True
    if method == "POST" and parts == ["api", "posture-snapshots"]:
        return True
    if len(parts) == 4 and parts[:2] == ["api", "endpoints"] and parts[3] == "heartbeat":
        return method == "POST"
    if len(parts) == 4 and parts[:2] == ["api", "endpoints"] and parts[3] == "response-actions":
        return method == "GET"
    if len(parts) == 4 and parts[:2] == ["api", "response-actions"] and parts[3] == "result":
        return method == "POST"
    return False


def _is_readonly_path(method: str, path: str) -> bool:
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return False
    parts = path.strip("/").split("/")
    if len(parts) == 4 and parts[:2] == ["api", "installer-profiles"] and parts[3] == "artifact":
        return False
    return path.startswith("/api/")


async def api_token_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    token = getattr(request.app.state, "api_token", None)
    agent_token = getattr(request.app.state, "agent_api_token", None)
    readonly_token = getattr(request.app.state, "readonly_api_token", None)
    external_auth_token = getattr(request.app.state, "external_auth_trusted_token", None)
    if (not token and not agent_token and not readonly_token and not external_auth_token) or request.url.path in _OPEN_PATHS:
        return await call_next(request)
    external_role = _external_auth_role(request, external_auth_token)
    if external_role == "operator":
        return await call_next(request)
    if external_role == "readonly":
        if _is_readonly_path(request.method, request.url.path):
            return await call_next(request)
        return JSONResponse({"detail": "forbidden for external read-only role"}, status_code=403)
    if external_role is not None:
        return JSONResponse({"detail": "forbidden for external auth role"}, status_code=403)
    request_token = _request_token(request)
    if token and compare_digest(request_token, token):
        return await call_next(request)
    if agent_token and compare_digest(request_token, agent_token):
        if _is_agent_path(request.method, request.url.path):
            return await call_next(request)
        return JSONResponse({"detail": "forbidden for agent token"}, status_code=403)
    if readonly_token and compare_digest(request_token, readonly_token):
        if _is_readonly_path(request.method, request.url.path):
            return await call_next(request)
        return JSONResponse({"detail": "forbidden for read-only token"}, status_code=403)
    return JSONResponse({"detail": "authentication required"}, status_code=401)
