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


async def api_token_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    token = getattr(request.app.state, "api_token", None)
    agent_token = getattr(request.app.state, "agent_api_token", None)
    if (not token and not agent_token) or request.url.path in _OPEN_PATHS:
        return await call_next(request)
    request_token = _request_token(request)
    if token and compare_digest(request_token, token):
        return await call_next(request)
    if agent_token and compare_digest(request_token, agent_token):
        if _is_agent_path(request.method, request.url.path):
            return await call_next(request)
        return JSONResponse({"detail": "forbidden for agent token"}, status_code=403)
    return JSONResponse({"detail": "authentication required"}, status_code=401)
