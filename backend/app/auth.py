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


async def api_token_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    token = getattr(request.app.state, "api_token", None)
    if not token or request.url.path in _OPEN_PATHS:
        return await call_next(request)
    if compare_digest(_request_token(request), token):
        return await call_next(request)
    return JSONResponse({"detail": "authentication required"}, status_code=401)
