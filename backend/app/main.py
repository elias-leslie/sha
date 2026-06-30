from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.endpoints.approvals import router as approvals_router
from app.api.endpoints.evidence import router as evidence_router
from app.api.endpoints.endpoints import router as endpoints_router
from app.api.endpoints.health import router as health_router
from app.api.endpoints.installers import router as installers_router
from app.api.endpoints.posture import router as posture_router
from app.api.endpoints.response_actions import router as response_actions_router
from app.api.endpoints.source_packs import router as source_packs_router
from app.auth import api_token_middleware
from app.config import get_settings
from app.db import DatabaseStore


def create_app(
    database_url: str | None = None,
    api_token: str | None = None,
    agent_api_token: str | None = None,
    readonly_api_token: str | None = None,
    external_auth_trusted_token: str | None = None,
) -> FastAPI:
    settings = get_settings()
    store = DatabaseStore(database_url or settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        store.prepare()
        try:
            yield
        finally:
            store.dispose()

    app = FastAPI(title=settings.service_name, version=settings.version, lifespan=lifespan)
    app.state.store = store
    app.state.api_token = api_token if api_token is not None else settings.api_token
    app.state.agent_api_token = agent_api_token if agent_api_token is not None else settings.agent_api_token
    app.state.readonly_api_token = (
        readonly_api_token if readonly_api_token is not None else settings.readonly_api_token
    )
    app.state.external_auth_trusted_token = (
        external_auth_trusted_token
        if external_auth_trusted_token is not None
        else settings.external_auth_trusted_token
    )
    app.middleware("http")(api_token_middleware)
    app.include_router(health_router)
    app.include_router(endpoints_router)
    app.include_router(posture_router)
    app.include_router(installers_router)
    app.include_router(approvals_router)
    app.include_router(response_actions_router)
    app.include_router(source_packs_router)
    app.include_router(evidence_router)
    return app


app = create_app()
