from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.endpoints.approvals import router as approvals_router
from app.api.endpoints.endpoints import router as endpoints_router
from app.api.endpoints.health import router as health_router
from app.api.endpoints.installers import router as installers_router
from app.api.endpoints.posture import router as posture_router
from app.config import get_settings
from app.db import DatabaseStore


def create_app(database_url: str | None = None) -> FastAPI:
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
    app.include_router(health_router)
    app.include_router(endpoints_router)
    app.include_router(posture_router)
    app.include_router(installers_router)
    app.include_router(approvals_router)
    return app


app = create_app()
