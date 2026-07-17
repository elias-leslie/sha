from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from app.api.endpoints.approvals import router as approvals_router
from app.api.endpoints.audit import router as audit_router
from app.api.endpoints.authentication import router as authentication_router
from app.api.endpoints.control_registry import router as control_registry_router
from app.api.endpoints.device_identity import router as device_identity_router
from app.api.endpoints.evidence import router as evidence_router
from app.api.endpoints.endpoints import router as endpoints_router
from app.api.endpoints.fleet_metadata import router as fleet_metadata_router
from app.api.endpoints.health import router as health_router
from app.api.endpoints.hierarchy import router as hierarchy_router
from app.api.endpoints.identity import router as identity_router
from app.api.endpoints.installers import router as installers_router
from app.api.endpoints.posture import router as posture_router
from app.api.endpoints.response_actions import router as response_actions_router
from app.api.endpoints.source_packs import router as source_packs_router
from app.agent_packages import AgentPackageProvider
from app.agent_protocol import LegacyReporterPolicy
from app.auth import api_token_middleware
from app.authorization import classify_api_routes
from app.browser_auth import OidcClientConfig, build_oidc_client, validate_oidc_config
from app.config import get_settings
from app.db import DatabaseStore
from app.device_identity import validate_hmac_key


def create_app(
    database_url: str | None = None,
    api_token: str | None = None,
    agent_api_token: str | None = None,
    readonly_api_token: str | None = None,
    external_auth_trusted_token: str | None = None,
    credential_hmac_key: bytes | None = None,
    browser_session_key: bytes | None = None,
    oidc_client: Any | None = None,
    oidc_config: OidcClientConfig | None = None,
    public_base_url: str | None = None,
    auth_mode: Literal["development_open", "protected"] | None = None,
    database_migration_mode: Literal["upgrade", "check"] | None = None,
    legacy_reporter_mode: Literal["disabled", "migration"] | None = None,
    legacy_reporter_compatibility_until: str | None = None,
    device_credential_lifetime_days: int | None = None,
    agent_package_provider: AgentPackageProvider | None = None,
) -> FastAPI:
    settings = get_settings()
    store = DatabaseStore(
        database_url or settings.resolved_database_url(),
        migration_mode=database_migration_mode or settings.database_migration_mode,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        store.prepare()
        try:
            yield
        finally:
            store.dispose()

    app = FastAPI(title=settings.service_name, version=settings.version, lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def redact_secret_validation_inputs(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        errors: list[dict[str, object]] = []
        for raw_error in exc.errors():
            error = dict(raw_error)
            location = error.get("loc", ())
            if isinstance(location, (tuple, list)) and "credential_secret" in location:
                error["input"] = "[REDACTED]"
            errors.append(error)
        return JSONResponse(
            status_code=422,
            content=jsonable_encoder({"detail": errors}),
        )

    app.state.store = store
    app.state.api_token = api_token if api_token is not None else settings.resolved_api_token()
    app.state.agent_api_token = agent_api_token if agent_api_token is not None else settings.resolved_agent_api_token()
    app.state.readonly_api_token = (
        readonly_api_token if readonly_api_token is not None else settings.resolved_readonly_api_token()
    )
    app.state.external_auth_trusted_token = (
        external_auth_trusted_token
        if external_auth_trusted_token is not None
        else settings.resolved_external_auth_trusted_token()
    )
    app.state.credential_hmac_key = validate_hmac_key(
        credential_hmac_key
        if credential_hmac_key is not None
        else settings.resolved_credential_hmac_key()
    )
    app.state.legacy_reporter_policy = LegacyReporterPolicy.from_config(
        legacy_reporter_mode or settings.legacy_reporter_mode,
        (
            legacy_reporter_compatibility_until
            if legacy_reporter_compatibility_until is not None
            else settings.legacy_reporter_compatibility_until
        ),
    )
    effective_credential_lifetime = (
        device_credential_lifetime_days
        if device_credential_lifetime_days is not None
        else settings.device_credential_lifetime_days
    )
    if not 1 <= effective_credential_lifetime <= 3650:
        raise ValueError("device credential lifetime days must be between 1 and 3650")
    app.state.device_credential_lifetime_days = effective_credential_lifetime
    package_fields = (
        settings.agent_release_root,
        settings.agent_release_trust_policy_file,
        settings.agent_profile_signing_key_file,
        settings.agent_profile_signing_identity,
        settings.agent_profile_signing_key_id,
        settings.agent_package_spool_root,
        settings.agent_profile_package_tool,
    )
    if agent_package_provider is None and any(package_fields):
        if not all(package_fields):
            raise ValueError("signed agent package configuration is incomplete")
        agent_package_provider = AgentPackageProvider.from_paths(
            release_root=str(package_fields[0]),
            trust_policy_file=str(package_fields[1]),
            profile_signing_key_file=str(package_fields[2]),
            profile_signing_identity=str(package_fields[3]),
            profile_signing_key_id=str(package_fields[4]),
            spool_root=str(package_fields[5]),
            profile_package_tool=str(package_fields[6]),
            ca_bundle_file=settings.agent_profile_ca_bundle_file,
        )
    app.state.agent_package_provider = agent_package_provider
    effective_browser_key = (
        browser_session_key
        if browser_session_key is not None
        else settings.resolved_browser_session_key()
    )
    if effective_browser_key is not None and len(effective_browser_key) < 32:
        raise ValueError("browser session key must contain at least 32 bytes")

    configured_oidc_fields = (
        settings.oidc_issuer,
        settings.oidc_metadata_url,
        settings.oidc_client_id,
        settings.resolved_oidc_client_secret(),
        settings.public_base_url,
    )
    if oidc_config is None and any(configured_oidc_fields):
        if not all(configured_oidc_fields):
            raise ValueError(
                "OIDC configuration requires issuer, metadata URL, client ID, client secret, and public base URL"
            )
        oidc_config = OidcClientConfig(
            issuer=str(configured_oidc_fields[0]),
            metadata_url=str(configured_oidc_fields[1]),
            client_id=str(configured_oidc_fields[2]),
            client_secret=str(configured_oidc_fields[3]),
            public_base_url=str(configured_oidc_fields[4]),
            ca_bundle_file=settings.oidc_ca_bundle_file,
        )
    if oidc_client is not None and oidc_config is None:
        raise ValueError("an injected OIDC client requires OIDC configuration")
    if oidc_config is not None:
        validate_oidc_config(oidc_config)
        if effective_browser_key is None:
            raise ValueError("OIDC authentication requires a browser session key")
        if oidc_client is None:
            oidc_client = build_oidc_client(oidc_config)

    for label, value in (
        ("session idle minutes", settings.session_idle_minutes),
        ("session absolute hours", settings.session_absolute_hours),
        ("OIDC login TTL minutes", settings.oidc_login_ttl_minutes),
    ):
        if value <= 0:
            raise ValueError(f"{label} must be greater than zero")
    app.state.browser_session_key = effective_browser_key
    app.state.oidc_client = oidc_client
    app.state.oidc_config = oidc_config
    app.state.public_base_url = (
        oidc_config.public_base_url
        if oidc_config is not None
        else public_base_url or settings.public_base_url
    )
    app.state.session_idle_minutes = settings.session_idle_minutes
    app.state.session_absolute_hours = settings.session_absolute_hours
    app.state.oidc_login_ttl_minutes = settings.oidc_login_ttl_minutes
    authentication_configured = bool(
        app.state.api_token
        or app.state.agent_api_token
        or app.state.readonly_api_token
        or app.state.external_auth_trusted_token
        or app.state.credential_hmac_key
        or app.state.oidc_client
    )
    app.state.auth_mode = auth_mode or ("protected" if authentication_configured else settings.auth_mode)
    app.middleware("http")(api_token_middleware)
    app.include_router(health_router)
    app.include_router(authentication_router)
    app.include_router(identity_router)
    app.include_router(device_identity_router)
    app.include_router(hierarchy_router)
    app.include_router(endpoints_router)
    app.include_router(fleet_metadata_router)
    app.include_router(posture_router)
    app.include_router(installers_router)
    app.include_router(approvals_router)
    app.include_router(audit_router)
    app.include_router(response_actions_router)
    app.include_router(control_registry_router)
    app.include_router(source_packs_router)
    app.include_router(evidence_router)
    app.state.route_authorization_policies = classify_api_routes(app)
    return app


app = create_app()
