from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select

from app.agent_packages import AgentPackageError, AgentPackageProvider
from app.agent_protocol import LegacyReporterPolicy
from app.auth import Principal
from app.authorization import record_audit_event, require_permission, require_scope, scope_clause
from app.db import DatabaseStore, get_store
from app.hierarchy import resolve_scope, validate_scope_filter
from app.installer_artifacts import render_installer_artifact
from app.models import InstallerProfile
from app.schemas.contracts import (
    InstallerProfileCreateRequest,
    InstallerProfileListResponse,
    InstallerProfileResponse,
)
from app.utils import (
    generate_prefixed_id,
    normalize_installer_channel,
    normalize_platform,
    normalize_policy_mode,
    normalize_required_string,
    validate_http_url,
    to_utc_z,
    utc_now,
)

router = APIRouter(prefix="/api/installer-profiles", tags=["installer-profiles"])


def _installer_profile_payload(profile: InstallerProfile) -> dict[str, object]:
    return {
        "id": profile.id,
        "name": profile.name,
        "platform": profile.platform,
        "channel": profile.channel,
        "control_plane_url": profile.control_plane_url,
        "policy_mode": profile.policy_mode,
        "runtime_kind": profile.runtime_kind,
        "client_id": profile.client_id,
        "location_id": profile.location_id,
        "tenant_id": profile.tenant_id,
        "site_id": profile.site_id,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }


@router.get("", response_model=InstallerProfileListResponse)
def list_installer_profiles(
    client_id: str | None = Query(None),
    location_id: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("installer_profile.read")),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        normalized_client_id, normalized_location_id = validate_scope_filter(
            session,
            client_id=client_id,
            location_id=location_id,
        )
        statement = select(InstallerProfile)
        if normalized_client_id is not None:
            require_scope(
                principal,
                "installer_profile.read",
                client_id=normalized_client_id,
                location_id=normalized_location_id,
            )
        statement = statement.where(
            scope_clause(
                principal,
                "installer_profile.read",
                InstallerProfile.client_id,
                InstallerProfile.location_id,
            )
        )
        if normalized_client_id is not None:
            statement = statement.where(InstallerProfile.client_id == normalized_client_id)
        if normalized_location_id is not None:
            statement = statement.where(InstallerProfile.location_id == normalized_location_id)
        profiles = session.scalars(
            statement.order_by(InstallerProfile.created_at.asc(), InstallerProfile.id.asc())
        ).all()
    return {"items": [_installer_profile_payload(profile) for profile in profiles]}


@router.get("/{profile_id}/artifact")
def get_installer_artifact(
    profile_id: str,
    request: Request,
    architecture: str = Query("amd64", pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$"),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("installer_artifact.download")),
) -> Response:
    normalized_profile_id = normalize_required_string(profile_id, "profile_id")

    with store.session() as session:
        profile = session.scalar(
            select(InstallerProfile).where(
                InstallerProfile.id == normalized_profile_id,
                scope_clause(
                    principal,
                    "installer_artifact.download",
                    InstallerProfile.client_id,
                    InstallerProfile.location_id,
                ),
            )
        )
        if profile is None:
            raise HTTPException(status_code=404, detail="installer profile not found")

    if profile.runtime_kind == "go_agent":
        provider = getattr(request.app.state, "agent_package_provider", None)
        if not isinstance(provider, AgentPackageProvider):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="signed agent package service is not configured",
            )
        try:
            package = provider.package(profile.platform, architecture)
            content = provider.read_generic(package)
        except AgentPackageError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        media_type = (
            "application/zip"
            if package.filename.endswith(".zip")
            else "application/gzip"
        )
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Cache-Control": "private, no-store",
                "Content-Disposition": f'attachment; filename="{package.filename}"',
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "X-SHA-Artifact-Sha256": package.sha256,
                "X-SHA-Signing-Identity": package.signing_identity,
                "X-SHA-Signing-Key-Id": package.signing_key_id,
            },
        )

    legacy_policy = getattr(request.app.state, "legacy_reporter_policy", None)
    auth_mode = getattr(request.app.state, "auth_mode", "protected")
    if auth_mode != "development_open" and isinstance(legacy_policy, LegacyReporterPolicy) and not legacy_policy.allows():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="legacy reporter artifact generation is disabled or expired",
        )

    agent_api_token = getattr(request.app.state, "agent_api_token", None)
    operator_auth_configured = bool(
        getattr(request.app.state, "api_token", None)
        or getattr(request.app.state, "external_auth_trusted_token", None)
        or getattr(request.app.state, "oidc_client", None)
    )
    if operator_auth_configured and not agent_api_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent API token is required to generate installer artifacts when operator authentication is configured",
        )

    filename, media_type, content = render_installer_artifact(profile, api_token=agent_api_token)
    sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "private, no-store",
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-SHA-Artifact-Sha256": sha256,
        },
    )


@router.post("", status_code=status.HTTP_201_CREATED, response_model=InstallerProfileResponse)
def create_installer_profile(
    payload: InstallerProfileCreateRequest,
    request: Request,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("installer_profile.manage")),
) -> dict[str, object]:
    name = normalize_required_string(payload.name, "name")
    platform = normalize_platform(payload.platform.value)
    channel = normalize_installer_channel(payload.channel.value)
    control_plane_url = validate_http_url(payload.control_plane_url)
    policy_mode = normalize_policy_mode(payload.policy_mode.value)
    name_normalized = name.lower()
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            resolved_scope = resolve_scope(
                session,
                client_id=payload.client_id,
                location_id=payload.location_id,
                tenant_id=payload.tenant_id,
                site_id=payload.site_id,
                canonical_fields_supplied=bool(
                    {"client_id", "location_id"} & payload.model_fields_set
                ),
                tenant_field_supplied="tenant_id" in payload.model_fields_set,
                site_field_supplied="site_id" in payload.model_fields_set,
            )
            require_scope(
                principal,
                "installer_profile.manage",
                client_id=resolved_scope.client_id,
                location_id=resolved_scope.location_id,
            )
            existing = session.scalar(
                select(InstallerProfile).where(
                    InstallerProfile.client_id == resolved_scope.client_id,
                    InstallerProfile.platform == platform,
                    InstallerProfile.name_normalized == name_normalized,
                )
            )
            if existing is not None:
                raise HTTPException(
                    status_code=409,
                    detail="installer profile already exists for client and platform",
                )

            profile = InstallerProfile(
                id=generate_prefixed_id("ip"),
                name=name,
                name_normalized=name_normalized,
                platform=platform,
                channel=channel,
                control_plane_url=control_plane_url,
                policy_mode=policy_mode,
                runtime_kind=(
                    "go_agent"
                    if (getattr(request.app.state, "api_token", None) or getattr(request.app.state, "external_auth_trusted_token", None) or getattr(request.app.state, "oidc_client", None))
                    else "legacy_reporter"
                ),
                client_id=resolved_scope.client_id,
                location_id=resolved_scope.location_id,
                tenant_id=resolved_scope.tenant_id,
                site_id=resolved_scope.site_id,
                created_at=now,
                updated_at=now,
            )
            session.add(profile)
            record_audit_event(
                session,
                event_type="installer_profile_created",
                principal=principal,
                client_id=profile.client_id,
                location_id=profile.location_id,
                target_type="installer_profile",
                target_id=profile.id,
                created_at=now,
            )
            session.flush()
            return _installer_profile_payload(profile)
