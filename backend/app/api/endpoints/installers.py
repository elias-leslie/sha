from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.db import DatabaseStore, get_store
from app.models import InstallerProfile
from app.schemas.contracts import (
    InstallerProfileCreateRequest,
    InstallerProfileListResponse,
    InstallerProfileResponse,
)
from app.utils import (
    generate_prefixed_id,
    normalize_installer_channel,
    normalize_optional_string,
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
        "tenant_id": profile.tenant_id,
        "site_id": profile.site_id,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }


@router.get("", response_model=InstallerProfileListResponse)
def list_installer_profiles(
    store: DatabaseStore = Depends(get_store),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        profiles = session.scalars(
            select(InstallerProfile).order_by(InstallerProfile.created_at.asc(), InstallerProfile.id.asc())
        ).all()
    return {"items": [_installer_profile_payload(profile) for profile in profiles]}


@router.post("", status_code=status.HTTP_201_CREATED, response_model=InstallerProfileResponse)
def create_installer_profile(
    payload: InstallerProfileCreateRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    name = normalize_required_string(payload.name, "name")
    platform = normalize_platform(payload.platform.value)
    channel = normalize_installer_channel(payload.channel.value)
    control_plane_url = validate_http_url(payload.control_plane_url)
    policy_mode = normalize_policy_mode(payload.policy_mode.value)
    tenant_id = normalize_optional_string(payload.tenant_id, "tenant_id")
    site_id = normalize_optional_string(payload.site_id, "site_id")
    name_normalized = name.lower()
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            existing = session.scalar(
                select(InstallerProfile).where(
                    InstallerProfile.platform == platform,
                    InstallerProfile.name_normalized == name_normalized,
                )
            )
            if existing is not None:
                raise HTTPException(
                    status_code=409,
                    detail="installer profile already exists for platform",
                )

            profile = InstallerProfile(
                id=generate_prefixed_id("ip"),
                name=name,
                name_normalized=name_normalized,
                platform=platform,
                channel=channel,
                control_plane_url=control_plane_url,
                policy_mode=policy_mode,
                tenant_id=tenant_id,
                site_id=site_id,
                created_at=now,
                updated_at=now,
            )
            session.add(profile)
            session.flush()
            return _installer_profile_payload(profile)
