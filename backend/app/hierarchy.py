from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Client, Location
from app.utils import normalize_optional_string, normalize_required_string

QUARANTINE_CLIENT_ID = "cl_legacy_quarantine"
QUARANTINE_LOCATION_ID = "loc_legacy_quarantine"


@dataclass(frozen=True)
class ResolvedScope:
    client_id: str
    location_id: str
    tenant_id: str | None
    site_id: str | None


def scope_payload(client: Client, location: Location) -> dict[str, object]:
    return {
        "client_id": client.client_id,
        "client_name": client.name,
        "location_id": location.location_id,
        "location_name": location.name,
    }


def load_scope(session: Session, client_id: str, location_id: str) -> tuple[Client, Location]:
    client = session.get(Client, client_id)
    location = session.scalar(
        select(Location).where(
            Location.location_id == location_id,
            Location.client_id == client_id,
        )
    )
    if client is None or location is None:
        raise HTTPException(status_code=422, detail="client_id and location_id must identify one location")
    if client.state == "archived" or location.state == "archived":
        raise HTTPException(status_code=409, detail="client and location must be active")
    return client, location


def resolve_scope(
    session: Session,
    *,
    client_id: str | None,
    location_id: str | None,
    tenant_id: str | None,
    site_id: str | None,
    canonical_fields_supplied: bool,
    tenant_field_supplied: bool,
    site_field_supplied: bool,
) -> ResolvedScope:
    normalized_tenant_id = normalize_optional_string(tenant_id, "tenant_id")
    normalized_site_id = normalize_optional_string(site_id, "site_id")

    if canonical_fields_supplied:
        if client_id is None or location_id is None:
            raise HTTPException(status_code=422, detail="client_id and location_id must be supplied together")
        normalized_client_id = normalize_required_string(client_id, "client_id")
        normalized_location_id = normalize_required_string(location_id, "location_id")
        client, location = load_scope(session, normalized_client_id, normalized_location_id)
        if tenant_field_supplied and normalized_tenant_id != client.key:
            raise HTTPException(status_code=422, detail="tenant_id does not match client_id")
        if site_field_supplied and normalized_site_id != location.key:
            raise HTTPException(status_code=422, detail="site_id does not match location_id")
        return ResolvedScope(
            client_id=client.client_id,
            location_id=location.location_id,
            tenant_id=client.key,
            site_id=location.key,
        )

    client: Client | None = None
    location: Location | None = None
    if normalized_tenant_id is not None:
        client = session.scalar(select(Client).where(Client.key == normalized_tenant_id))
        if client is not None:
            location = session.scalar(
                select(Location).where(
                    Location.client_id == client.client_id,
                    Location.key == normalized_site_id,
                )
            )
    elif normalized_site_id is not None:
        client = session.get(Client, QUARANTINE_CLIENT_ID)
        if client is not None:
            location = session.scalar(
                select(Location).where(
                    Location.client_id == client.client_id,
                    Location.key == normalized_site_id,
                )
            )

    if client is None or location is None or client.state == "archived" or location.state == "archived":
        load_scope(session, QUARANTINE_CLIENT_ID, QUARANTINE_LOCATION_ID)
        return ResolvedScope(
            client_id=QUARANTINE_CLIENT_ID,
            location_id=QUARANTINE_LOCATION_ID,
            tenant_id=normalized_tenant_id,
            site_id=normalized_site_id,
        )

    return ResolvedScope(
        client_id=client.client_id,
        location_id=location.location_id,
        tenant_id=normalized_tenant_id,
        site_id=normalized_site_id,
    )


def validate_scope_filter(
    session: Session,
    *,
    client_id: str | None,
    location_id: str | None,
) -> tuple[str | None, str | None]:
    normalized_client_id = (
        normalize_required_string(client_id, "client_id") if client_id is not None else None
    )
    normalized_location_id = (
        normalize_required_string(location_id, "location_id") if location_id is not None else None
    )
    if normalized_location_id is not None and normalized_client_id is None:
        raise HTTPException(status_code=422, detail="location_id requires client_id")
    if normalized_client_id is None:
        return None, None
    client = session.get(Client, normalized_client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="client not found")
    if normalized_location_id is not None:
        location = session.scalar(
            select(Location).where(
                Location.location_id == normalized_location_id,
                Location.client_id == normalized_client_id,
            )
        )
        if location is None:
            raise HTTPException(status_code=422, detail="location does not belong to client")
    return normalized_client_id, normalized_location_id
