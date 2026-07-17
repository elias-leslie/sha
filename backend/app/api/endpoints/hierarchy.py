from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.auth import Principal
from app.authorization import (
    client_scope_clause,
    record_audit_event,
    require_global_permission,
    require_permission,
    require_scope,
    scope_clause,
)
from app.db import DatabaseStore, get_store
from app.models import Client, Location
from app.schemas.contracts import (
    ClientCreateRequest,
    ClientListResponse,
    ClientResponse,
    LocationCreateRequest,
    LocationListResponse,
    LocationResponse,
)
from app.utils import generate_prefixed_id, normalize_required_string, to_utc_z, utc_now

router = APIRouter(prefix="/api/clients", tags=["hierarchy"])


def _client_payload(client: Client) -> dict[str, object]:
    return {
        "client_id": client.client_id,
        "key": client.key,
        "name": client.name,
        "state": client.state,
        "is_system": client.is_system,
        "created_at": client.created_at,
        "updated_at": client.updated_at,
    }


def _location_payload(location: Location) -> dict[str, object]:
    return {
        "location_id": location.location_id,
        "client_id": location.client_id,
        "key": location.key,
        "name": location.name,
        "state": location.state,
        "is_system": location.is_system,
        "created_at": location.created_at,
        "updated_at": location.updated_at,
    }


@router.get("", response_model=ClientListResponse)
def list_clients(
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("hierarchy.read")),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        clients = session.scalars(
            select(Client)
            .where(client_scope_clause(principal, "hierarchy.read", Client.client_id))
            .order_by(Client.is_system.asc(), Client.name.asc(), Client.client_id.asc())
        ).all()
        return {"items": [_client_payload(client) for client in clients]}


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ClientResponse)
def create_client(
    payload: ClientCreateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("hierarchy.manage")),
) -> dict[str, object]:
    require_global_permission(principal, "hierarchy.manage")
    key = normalize_required_string(payload.key, "key")
    name = normalize_required_string(payload.name, "name")
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            existing = session.scalar(select(Client).where(Client.key == key))
            if existing is not None:
                raise HTTPException(status_code=409, detail="client key already exists")
            client = Client(
                client_id=generate_prefixed_id("cl"),
                key=key,
                name=name,
                name_normalized=name.lower(),
                state="active",
                is_system=False,
                created_at=now,
                updated_at=now,
            )
            session.add(client)
            session.flush()
            location = Location(
                    location_id=generate_prefixed_id("loc"),
                    client_id=client.client_id,
                    key=None,
                    name="Unassigned",
                    name_normalized="unassigned",
                    state="migration_quarantine",
                    is_system=True,
                    created_at=now,
                    updated_at=now,
                )
            session.add(location)
            session.flush()
            record_audit_event(
                session,
                event_type="client_created",
                principal=principal,
                client_id=client.client_id,
                location_id=location.location_id,
                target_type="client",
                target_id=client.client_id,
                created_at=now,
            )
            session.flush()
            return _client_payload(client)


@router.get("/{client_id}/locations", response_model=LocationListResponse)
def list_locations(
    client_id: str,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("hierarchy.read")),
) -> dict[str, list[dict[str, object]]]:
    normalized_client_id = normalize_required_string(client_id, "client_id")
    with store.session() as session:
        if session.scalar(
            select(Client).where(
                Client.client_id == normalized_client_id,
                client_scope_clause(principal, "hierarchy.read", Client.client_id),
            )
        ) is None:
            raise HTTPException(status_code=404, detail="client not found")
        locations = session.scalars(
            select(Location)
            .where(
                Location.client_id == normalized_client_id,
                scope_clause(
                    principal,
                    "hierarchy.read",
                    Location.client_id,
                    Location.location_id,
                ),
            )
            .order_by(Location.is_system.asc(), Location.name.asc(), Location.location_id.asc())
        ).all()
        return {"items": [_location_payload(location) for location in locations]}


@router.post(
    "/{client_id}/locations",
    status_code=status.HTTP_201_CREATED,
    response_model=LocationResponse,
)
def create_location(
    client_id: str,
    payload: LocationCreateRequest,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("hierarchy.manage")),
) -> dict[str, object]:
    normalized_client_id = normalize_required_string(client_id, "client_id")
    key = normalize_required_string(payload.key, "key")
    name = normalize_required_string(payload.name, "name")
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            client = session.get(Client, normalized_client_id)
            if client is None:
                raise HTTPException(status_code=404, detail="client not found")
            require_scope(
                principal,
                "hierarchy.manage",
                client_id=client.client_id,
                location_id=None,
            )
            if client.state == "archived":
                raise HTTPException(status_code=409, detail="client must be active")
            existing = session.scalar(
                select(Location).where(
                    Location.client_id == normalized_client_id,
                    Location.key == key,
                )
            )
            if existing is not None:
                raise HTTPException(status_code=409, detail="location key already exists for client")
            location = Location(
                location_id=generate_prefixed_id("loc"),
                client_id=normalized_client_id,
                key=key,
                name=name,
                name_normalized=name.lower(),
                state="active",
                is_system=False,
                created_at=now,
                updated_at=now,
            )
            session.add(location)
            session.flush()
            record_audit_event(
                session,
                event_type="location_created",
                principal=principal,
                client_id=location.client_id,
                location_id=location.location_id,
                target_type="location",
                target_id=location.location_id,
                created_at=now,
            )
            session.flush()
            return _location_payload(location)
