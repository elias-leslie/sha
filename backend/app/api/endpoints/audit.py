from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.auth import Principal
from app.authorization import require_permission, require_scope, scope_clause
from app.db import DatabaseStore, get_store
from app.hierarchy import validate_scope_filter
from app.models import AuditEvent
from app.schemas.contracts import AuditEventListResponse

router = APIRouter(prefix="/api/audit-events", tags=["audit"])


@router.get("", response_model=AuditEventListResponse)
def list_audit_events(
    client_id: str | None = Query(None),
    location_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("audit.read")),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        normalized_client_id, normalized_location_id = validate_scope_filter(
            session,
            client_id=client_id,
            location_id=location_id,
        )
        if normalized_client_id is not None:
            require_scope(
                principal,
                "audit.read",
                client_id=normalized_client_id,
                location_id=normalized_location_id,
            )
        statement = select(AuditEvent).where(
            scope_clause(
                principal,
                "audit.read",
                AuditEvent.client_id,
                AuditEvent.location_id,
            )
        )
        if normalized_client_id is not None:
            statement = statement.where(AuditEvent.client_id == normalized_client_id)
        if normalized_location_id is not None:
            statement = statement.where(AuditEvent.location_id == normalized_location_id)
        events = session.scalars(
            statement.order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_event_id.desc(),
            ).limit(limit)
        ).all()
        return {
            "items": [
                {
                    "audit_event_id": event.audit_event_id,
                    "event_type": event.event_type,
                    "outcome": event.outcome,
                    "actor": event.actor,
                    "user_id": event.user_id,
                    "auth_method": event.auth_method,
                    "client_id": event.client_id,
                    "location_id": event.location_id,
                    "endpoint_id": event.endpoint_id,
                    "target_type": event.target_type,
                    "target_id": event.target_id,
                    "request_id": event.request_id,
                    "metadata": event.metadata_json,
                    "created_at": event.created_at,
                }
                for event in events
            ]
        }
