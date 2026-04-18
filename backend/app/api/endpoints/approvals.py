from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.db import DatabaseStore, get_store
from app.models import ApprovalGrant, Endpoint
from app.schemas.contracts import (
    ApprovalGrantCreateRequest,
    ApprovalGrantListResponse,
    ApprovalGrantResponse,
)
from app.utils import (
    APPROVAL_ACTIONS,
    generate_prefixed_id,
    normalize_approval_action,
    normalize_endpoint_id,
    normalize_optional_string,
    normalize_required_string,
    to_utc_z,
    utc_now,
)

router = APIRouter(prefix="/api/approval-grants", tags=["approval-grants"])


def _approval_grant_payload(grant: ApprovalGrant) -> dict[str, object]:
    return {
        "approval_grant_id": grant.approval_grant_id,
        "endpoint_ids": list(grant.endpoint_ids),
        "allowed_actions": list(grant.allowed_actions),
        "requested_by": grant.requested_by,
        "approved_by": grant.approved_by,
        "reason": grant.reason,
        "expires_at": grant.expires_at,
        "status": grant.status,
        "created_at": grant.created_at,
        "updated_at": grant.updated_at,
    }


@router.get("", response_model=ApprovalGrantListResponse)
def list_approval_grants(
    store: DatabaseStore = Depends(get_store),
) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        grants = session.scalars(
            select(ApprovalGrant).order_by(
                ApprovalGrant.created_at.asc(),
                ApprovalGrant.approval_grant_id.asc(),
            )
        ).all()
    return {"items": [_approval_grant_payload(grant) for grant in grants]}


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ApprovalGrantResponse)
def create_approval_grant(
    payload: ApprovalGrantCreateRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    if not payload.endpoint_ids:
        raise HTTPException(status_code=422, detail="endpoint_ids must not be empty")
    if not payload.allowed_actions:
        raise HTTPException(status_code=422, detail="allowed_actions must not be empty")

    endpoint_ids = [normalize_endpoint_id(endpoint_id) for endpoint_id in payload.endpoint_ids]
    allowed_actions = [normalize_approval_action(action.value) for action in payload.allowed_actions]
    requested_by = normalize_required_string(payload.requested_by, "requested_by")
    approved_by = normalize_required_string(payload.approved_by, "approved_by")
    reason = normalize_required_string(payload.reason, "reason")
    expires_at = to_utc_z(payload.expires_at)
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            existing_endpoint_ids = set(
                session.scalars(
                    select(Endpoint.endpoint_id).where(Endpoint.endpoint_id.in_(set(endpoint_ids)))
                ).all()
            )
            if existing_endpoint_ids != set(endpoint_ids):
                raise HTTPException(status_code=422, detail="one or more endpoint_ids were not found")

            if len(endpoint_ids) != len(set(endpoint_ids)):
                raise HTTPException(status_code=422, detail="duplicate endpoint_ids are not allowed")
            if len(allowed_actions) != len(set(allowed_actions)):
                raise HTTPException(status_code=422, detail="duplicate allowed_actions are not allowed")

            grant = ApprovalGrant(
                approval_grant_id=generate_prefixed_id("grant"),
                endpoint_ids=endpoint_ids,
                allowed_actions=allowed_actions,
                requested_by=requested_by,
                approved_by=approved_by,
                reason=reason,
                expires_at=expires_at,
                status="approved",
                created_at=now,
                updated_at=now,
            )
            session.add(grant)
            session.flush()
            return _approval_grant_payload(grant)
