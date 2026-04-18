from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import DatabaseStore, get_store
from app.models import ApprovalGrant, ApprovalRequest, ApprovalRequestEvent, Endpoint
from app.schemas.contracts import (
    ApprovalDecisionRequest,
    ApprovalGrantCreateRequest,
    ApprovalGrantListResponse,
    ApprovalGrantResponse,
    ApprovalRequestCreateRequest,
    ApprovalRequestListResponse,
    ApprovalRequestResponse,
)
from app.utils import (
    generate_prefixed_id,
    has_duplicates,
    normalize_approval_action,
    normalize_approval_decision,
    normalize_approval_request_kind,
    normalize_approval_risk,
    normalize_endpoint_id,
    normalize_required_string,
    normalize_troubleshooting_scope,
    to_utc_z,
    utc_now,
)

router = APIRouter(tags=["approvals"])

_HARDENING_ACTIONS = {"apply_control", "rollback_control"}
_TROUBLESHOOTING_ACTIONS = {
    "request_elevated_troubleshooting",
    "collect_security_context",
    "collect_remediation_evidence",
    "inspect_control",
}
_EXPIRED_COMMENT = "Grant expired automatically."


def _approval_event_payload(event: ApprovalRequestEvent) -> dict[str, object]:
    return {
        "approval_event_id": event.approval_event_id,
        "event_type": event.event_type,
        "actor": event.actor,
        "comment": event.comment,
        "created_at": event.created_at,
    }


def _approval_request_payload(
    request: ApprovalRequest,
    events: list[ApprovalRequestEvent],
) -> dict[str, object]:
    return {
        "approval_request_id": request.approval_request_id,
        "endpoint_ids": list(request.endpoint_ids),
        "request_kind": request.request_kind,
        "requested_actions": list(request.requested_actions),
        "control_ids": list(request.control_ids),
        "troubleshooting_scopes": list(request.troubleshooting_scopes),
        "requested_ttl_minutes": request.requested_ttl_minutes,
        "requested_by": request.requested_by,
        "reason": request.reason,
        "risk": request.risk,
        "status": request.status,
        "decision_by": request.decision_by,
        "decision_comment": request.decision_comment,
        "decision_at": request.decision_at,
        "approval_grant_id": request.approval_grant_id,
        "created_at": request.created_at,
        "updated_at": request.updated_at,
        "audit_events": [_approval_event_payload(event) for event in events],
    }


def _approval_grant_payload(grant: ApprovalGrant) -> dict[str, object]:
    return {
        "approval_grant_id": grant.approval_grant_id,
        "approval_request_id": grant.approval_request_id,
        "endpoint_ids": list(grant.endpoint_ids),
        "allowed_actions": list(grant.allowed_actions),
        "control_ids": list(grant.control_ids),
        "troubleshooting_scopes": list(grant.troubleshooting_scopes),
        "requested_by": grant.requested_by,
        "approved_by": grant.approved_by,
        "reason": grant.reason,
        "expires_at": grant.expires_at,
        "status": grant.status,
        "created_at": grant.created_at,
        "updated_at": grant.updated_at,
    }


def _normalize_endpoint_ids(session: Session, raw_endpoint_ids: list[str]) -> list[str]:
    endpoint_ids = [normalize_endpoint_id(endpoint_id) for endpoint_id in raw_endpoint_ids]
    requested_ids = set(endpoint_ids)
    existing_ids = set(
        session.scalars(select(Endpoint.endpoint_id).where(Endpoint.endpoint_id.in_(requested_ids))).all()
    )
    if existing_ids != requested_ids:
        raise HTTPException(status_code=422, detail="one or more endpoint_ids were not found")
    if has_duplicates(endpoint_ids):
        raise HTTPException(status_code=422, detail="duplicate endpoint_ids are not allowed")
    return endpoint_ids


def _normalize_control_ids(raw_control_ids: list[str]) -> list[str]:
    control_ids = [normalize_required_string(control_id, "control_id") for control_id in raw_control_ids]
    if has_duplicates(control_ids):
        raise HTTPException(status_code=422, detail="duplicate control_ids are not allowed")
    return control_ids


def _normalize_troubleshooting_scopes(raw_scopes: list[str]) -> list[str]:
    scopes = [normalize_troubleshooting_scope(scope) for scope in raw_scopes]
    if has_duplicates(scopes):
        raise HTTPException(status_code=422, detail="duplicate troubleshooting_scopes are not allowed")
    return scopes


def _normalize_actions(raw_actions: list[str]) -> list[str]:
    actions = [normalize_approval_action(action) for action in raw_actions]
    if has_duplicates(actions):
        raise HTTPException(status_code=422, detail="duplicate allowed_actions are not allowed")
    return actions


def _validate_request_shape(
    request_kind: str,
    requested_actions: list[str],
    control_ids: list[str],
    troubleshooting_scopes: list[str],
) -> None:
    if request_kind == "hardening_change":
        if not requested_actions or any(action not in _HARDENING_ACTIONS for action in requested_actions):
            raise HTTPException(
                status_code=422,
                detail="hardening_change requests may only use apply_control or rollback_control",
            )
        if not control_ids:
            raise HTTPException(status_code=422, detail="hardening_change requests require control_ids")
        if troubleshooting_scopes:
            raise HTTPException(
                status_code=422,
                detail="hardening_change requests must not include troubleshooting_scopes",
            )
        return

    if "request_elevated_troubleshooting" not in requested_actions:
        raise HTTPException(
            status_code=422,
            detail="elevated_troubleshooting requests must include request_elevated_troubleshooting",
        )
    if any(action not in _TROUBLESHOOTING_ACTIONS for action in requested_actions):
        raise HTTPException(
            status_code=422,
            detail="elevated_troubleshooting requests may only use bounded troubleshooting actions",
        )
    if control_ids:
        raise HTTPException(
            status_code=422,
            detail="elevated_troubleshooting requests must not include control_ids",
        )
    if not troubleshooting_scopes:
        raise HTTPException(
            status_code=422,
            detail="elevated_troubleshooting requests require troubleshooting_scopes",
        )


def _validate_manual_grant_shape(
    allowed_actions: list[str],
    control_ids: list[str],
    troubleshooting_scopes: list[str],
) -> None:
    has_hardening_signal = any(action in _HARDENING_ACTIONS for action in allowed_actions) or bool(control_ids)
    has_troubleshooting_signal = any(action in _TROUBLESHOOTING_ACTIONS for action in allowed_actions) or bool(
        troubleshooting_scopes
    )
    if has_hardening_signal and has_troubleshooting_signal:
        raise HTTPException(
            status_code=422,
            detail="manual approval grants must represent either hardening changes or elevated troubleshooting, not both",
        )
    if has_troubleshooting_signal:
        if "request_elevated_troubleshooting" not in allowed_actions:
            raise HTTPException(
                status_code=422,
                detail="elevated troubleshooting grants must include request_elevated_troubleshooting",
            )
        if any(action not in _TROUBLESHOOTING_ACTIONS for action in allowed_actions):
            raise HTTPException(
                status_code=422,
                detail="elevated troubleshooting grants may only use bounded troubleshooting actions",
            )
        if control_ids:
            raise HTTPException(
                status_code=422,
                detail="elevated troubleshooting grants must not include control_ids",
            )
        if not troubleshooting_scopes:
            raise HTTPException(
                status_code=422,
                detail="elevated troubleshooting grants require troubleshooting_scopes",
            )
        return
    if not allowed_actions or any(action not in _HARDENING_ACTIONS for action in allowed_actions):
        raise HTTPException(
            status_code=422,
            detail="hardening grants may only use apply_control or rollback_control",
        )
    if not control_ids:
        raise HTTPException(status_code=422, detail="hardening grants require control_ids")
    if troubleshooting_scopes:
        raise HTTPException(
            status_code=422,
            detail="hardening grants must not include troubleshooting_scopes",
        )


def _create_audit_event(
    session: Session,
    *,
    approval_request_id: str,
    event_type: str,
    actor: str,
    comment: str,
    created_at: str,
) -> ApprovalRequestEvent:
    event = ApprovalRequestEvent(
        approval_event_id=generate_prefixed_id("ape"),
        approval_request_id=approval_request_id,
        event_type=event_type,
        actor=actor,
        comment=comment,
        created_at=created_at,
    )
    session.add(event)
    return event


def _sync_expired_grants(session: Session, *, now_str: str) -> None:
    grants = session.scalars(
        select(ApprovalGrant)
        .where(ApprovalGrant.status == "approved")
        .order_by(ApprovalGrant.created_at.asc(), ApprovalGrant.approval_grant_id.asc())
    ).all()
    for grant in grants:
        if grant.expires_at > now_str:
            continue
        grant.status = "expired"
        grant.updated_at = now_str
        if not grant.approval_request_id:
            continue
        request = session.get(ApprovalRequest, grant.approval_request_id)
        if request is None:
            continue
        if request.status == "approved":
            request.status = "expired"
            request.updated_at = now_str
            savepoint = session.begin_nested()
            try:
                _create_audit_event(
                    session,
                    approval_request_id=request.approval_request_id,
                    event_type="expired",
                    actor=request.decision_by or "system",
                    comment=_EXPIRED_COMMENT,
                    created_at=now_str,
                )
                session.flush()
            except IntegrityError:
                savepoint.rollback()
            else:
                savepoint.commit()


def _collect_request_events(
    session: Session,
    approval_request_ids: list[str],
) -> dict[str, list[ApprovalRequestEvent]]:
    if not approval_request_ids:
        return {}
    events = session.scalars(
        select(ApprovalRequestEvent)
        .where(ApprovalRequestEvent.approval_request_id.in_(approval_request_ids))
        .order_by(ApprovalRequestEvent.created_at.asc(), ApprovalRequestEvent.approval_event_id.asc())
    ).all()
    grouped: dict[str, list[ApprovalRequestEvent]] = defaultdict(list)
    for event in events:
        grouped[event.approval_request_id].append(event)
    return grouped


@router.get("/api/approval-requests", response_model=ApprovalRequestListResponse)
def list_approval_requests(
    store: DatabaseStore = Depends(get_store),
) -> dict[str, list[dict[str, object]]]:
    now_str = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
        requests = session.scalars(
            select(ApprovalRequest).order_by(
                ApprovalRequest.created_at.asc(),
                ApprovalRequest.approval_request_id.asc(),
            )
        ).all()
        events_by_request = _collect_request_events(
            session,
            [request.approval_request_id for request in requests],
        )
    return {
        "items": [
            _approval_request_payload(request, events_by_request.get(request.approval_request_id, []))
            for request in requests
        ]
    }


@router.post(
    "/api/approval-requests",
    status_code=status.HTTP_201_CREATED,
    response_model=ApprovalRequestResponse,
)
def create_approval_request(
    payload: ApprovalRequestCreateRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    request_kind = normalize_approval_request_kind(payload.request_kind.value)
    requested_actions = _normalize_actions([action.value for action in payload.requested_actions])
    control_ids = _normalize_control_ids(payload.control_ids)
    troubleshooting_scopes = _normalize_troubleshooting_scopes(
        [scope.value for scope in payload.troubleshooting_scopes]
    )
    requested_by = normalize_required_string(payload.requested_by, "requested_by")
    reason = normalize_required_string(payload.reason, "reason")
    risk = normalize_approval_risk(payload.risk.value)
    requested_ttl_minutes = payload.requested_ttl_minutes
    if not 15 <= requested_ttl_minutes <= 240:
        raise HTTPException(status_code=422, detail="requested_ttl_minutes must be between 15 and 240")
    _validate_request_shape(request_kind, requested_actions, control_ids, troubleshooting_scopes)
    now_str = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            endpoint_ids = _normalize_endpoint_ids(session, payload.endpoint_ids)
            request = ApprovalRequest(
                approval_request_id=generate_prefixed_id("apr"),
                endpoint_ids=endpoint_ids,
                request_kind=request_kind,
                requested_actions=requested_actions,
                control_ids=control_ids,
                troubleshooting_scopes=troubleshooting_scopes,
                requested_ttl_minutes=requested_ttl_minutes,
                requested_by=requested_by,
                reason=reason,
                risk=risk,
                status="pending",
                decision_by=None,
                decision_comment=None,
                decision_at=None,
                approval_grant_id=None,
                created_at=now_str,
                updated_at=now_str,
            )
            session.add(request)
            session.flush()
            event = _create_audit_event(
                session,
                approval_request_id=request.approval_request_id,
                event_type="requested",
                actor=requested_by,
                comment=reason,
                created_at=now_str,
            )
            return _approval_request_payload(request, [event])


@router.post(
    "/api/approval-requests/{approval_request_id}/decisions",
    response_model=ApprovalRequestResponse,
)
def decide_approval_request(
    approval_request_id: str,
    payload: ApprovalDecisionRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    approval_request_id = normalize_required_string(approval_request_id, "approval_request_id")
    decision = normalize_approval_decision(payload.decision.value)
    decided_by = normalize_required_string(payload.decided_by, "decided_by")
    decision_comment = normalize_required_string(payload.decision_comment, "decision_comment")
    now_dt = utc_now()
    now_str = to_utc_z(now_dt)

    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
            request = session.get(ApprovalRequest, approval_request_id)
            if request is None:
                raise HTTPException(status_code=404, detail="approval request not found")

            if decision == "approve":
                if request.status != "pending":
                    raise HTTPException(
                        status_code=409,
                        detail="approval request is not in a state that allows this decision",
                    )
                if payload.expires_at is None:
                    raise HTTPException(status_code=422, detail="expires_at is required for approve decisions")
                expires_at_dt = payload.expires_at
                upper_bound = now_dt + timedelta(minutes=request.requested_ttl_minutes)
                if expires_at_dt.tzinfo is None:
                    expires_at_dt = expires_at_dt.replace(tzinfo=now_dt.tzinfo)
                expires_at_str = to_utc_z(expires_at_dt)
                if not (now_str < expires_at_str <= to_utc_z(upper_bound)):
                    raise HTTPException(
                        status_code=422,
                        detail="expires_at must be within requested_ttl_minutes of decision time",
                    )
                grant = ApprovalGrant(
                    approval_grant_id=generate_prefixed_id("grant"),
                    approval_request_id=request.approval_request_id,
                    endpoint_ids=list(request.endpoint_ids),
                    allowed_actions=list(request.requested_actions),
                    control_ids=list(request.control_ids),
                    troubleshooting_scopes=list(request.troubleshooting_scopes),
                    requested_by=request.requested_by,
                    approved_by=decided_by,
                    reason=request.reason,
                    expires_at=expires_at_str,
                    status="approved",
                    created_at=now_str,
                    updated_at=now_str,
                )
                update_result = session.execute(
                    update(ApprovalRequest)
                    .where(
                        ApprovalRequest.approval_request_id == request.approval_request_id,
                        ApprovalRequest.status == "pending",
                    )
                    .values(
                        status="approved",
                        decision_by=decided_by,
                        decision_comment=decision_comment,
                        decision_at=now_str,
                        approval_grant_id=grant.approval_grant_id,
                        updated_at=now_str,
                    )
                )
                if update_result.rowcount != 1:
                    raise HTTPException(
                        status_code=409,
                        detail="approval request is not in a state that allows this decision",
                    )
                savepoint = session.begin_nested()
                try:
                    session.add(grant)
                    session.flush()
                except IntegrityError:
                    savepoint.rollback()
                    raise HTTPException(
                        status_code=409,
                        detail="approval request is not in a state that allows this decision",
                    ) from None
                else:
                    savepoint.commit()
                _create_audit_event(
                    session,
                    approval_request_id=request.approval_request_id,
                    event_type="approved",
                    actor=decided_by,
                    comment=decision_comment,
                    created_at=now_str,
                )
            elif decision == "deny":
                if request.status != "pending":
                    raise HTTPException(
                        status_code=409,
                        detail="approval request is not in a state that allows this decision",
                    )
                if payload.expires_at is not None:
                    raise HTTPException(status_code=422, detail="expires_at is not allowed for deny decisions")
                update_result = session.execute(
                    update(ApprovalRequest)
                    .where(
                        ApprovalRequest.approval_request_id == request.approval_request_id,
                        ApprovalRequest.status == "pending",
                    )
                    .values(
                        status="denied",
                        decision_by=decided_by,
                        decision_comment=decision_comment,
                        decision_at=now_str,
                        updated_at=now_str,
                    )
                )
                if update_result.rowcount != 1:
                    raise HTTPException(
                        status_code=409,
                        detail="approval request is not in a state that allows this decision",
                    )
                _create_audit_event(
                    session,
                    approval_request_id=request.approval_request_id,
                    event_type="denied",
                    actor=decided_by,
                    comment=decision_comment,
                    created_at=now_str,
                )
            else:
                if request.status != "approved":
                    raise HTTPException(
                        status_code=409,
                        detail="approval request is not in a state that allows this decision",
                    )
                if payload.expires_at is not None:
                    raise HTTPException(status_code=422, detail="expires_at is not allowed for revoke decisions")
                update_result = session.execute(
                    update(ApprovalRequest)
                    .where(
                        ApprovalRequest.approval_request_id == request.approval_request_id,
                        ApprovalRequest.status == "approved",
                    )
                    .values(
                        status="revoked",
                        decision_by=decided_by,
                        decision_comment=decision_comment,
                        decision_at=now_str,
                        updated_at=now_str,
                    )
                )
                if update_result.rowcount != 1:
                    raise HTTPException(
                        status_code=409,
                        detail="approval request is not in a state that allows this decision",
                    )
                session.execute(
                    update(ApprovalGrant)
                    .where(
                        ApprovalGrant.approval_request_id == request.approval_request_id,
                        ApprovalGrant.status == "approved",
                    )
                    .values(status="revoked", updated_at=now_str)
                )
                _create_audit_event(
                    session,
                    approval_request_id=request.approval_request_id,
                    event_type="revoked",
                    actor=decided_by,
                    comment=decision_comment,
                    created_at=now_str,
                )
            session.flush()
            session.expire_all()
            request = session.get(ApprovalRequest, approval_request_id)
            if request is None:
                raise HTTPException(status_code=404, detail="approval request not found")
            events = _collect_request_events(session, [request.approval_request_id])
            return _approval_request_payload(request, events.get(request.approval_request_id, []))


@router.get("/api/approval-grants", response_model=ApprovalGrantListResponse)
def list_approval_grants(
    store: DatabaseStore = Depends(get_store),
) -> dict[str, list[dict[str, object]]]:
    now_str = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
        grants = session.scalars(
            select(ApprovalGrant).order_by(
                ApprovalGrant.created_at.asc(),
                ApprovalGrant.approval_grant_id.asc(),
            )
        ).all()
    return {"items": [_approval_grant_payload(grant) for grant in grants]}


@router.post("/api/approval-grants", status_code=status.HTTP_201_CREATED, response_model=ApprovalGrantResponse)
def create_approval_grant(
    payload: ApprovalGrantCreateRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    allowed_actions = _normalize_actions([action.value for action in payload.allowed_actions])
    control_ids = _normalize_control_ids(payload.control_ids)
    troubleshooting_scopes = _normalize_troubleshooting_scopes(
        [scope.value for scope in payload.troubleshooting_scopes]
    )
    requested_by = normalize_required_string(payload.requested_by, "requested_by")
    approved_by = normalize_required_string(payload.approved_by, "approved_by")
    reason = normalize_required_string(payload.reason, "reason")
    expires_at = to_utc_z(payload.expires_at)
    now_str = to_utc_z(utc_now())
    if expires_at <= now_str:
        raise HTTPException(status_code=422, detail="expires_at must be in the future")

    with store.session() as session:
        with session.begin():
            endpoint_ids = _normalize_endpoint_ids(session, payload.endpoint_ids)
            _validate_manual_grant_shape(allowed_actions, control_ids, troubleshooting_scopes)
            grant = ApprovalGrant(
                approval_grant_id=generate_prefixed_id("grant"),
                approval_request_id=None,
                endpoint_ids=endpoint_ids,
                allowed_actions=allowed_actions,
                control_ids=control_ids,
                troubleshooting_scopes=troubleshooting_scopes,
                requested_by=requested_by,
                approved_by=approved_by,
                reason=reason,
                expires_at=expires_at,
                status="approved",
                created_at=now_str,
                updated_at=now_str,
            )
            session.add(grant)
            session.flush()
            return _approval_grant_payload(grant)
