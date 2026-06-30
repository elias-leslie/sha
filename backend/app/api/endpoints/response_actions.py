from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.endpoints.approvals import _sync_expired_grants
from app.api.endpoints.endpoints import _parse_declared_capabilities
from app.db import DatabaseStore, get_store
from app.models import ApprovalGrant, Endpoint, ResponseAction
from app.schemas.contracts import (
    ResponseActionCreateRequest,
    ResponseActionListResponse,
    ResponseActionResponse,
    ResponseActionResultRequest,
)
from app.utils import (
    generate_prefixed_id,
    normalize_approval_action,
    normalize_endpoint_id,
    normalize_optional_string,
    normalize_required_string,
    normalize_troubleshooting_scope,
    to_utc_z,
    utc_now,
)

router = APIRouter(tags=["response-actions"])

_HARDENING_ACTIONS = {"apply_control", "rollback_control"}
_UNSCOPED_RESPONSE_ACTIONS = {"collect_remediation_evidence"}


def pending_response_action_count(session: Session, endpoint_id: str, now_str: str) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(ResponseAction)
            .join(ApprovalGrant, ApprovalGrant.approval_grant_id == ResponseAction.approval_grant_id)
            .where(
                ResponseAction.endpoint_id == endpoint_id,
                ResponseAction.status == "queued",
                ApprovalGrant.status == "approved",
                ApprovalGrant.expires_at > now_str,
            )
        )
        or 0
    )


def _response_action_payload(action: ResponseAction) -> dict[str, object]:
    return {
        "response_action_id": action.response_action_id,
        "endpoint_id": action.endpoint_id,
        "approval_grant_id": action.approval_grant_id,
        "action": action.action,
        "control_id": action.control_id,
        "troubleshooting_scope": action.troubleshooting_scope,
        "requested_by": action.requested_by,
        "reason": action.reason,
        "status": action.status,
        "result_summary": action.result_summary,
        "created_at": action.created_at,
        "updated_at": action.updated_at,
        "completed_at": action.completed_at,
    }


def _normalize_action_shape(
    raw_action: str,
    raw_control_id: str | None,
    raw_troubleshooting_scope: str | None,
) -> tuple[str, str | None, str | None]:
    action = normalize_approval_action(raw_action)
    control_id = normalize_optional_string(raw_control_id, "control_id")
    troubleshooting_scope = (
        normalize_troubleshooting_scope(raw_troubleshooting_scope)
        if raw_troubleshooting_scope is not None
        else None
    )
    if action in _HARDENING_ACTIONS:
        if not control_id:
            raise HTTPException(status_code=422, detail="hardening actions require control_id")
        if troubleshooting_scope:
            raise HTTPException(status_code=422, detail="hardening actions must not include troubleshooting_scope")
        return action, control_id, None
    if action in _UNSCOPED_RESPONSE_ACTIONS:
        if control_id:
            raise HTTPException(status_code=422, detail="unscoped response actions must not include control_id")
        if troubleshooting_scope:
            raise HTTPException(status_code=422, detail="unscoped response actions must not include troubleshooting_scope")
        return action, None, None
    if control_id:
        raise HTTPException(status_code=422, detail="troubleshooting actions must not include control_id")
    if not troubleshooting_scope:
        raise HTTPException(status_code=422, detail="troubleshooting actions require troubleshooting_scope")
    return action, None, troubleshooting_scope


def _validate_grant_scope(
    *,
    grant: ApprovalGrant,
    endpoint_id: str,
    action: str,
    control_id: str | None,
    troubleshooting_scope: str | None,
    now_str: str,
) -> None:
    if grant.status != "approved" or grant.expires_at <= now_str:
        raise HTTPException(status_code=409, detail="approval grant is not active")
    if endpoint_id not in grant.endpoint_ids:
        raise HTTPException(status_code=422, detail="approval grant does not include endpoint_id")
    if action not in grant.allowed_actions:
        raise HTTPException(status_code=422, detail="approval grant does not allow action")
    if control_id is not None and control_id not in grant.control_ids:
        raise HTTPException(status_code=422, detail="approval grant does not include control_id")
    if troubleshooting_scope is not None and troubleshooting_scope not in grant.troubleshooting_scopes:
        raise HTTPException(status_code=422, detail="approval grant does not include troubleshooting_scope")


@router.post("/api/response-actions", status_code=status.HTTP_201_CREATED, response_model=ResponseActionResponse)
def create_response_action(
    payload: ResponseActionCreateRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    endpoint_id = normalize_endpoint_id(payload.endpoint_id)
    approval_grant_id = normalize_required_string(payload.approval_grant_id, "approval_grant_id")
    action, control_id, troubleshooting_scope = _normalize_action_shape(
        payload.action.value,
        payload.control_id,
        payload.troubleshooting_scope.value if payload.troubleshooting_scope is not None else None,
    )
    requested_by = normalize_required_string(payload.requested_by, "requested_by")
    reason = normalize_required_string(payload.reason, "reason")
    now_str = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
            endpoint = session.get(Endpoint, endpoint_id)
            if endpoint is None:
                raise HTTPException(status_code=404, detail="endpoint not found")
            if action not in _parse_declared_capabilities(endpoint):
                raise HTTPException(status_code=422, detail="endpoint has not declared action capability")
            grant = session.get(ApprovalGrant, approval_grant_id)
            if grant is None:
                raise HTTPException(status_code=404, detail="approval grant not found")
            _validate_grant_scope(
                grant=grant,
                endpoint_id=endpoint_id,
                action=action,
                control_id=control_id,
                troubleshooting_scope=troubleshooting_scope,
                now_str=now_str,
            )
            response_action = ResponseAction(
                response_action_id=generate_prefixed_id("act"),
                endpoint_id=endpoint_id,
                approval_grant_id=approval_grant_id,
                action=action,
                control_id=control_id,
                troubleshooting_scope=troubleshooting_scope,
                requested_by=requested_by,
                reason=reason,
                status="queued",
                result_summary=None,
                created_at=now_str,
                updated_at=now_str,
                completed_at=None,
            )
            session.add(response_action)
            session.flush()
            return _response_action_payload(response_action)


@router.get("/api/endpoints/{endpoint_id}/response-actions", response_model=ResponseActionListResponse)
def list_endpoint_response_actions(
    endpoint_id: str,
    include_terminal: bool = Query(False),
    store: DatabaseStore = Depends(get_store),
) -> dict[str, list[dict[str, object]]]:
    endpoint_id = normalize_endpoint_id(endpoint_id)
    now_str = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
        if session.get(Endpoint, endpoint_id) is None:
            raise HTTPException(status_code=404, detail="endpoint not found")
        query = select(ResponseAction).where(ResponseAction.endpoint_id == endpoint_id)
        if not include_terminal:
            query = (
                query.join(ApprovalGrant, ApprovalGrant.approval_grant_id == ResponseAction.approval_grant_id)
                .where(
                    ResponseAction.status == "queued",
                    ApprovalGrant.status == "approved",
                    ApprovalGrant.expires_at > now_str,
                )
            )
        actions = session.scalars(query.order_by(ResponseAction.created_at.asc(), ResponseAction.response_action_id.asc())).all()
    return {"items": [_response_action_payload(action) for action in actions]}


@router.post("/api/response-actions/{response_action_id}/result", response_model=ResponseActionResponse)
def complete_response_action(
    response_action_id: str,
    payload: ResponseActionResultRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    response_action_id = normalize_required_string(response_action_id, "response_action_id")
    result_status = payload.status.value
    if result_status not in {"succeeded", "failed"}:
        raise HTTPException(status_code=422, detail="result status must be succeeded or failed")
    result_summary = normalize_required_string(payload.result_summary, "result_summary")
    now_str = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            response_action = session.get(ResponseAction, response_action_id)
            if response_action is None:
                raise HTTPException(status_code=404, detail="response action not found")
            if response_action.status != "queued":
                raise HTTPException(status_code=409, detail="response action is already terminal")
            response_action.status = result_status
            response_action.result_summary = result_summary
            response_action.updated_at = now_str
            response_action.completed_at = now_str
            session.flush()
            return _response_action_payload(response_action)
