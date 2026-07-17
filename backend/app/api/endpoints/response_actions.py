from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from secrets import compare_digest, token_urlsafe

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError

from app.api.endpoints.approvals import _sync_expired_grants
from app.api.endpoints.endpoints import _parse_declared_capabilities
from app.auth import (
    Principal,
    current_principal,
    enforce_device_endpoint,
    enforce_endpoint_credential_mode,
)
from app.authorization import record_audit_event, require_permission, scope_clause
from app.control_registry import require_control_action
from app.db import DatabaseStore, get_store
from app.models import ApprovalGrant, Endpoint, ResponseAction
from app.schemas.contracts import (
    ResponseActionCreateRequest,
    ResponseActionClaimResponse,
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
_LEASE_SECONDS = 120


def _declares_action_capability(
    declared_capabilities: list[str],
    *,
    action: str,
    control_id: str | None,
) -> bool:
    if action in declared_capabilities:
        return True
    return control_id is not None and f"{action}:{control_id}" in declared_capabilities


def _response_action_payload(action: ResponseAction) -> dict[str, object]:
    return {
        "response_action_id": action.response_action_id,
        "endpoint_id": action.endpoint_id,
        "approval_grant_id": action.approval_grant_id,
        "action": action.action,
        "control_id": action.control_id,
        "troubleshooting_scope": action.troubleshooting_scope,
        "idempotency_key": action.idempotency_key,
        "requested_by": action.requested_by,
        "reason": action.reason,
        "status": action.status,
        "lease_expires_at": action.lease_expires_at,
        "leased_at": action.leased_at,
        "attempt_count": action.attempt_count,
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


def _same_action_request(
    existing: ResponseAction,
    *,
    approval_grant_id: str,
    action: str,
    control_id: str | None,
    troubleshooting_scope: str | None,
    requested_by: str,
    reason: str,
) -> bool:
    return (
        existing.approval_grant_id == approval_grant_id
        and existing.action == action
        and existing.control_id == control_id
        and existing.troubleshooting_scope == troubleshooting_scope
        and existing.requested_by == requested_by
        and existing.reason == reason
    )


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
    principal: Principal = Depends(require_permission("response_action.create")),
) -> dict[str, object]:
    endpoint_id = normalize_endpoint_id(payload.endpoint_id)
    approval_grant_id = normalize_required_string(payload.approval_grant_id, "approval_grant_id")
    action, control_id, troubleshooting_scope = _normalize_action_shape(
        payload.action.value,
        payload.control_id,
        payload.troubleshooting_scope.value if payload.troubleshooting_scope is not None else None,
    )
    requested_by = principal.audit_actor
    reason = normalize_required_string(payload.reason, "reason")
    idempotency_key = (
        normalize_required_string(payload.idempotency_key, "idempotency_key")
        if payload.idempotency_key is not None
        else generate_prefixed_id("idem")
    )
    now_str = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
            endpoint = session.scalar(
                select(Endpoint).where(
                    Endpoint.endpoint_id == endpoint_id,
                    scope_clause(
                        principal,
                        "response_action.create",
                        Endpoint.client_id,
                        Endpoint.location_id,
                    ),
                )
            )
            if endpoint is None:
                raise HTTPException(status_code=404, detail="endpoint not found")
            if action in _HARDENING_ACTIONS and control_id is not None:
                try:
                    require_control_action(
                        control_id,
                        platform=endpoint.platform,
                        action="apply_control" if action == "apply_control" else "rollback_control",
                    )
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
            if not _declares_action_capability(
                _parse_declared_capabilities(endpoint),
                action=action,
                control_id=control_id,
            ):
                raise HTTPException(status_code=422, detail="endpoint has not declared action capability")
            grant = session.scalar(
                select(ApprovalGrant).where(
                    ApprovalGrant.approval_grant_id == approval_grant_id,
                    ApprovalGrant.scope_state == "active",
                    ApprovalGrant.client_id == endpoint.client_id,
                    or_(
                        ApprovalGrant.location_id.is_(None),
                        ApprovalGrant.location_id == endpoint.location_id,
                    ),
                )
            )
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
            existing = session.scalar(
                select(ResponseAction).where(
                    ResponseAction.endpoint_id == endpoint_id,
                    ResponseAction.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if _same_action_request(
                    existing,
                    approval_grant_id=approval_grant_id,
                    action=action,
                    control_id=control_id,
                    troubleshooting_scope=troubleshooting_scope,
                    requested_by=requested_by,
                    reason=reason,
                ):
                    return _response_action_payload(existing)
                raise HTTPException(
                    status_code=409,
                    detail="idempotency_key is already bound to a different response action",
                )
            response_action = ResponseAction(
                response_action_id=generate_prefixed_id("act"),
                endpoint_id=endpoint_id,
                approval_grant_id=approval_grant_id,
                action=action,
                control_id=control_id,
                troubleshooting_scope=troubleshooting_scope,
                idempotency_key=idempotency_key,
                requested_by=requested_by,
                reason=reason,
                status="queued",
                lease_token_hash=None,
                lease_expires_at=None,
                leased_at=None,
                attempt_count=0,
                result_summary=None,
                created_at=now_str,
                updated_at=now_str,
                completed_at=None,
            )
            savepoint = session.begin_nested()
            try:
                session.add(response_action)
                session.flush()
            except IntegrityError:
                savepoint.rollback()
                existing = session.scalar(
                    select(ResponseAction).where(
                        ResponseAction.endpoint_id == endpoint_id,
                        ResponseAction.idempotency_key == idempotency_key,
                    )
                )
                if existing is not None and _same_action_request(
                    existing,
                    approval_grant_id=approval_grant_id,
                    action=action,
                    control_id=control_id,
                    troubleshooting_scope=troubleshooting_scope,
                    requested_by=requested_by,
                    reason=reason,
                ):
                    return _response_action_payload(existing)
                raise HTTPException(
                    status_code=409,
                    detail="idempotency_key is already bound to a different response action",
                ) from None
            else:
                savepoint.commit()
            record_audit_event(
                session,
                event_type="response_action_created",
                principal=principal,
                client_id=endpoint.client_id,
                location_id=endpoint.location_id,
                endpoint_id=endpoint.endpoint_id,
                target_type="response_action",
                target_id=response_action.response_action_id,
                metadata={"action": response_action.action},
                created_at=now_str,
            )
            return _response_action_payload(response_action)


@router.post(
    "/api/endpoints/{endpoint_id}/response-actions/claim",
    response_model=ResponseActionClaimResponse,
)
def claim_endpoint_response_action(
    endpoint_id: str,
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(current_principal),
) -> dict[str, list[dict[str, object]]]:
    endpoint_id = normalize_endpoint_id(endpoint_id)
    enforce_device_endpoint(principal, endpoint_id)
    now_dt = utc_now()
    now_str = to_utc_z(now_dt)
    lease_expires_at = to_utc_z(now_dt + timedelta(seconds=_LEASE_SECONDS))
    lease_token = token_urlsafe(32)
    lease_token_hash = sha256(lease_token.encode("utf-8")).hexdigest()

    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
            endpoint = session.get(Endpoint, endpoint_id)
            if endpoint is None:
                raise HTTPException(status_code=404, detail="endpoint not found")
            enforce_endpoint_credential_mode(principal, endpoint.credential_mode)
            if endpoint.status == "pending":
                raise HTTPException(status_code=403, detail="endpoint approval is pending")

            claimable = or_(
                ResponseAction.status == "queued",
                and_(
                    ResponseAction.status == "leased",
                    ResponseAction.lease_expires_at <= now_str,
                ),
            )
            candidate_id = (
                select(ResponseAction.response_action_id)
                .join(
                    ApprovalGrant,
                    ApprovalGrant.approval_grant_id == ResponseAction.approval_grant_id,
                )
                .where(
                    ResponseAction.endpoint_id == endpoint_id,
                    claimable,
                    ApprovalGrant.status == "approved",
                    ApprovalGrant.expires_at > now_str,
                )
                .order_by(
                    ResponseAction.created_at.asc(),
                    ResponseAction.response_action_id.asc(),
                )
                .limit(1)
                .scalar_subquery()
            )
            claimed = session.scalar(
                update(ResponseAction)
                .where(
                    ResponseAction.response_action_id == candidate_id,
                    ResponseAction.endpoint_id == endpoint_id,
                    claimable,
                )
                .values(
                    status="leased",
                    lease_token_hash=lease_token_hash,
                    lease_expires_at=lease_expires_at,
                    leased_at=now_str,
                    attempt_count=ResponseAction.attempt_count + 1,
                    updated_at=now_str,
                )
                .returning(ResponseAction)
            )
            if claimed is None:
                return {"items": []}
            item = _response_action_payload(claimed)
            item["lease_token"] = lease_token
            return {"items": [item]}


@router.get("/api/endpoints/{endpoint_id}/response-actions", response_model=ResponseActionListResponse)
def list_endpoint_response_actions(
    endpoint_id: str,
    include_terminal: bool = Query(False),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("response_action.read")),
) -> dict[str, list[dict[str, object]]]:
    endpoint_id = normalize_endpoint_id(endpoint_id)
    now_str = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)
        if session.scalar(
            select(Endpoint).where(
                Endpoint.endpoint_id == endpoint_id,
                scope_clause(
                    principal,
                    "response_action.read",
                    Endpoint.client_id,
                    Endpoint.location_id,
                ),
            )
        ) is None:
            raise HTTPException(status_code=404, detail="endpoint not found")
        query = select(ResponseAction).where(ResponseAction.endpoint_id == endpoint_id)
        if not include_terminal:
            query = (
                query.join(ApprovalGrant, ApprovalGrant.approval_grant_id == ResponseAction.approval_grant_id)
                .where(
                    ResponseAction.status.in_(("queued", "leased")),
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
    principal: Principal = Depends(current_principal),
) -> dict[str, object]:
    response_action_id = normalize_required_string(response_action_id, "response_action_id")
    result_status = payload.status.value
    if result_status not in {"succeeded", "failed"}:
        raise HTTPException(status_code=422, detail="result status must be succeeded or failed")
    result_summary = normalize_required_string(payload.result_summary, "result_summary")
    lease_token_hash = sha256(payload.lease_token.encode("utf-8")).hexdigest()
    now_str = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            response_action = session.get(ResponseAction, response_action_id)
            if response_action is None:
                raise HTTPException(status_code=404, detail="response action not found")
            enforce_device_endpoint(principal, response_action.endpoint_id)
            endpoint = session.get(Endpoint, response_action.endpoint_id)
            if endpoint is None:
                raise HTTPException(status_code=404, detail="endpoint not found")
            enforce_endpoint_credential_mode(principal, endpoint.credential_mode)
            if endpoint.status == "pending":
                raise HTTPException(status_code=403, detail="endpoint approval is pending")
            lease_matches = bool(
                response_action.lease_token_hash
                and compare_digest(lease_token_hash, response_action.lease_token_hash)
            )
            if response_action.status in {"succeeded", "failed"}:
                if (
                    lease_matches
                    and response_action.status == result_status
                    and response_action.result_summary == result_summary
                ):
                    return _response_action_payload(response_action)
                raise HTTPException(status_code=409, detail="response action is already terminal")
            if response_action.status != "leased":
                raise HTTPException(status_code=409, detail="response action does not have an active lease")
            if not lease_matches:
                raise HTTPException(status_code=409, detail="response action lease does not match")
            if response_action.lease_expires_at is None or response_action.lease_expires_at <= now_str:
                raise HTTPException(status_code=409, detail="response action lease has expired")
            response_action.status = result_status
            response_action.result_summary = result_summary
            response_action.updated_at = now_str
            response_action.completed_at = now_str
            session.flush()
            record_audit_event(
                session,
                event_type="response_action_completed",
                principal=principal,
                client_id=endpoint.client_id,
                location_id=endpoint.location_id,
                endpoint_id=endpoint.endpoint_id,
                target_type="response_action",
                target_id=response_action.response_action_id,
                metadata={"status": response_action.status},
                created_at=now_str,
            )
            return _response_action_payload(response_action)
