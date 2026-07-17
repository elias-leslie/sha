from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.endpoints.approvals import (
    _approval_grant_payload,
    _approval_request_payload,
    _collect_request_events,
    _sync_expired_grants,
)
from app.api.endpoints.endpoints import _parse_declared_capabilities, _parse_execution_hooks
from app.api.endpoints.response_actions import _response_action_payload
from app.auth import Principal
from app.authorization import record_audit_event, require_permission, require_scope, scope_clause
from app.db import DatabaseStore, get_store
from app.hierarchy import validate_scope_filter
from app.models import ApprovalGrant, ApprovalRequest, Endpoint, PostureResult, PostureSnapshot, ResponseAction
from app.source_packs.catalog import load_source_catalog
from app.utils import to_utc_z, utc_now

router = APIRouter(tags=["evidence"])


def _posture_result_payload(result: PostureResult) -> dict[str, object]:
    return {
        "control_key": result.control_key,
        "status": result.status,
        "current_value": result.current_value,
        "recommended_value": result.recommended_value,
        "severity": result.severity,
        "evidence_summary": result.evidence_summary,
        "reboot_required": result.reboot_required,
    }


def _endpoint_evidence_payload(endpoint: Endpoint) -> dict[str, object]:
    return {
        "endpoint_id": endpoint.endpoint_id,
        "hostname": endpoint.hostname,
        "platform": endpoint.platform,
        "platform_version": endpoint.platform_version,
        "agent_version": endpoint.agent_version,
        "client_id": endpoint.client_id,
        "location_id": endpoint.location_id,
        "tenant_id": endpoint.tenant_id,
        "site_id": endpoint.site_id,
        "status": endpoint.status,
        "connectivity_status": endpoint.connectivity_status,
        "last_seen_at": endpoint.last_seen_at,
        "last_heartbeat_at": endpoint.last_heartbeat_at,
        "created_at": endpoint.created_at,
        "updated_at": endpoint.updated_at,
        "last_platform_profile": endpoint.platform_profile,
        "declared_capabilities": _parse_declared_capabilities(endpoint),
        "execution_hooks": _parse_execution_hooks(endpoint),
    }


@router.get("/api/compliance/evidence")
def export_compliance_evidence(
    client_id: str | None = Query(None),
    location_id: str | None = Query(None),
    store: DatabaseStore = Depends(get_store),
    principal: Principal = Depends(require_permission("compliance_evidence.export")),
) -> dict[str, object]:
    now_str = to_utc_z(utc_now())
    with store.session() as session:
        with session.begin():
            _sync_expired_grants(session, now_str=now_str)

        normalized_client_id, normalized_location_id = validate_scope_filter(
            session,
            client_id=client_id,
            location_id=location_id,
        )
        if normalized_client_id is not None:
            require_scope(
                principal,
                "compliance_evidence.export",
                client_id=normalized_client_id,
                location_id=normalized_location_id,
            )

        endpoint_statement = select(Endpoint).where(
            scope_clause(
                principal,
                "compliance_evidence.export",
                Endpoint.client_id,
                Endpoint.location_id,
            )
        )
        if normalized_client_id is not None:
            endpoint_statement = endpoint_statement.where(
                Endpoint.client_id == normalized_client_id
            )
        if normalized_location_id is not None:
            endpoint_statement = endpoint_statement.where(
                Endpoint.location_id == normalized_location_id
            )

        endpoints = session.scalars(
            endpoint_statement.order_by(Endpoint.created_at.asc(), Endpoint.endpoint_id.asc())
        ).all()
        endpoint_ids = [endpoint.endpoint_id for endpoint in endpoints]
        endpoint_payloads = [_endpoint_evidence_payload(endpoint) for endpoint in endpoints]
        approval_request_statement = select(ApprovalRequest).where(
            ApprovalRequest.scope_state == "active",
            scope_clause(
                principal,
                "compliance_evidence.export",
                ApprovalRequest.client_id,
                ApprovalRequest.location_id,
            ),
        )
        approval_grant_statement = select(ApprovalGrant).where(
            ApprovalGrant.scope_state == "active",
            scope_clause(
                principal,
                "compliance_evidence.export",
                ApprovalGrant.client_id,
                ApprovalGrant.location_id,
            ),
        )
        if normalized_client_id is not None:
            approval_request_statement = approval_request_statement.where(
                ApprovalRequest.client_id == normalized_client_id
            )
            approval_grant_statement = approval_grant_statement.where(
                ApprovalGrant.client_id == normalized_client_id
            )
        if normalized_location_id is not None:
            approval_request_statement = approval_request_statement.where(
                ApprovalRequest.location_id == normalized_location_id
            )
            approval_grant_statement = approval_grant_statement.where(
                ApprovalGrant.location_id == normalized_location_id
            )
        approval_requests = session.scalars(
            approval_request_statement.order_by(
                ApprovalRequest.created_at.asc(),
                ApprovalRequest.approval_request_id.asc(),
            )
        ).all()
        events_by_request = _collect_request_events(
            session,
            [request.approval_request_id for request in approval_requests],
        )
        approval_grants = session.scalars(
            approval_grant_statement.order_by(
                ApprovalGrant.created_at.asc(), ApprovalGrant.approval_grant_id.asc()
            )
        ).all()
        response_actions = (
            session.scalars(
                select(ResponseAction)
                .where(ResponseAction.endpoint_id.in_(endpoint_ids))
                .order_by(
                    ResponseAction.created_at.asc(),
                    ResponseAction.response_action_id.asc(),
                )
            ).all()
            if endpoint_ids
            else []
        )
        posture_snapshots = (
            session.scalars(
                select(PostureSnapshot)
                .where(PostureSnapshot.endpoint_id.in_(endpoint_ids))
                .order_by(PostureSnapshot.observed_at.asc(), PostureSnapshot.snapshot_id.asc())
            ).all()
            if endpoint_ids
            else []
        )
        snapshot_ids = [snapshot.snapshot_id for snapshot in posture_snapshots]
        posture_results = (
            session.scalars(
                select(PostureResult)
                .where(PostureResult.snapshot_id.in_(snapshot_ids))
                .order_by(
                    PostureResult.snapshot_id.asc(),
                    PostureResult.control_key.asc(),
                )
            ).all()
            if snapshot_ids
            else []
        )

        results_by_snapshot: dict[str, list[PostureResult]] = defaultdict(list)
        for result in posture_results:
            results_by_snapshot[result.snapshot_id].append(result)
        source_catalog = load_source_catalog().model_dump(mode="json")
        record_audit_event(
            session,
            event_type="compliance_evidence_exported",
            principal=principal,
            client_id=normalized_client_id,
            location_id=normalized_location_id,
            target_type="compliance_evidence",
            metadata={"endpoint_count": len(endpoints)},
            created_at=now_str,
        )
        session.commit()

    return {
        "exported_at": now_str,
        "source_catalog": source_catalog,
        "endpoints": endpoint_payloads,
        "posture_snapshots": [
            {
                "snapshot_id": snapshot.snapshot_id,
                "endpoint_id": snapshot.endpoint_id,
                "observed_at": snapshot.observed_at,
                "platform_profile": snapshot.platform_profile,
                "created_at": snapshot.created_at,
                "results": [_posture_result_payload(result) for result in results_by_snapshot[snapshot.snapshot_id]],
            }
            for snapshot in posture_snapshots
        ],
        "approval_requests": [
            _approval_request_payload(request, events_by_request.get(request.approval_request_id, []))
            for request in approval_requests
        ],
        "approval_grants": [_approval_grant_payload(grant) for grant in approval_grants],
        "response_actions": [_response_action_payload(action) for action in response_actions],
    }
