from __future__ import annotations

import json
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import DatabaseStore, get_store
from app.models import ApprovalGrant, Endpoint, PostureResult, PostureSnapshot, ResponseAction
from app.schemas.contracts import (
    EndpointDetailResponse,
    EndpointEnrollRequest,
    EndpointHeartbeatAck,
    EndpointHeartbeatRequest,
    EndpointInventoryListResponse,
    EndpointResponse,
)
from app.utils import (
    generate_prefixed_id,
    has_duplicates,
    normalize_agent_capability,
    normalize_agent_fingerprint,
    normalize_connectivity_status,
    normalize_optional_string,
    normalize_platform,
    normalize_required_string,
    to_utc_z,
    utc_now,
)

router = APIRouter(prefix="/api/endpoints", tags=["endpoints"])


def _endpoint_payload(endpoint: Endpoint) -> dict[str, object]:
    return {
        "endpoint_id": endpoint.endpoint_id,
        "agent_fingerprint": endpoint.agent_fingerprint,
        "hostname": endpoint.hostname,
        "platform": endpoint.platform,
        "platform_version": endpoint.platform_version,
        "agent_version": endpoint.agent_version,
        "tenant_id": endpoint.tenant_id,
        "site_id": endpoint.site_id,
        "status": endpoint.status,
        "last_seen_at": endpoint.last_seen_at,
        "created_at": endpoint.created_at,
        "updated_at": endpoint.updated_at,
    }


def _parse_declared_capabilities(endpoint: Endpoint) -> list[str]:
    if not endpoint.declared_capabilities_json:
        return []
    value = json.loads(endpoint.declared_capabilities_json)
    return value if isinstance(value, list) else []


def _parse_execution_hooks(endpoint: Endpoint) -> dict[str, bool] | None:
    if not endpoint.execution_hooks_json:
        return None
    value = json.loads(endpoint.execution_hooks_json)
    return value if isinstance(value, dict) else None


def _latest_posture(session: Session, endpoint_id: str) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    snapshot = session.scalar(
        select(PostureSnapshot)
        .where(PostureSnapshot.endpoint_id == endpoint_id)
        .order_by(PostureSnapshot.observed_at.desc(), PostureSnapshot.snapshot_id.desc())
    )
    if snapshot is None:
        return None, []

    results = session.scalars(
        select(PostureResult)
        .where(PostureResult.snapshot_id == snapshot.snapshot_id)
        .order_by(PostureResult.control_key.asc())
    ).all()
    counts = Counter(result.status for result in results)
    summary: dict[str, object] = {
        "snapshot_id": snapshot.snapshot_id,
        "observed_at": snapshot.observed_at,
        "platform_profile": snapshot.platform_profile,
        "pass_count": counts.get("pass", 0),
        "fail_count": counts.get("fail", 0),
        "warn_count": counts.get("warn", 0),
        "error_count": counts.get("error", 0),
        "not_applicable_count": counts.get("not_applicable", 0),
        "reboot_required_count": sum(1 for result in results if result.reboot_required),
    }
    result_payloads: list[dict[str, object]] = [
        {
            "control_key": result.control_key,
            "status": result.status,
            "current_value": result.current_value,
            "recommended_value": result.recommended_value,
            "severity": result.severity,
            "evidence_summary": result.evidence_summary,
            "reboot_required": result.reboot_required,
        }
        for result in results
    ]
    return summary, result_payloads


def _endpoint_inventory_payload(
    session: Session,
    endpoint: Endpoint,
    *,
    include_results: bool = False,
) -> dict[str, object]:
    latest_posture_summary, latest_results = _latest_posture(session, endpoint.endpoint_id)
    payload: dict[str, object] = {
        "endpoint_id": endpoint.endpoint_id,
        "hostname": endpoint.hostname,
        "platform": endpoint.platform,
        "platform_version": endpoint.platform_version,
        "agent_version": endpoint.agent_version,
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
        "latest_posture_summary": latest_posture_summary,
    }
    if include_results:
        payload["latest_results"] = latest_results
    return payload


def _normalize_declared_capabilities(raw_capabilities: list[str]) -> list[str]:
    capabilities = [normalize_agent_capability(capability) for capability in raw_capabilities]
    if has_duplicates(capabilities):
        raise HTTPException(status_code=422, detail="duplicate declared_capabilities are not allowed")
    return sorted(capabilities)


@router.post(
    "/enroll",
    response_model=EndpointResponse,
    responses={201: {"model": EndpointResponse}},
)
def enroll_endpoint(
    payload: EndpointEnrollRequest,
    response: Response,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    agent_fingerprint = normalize_agent_fingerprint(payload.agent_fingerprint)
    hostname = normalize_required_string(payload.hostname, "hostname")
    platform = normalize_platform(payload.platform.value)
    agent_version = normalize_required_string(payload.agent_version, "agent_version")
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            existing = session.scalar(select(Endpoint).where(Endpoint.agent_fingerprint == agent_fingerprint))
            if existing is None:
                endpoint = Endpoint(
                    endpoint_id=generate_prefixed_id("ep"),
                    agent_fingerprint=agent_fingerprint,
                    hostname=hostname,
                    platform=platform,
                    platform_version=(
                        normalize_optional_string(payload.platform_version, "platform_version")
                        if payload.platform_version is not None
                        else None
                    ),
                    platform_profile=None,
                    agent_version=agent_version,
                    tenant_id=(
                        normalize_optional_string(payload.tenant_id, "tenant_id")
                        if payload.tenant_id is not None
                        else None
                    ),
                    site_id=(
                        normalize_optional_string(payload.site_id, "site_id")
                        if payload.site_id is not None
                        else None
                    ),
                    status="active",
                    connectivity_status=None,
                    declared_capabilities_json=None,
                    execution_hooks_json=None,
                    last_seen_at=now,
                    last_heartbeat_at=None,
                    created_at=now,
                    updated_at=now,
                )
                session.add(endpoint)
                session.flush()
                response.status_code = status.HTTP_201_CREATED
                return _endpoint_payload(endpoint)

            if existing.platform != platform:
                raise HTTPException(
                    status_code=409,
                    detail="agent fingerprint already enrolled for a different platform",
                )

            existing.hostname = hostname
            existing.platform = platform
            existing.agent_version = agent_version
            existing.status = "active"
            existing.last_seen_at = now
            existing.updated_at = now

            if "platform_version" in payload.model_fields_set:
                if payload.platform_version is None:
                    existing.platform_version = None
                else:
                    existing.platform_version = normalize_optional_string(payload.platform_version, "platform_version")
            if "tenant_id" in payload.model_fields_set:
                if payload.tenant_id is None:
                    existing.tenant_id = None
                else:
                    existing.tenant_id = normalize_optional_string(payload.tenant_id, "tenant_id")
            if "site_id" in payload.model_fields_set:
                if payload.site_id is None:
                    existing.site_id = None
                else:
                    existing.site_id = normalize_optional_string(payload.site_id, "site_id")

            session.flush()
            response.status_code = status.HTTP_200_OK
            return _endpoint_payload(existing)


@router.post("/{endpoint_id}/heartbeat", status_code=status.HTTP_202_ACCEPTED, response_model=EndpointHeartbeatAck)
def heartbeat_endpoint(
    endpoint_id: str,
    payload: EndpointHeartbeatRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    normalized_endpoint_id = normalize_required_string(endpoint_id, "endpoint_id")
    agent_version = normalize_required_string(payload.agent_version, "agent_version")
    platform_profile = normalize_required_string(payload.platform_profile, "platform_profile")
    connectivity_status = normalize_connectivity_status(payload.connectivity_status.value)
    declared_capabilities = _normalize_declared_capabilities([capability.value for capability in payload.declared_capabilities])
    execution_hooks = payload.execution_hooks.model_dump(mode="json")
    now = to_utc_z(utc_now())

    with store.session() as session:
        with session.begin():
            endpoint = session.get(Endpoint, normalized_endpoint_id)
            if endpoint is None:
                raise HTTPException(status_code=404, detail="endpoint not found")

            endpoint.agent_version = agent_version
            endpoint.platform_profile = platform_profile
            endpoint.connectivity_status = connectivity_status
            endpoint.declared_capabilities_json = json.dumps(declared_capabilities, separators=(",", ":"))
            endpoint.execution_hooks_json = json.dumps(execution_hooks, separators=(",", ":"), sort_keys=True)
            endpoint.last_seen_at = now
            endpoint.last_heartbeat_at = now
            endpoint.updated_at = now
            endpoint.status = "active"

            if "platform_version" in payload.model_fields_set:
                if payload.platform_version is None:
                    endpoint.platform_version = None
                else:
                    endpoint.platform_version = normalize_optional_string(payload.platform_version, "platform_version")

            session.flush()
            pending_action_count = int(
                session.scalar(
                    select(func.count())
                    .select_from(ResponseAction)
                    .join(ApprovalGrant, ApprovalGrant.approval_grant_id == ResponseAction.approval_grant_id)
                    .where(
                        ResponseAction.endpoint_id == endpoint.endpoint_id,
                        ResponseAction.status == "queued",
                        ApprovalGrant.status == "approved",
                        ApprovalGrant.expires_at > now,
                    )
                )
                or 0
            )
            return {
                "endpoint_id": endpoint.endpoint_id,
                "status": endpoint.status,
                "connectivity_status": endpoint.connectivity_status,
                "last_seen_at": endpoint.last_seen_at,
                "last_heartbeat_at": endpoint.last_heartbeat_at,
                "accepted_capability_count": len(declared_capabilities),
                "pending_action_count": pending_action_count,
                "created_at": endpoint.created_at,
                "updated_at": endpoint.updated_at,
            }


@router.get("", response_model=EndpointInventoryListResponse)
def list_endpoints(store: DatabaseStore = Depends(get_store)) -> dict[str, list[dict[str, object]]]:
    with store.session() as session:
        endpoints = session.scalars(
            select(Endpoint).order_by(Endpoint.created_at.asc(), Endpoint.endpoint_id.asc())
        ).all()
        return {"items": [_endpoint_inventory_payload(session, endpoint) for endpoint in endpoints]}


@router.get("/{endpoint_id}", response_model=EndpointDetailResponse)
def get_endpoint_detail(endpoint_id: str, store: DatabaseStore = Depends(get_store)) -> dict[str, object]:
    normalized_endpoint_id = normalize_required_string(endpoint_id, "endpoint_id")
    with store.session() as session:
        endpoint = session.get(Endpoint, normalized_endpoint_id)
        if endpoint is None:
            raise HTTPException(status_code=404, detail="endpoint not found")
        return _endpoint_inventory_payload(session, endpoint, include_results=True)
