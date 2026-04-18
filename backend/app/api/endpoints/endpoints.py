from __future__ import annotations

from fastapi import APIRouter, Depends, Response, HTTPException, status
from sqlalchemy import select

from app.db import DatabaseStore, get_store
from app.models import Endpoint
from app.schemas.contracts import EndpointEnrollRequest, EndpointResponse
from app.utils import (
    generate_prefixed_id,
    normalize_agent_fingerprint,
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
                    last_seen_at=now,
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
