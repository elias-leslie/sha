from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.db import DatabaseStore, get_store
from app.models import Endpoint, PostureResult, PostureSnapshot
from app.schemas.contracts import PostureSnapshotAck, PostureSnapshotCreateRequest
from app.utils import (
    generate_prefixed_id,
    normalize_control_key,
    normalize_optional_string,
    normalize_platform,
    normalize_posture_status,
    normalize_required_string,
    to_utc_z,
    utc_now,
)

router = APIRouter(prefix="/api/posture-snapshots", tags=["posture-snapshots"])


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=PostureSnapshotAck)
def create_posture_snapshot(
    payload: PostureSnapshotCreateRequest,
    store: DatabaseStore = Depends(get_store),
) -> dict[str, object]:
    endpoint_id = normalize_required_string(payload.endpoint_id, "endpoint_id")
    platform_profile = normalize_required_string(payload.platform_profile, "platform_profile")
    observed_at = to_utc_z(payload.observed_at)

    with store.session() as session:
        with session.begin():
            endpoint = session.get(Endpoint, endpoint_id)
            if endpoint is None:
                raise HTTPException(status_code=404, detail="endpoint not found")

            if not payload.results:
                raise HTTPException(status_code=422, detail="results must not be empty")

            normalized_results: list[dict[str, object]] = []
            seen_control_keys: set[str] = set()
            for result in payload.results:
                control_key, control_key_normalized = normalize_control_key(result.control_key)
                if control_key_normalized in seen_control_keys:
                    raise HTTPException(
                        status_code=422,
                        detail="duplicate control_key values are not allowed",
                    )
                seen_control_keys.add(control_key_normalized)

                normalized_results.append(
                    {
                        "control_key": control_key,
                        "control_key_normalized": control_key_normalized,
                        "status": normalize_posture_status(result.status.value),
                        "current_value": (
                            normalize_optional_string(result.current_value, "current_value")
                            if result.current_value is not None
                            else None
                        ),
                        "recommended_value": (
                            normalize_optional_string(result.recommended_value, "recommended_value")
                            if result.recommended_value is not None
                            else None
                        ),
                        "severity": (
                            normalize_optional_string(result.severity, "severity")
                            if result.severity is not None
                            else None
                        ),
                        "evidence_summary": normalize_required_string(
                            result.evidence_summary,
                            "evidence_summary",
                        ),
                        "reboot_required": result.reboot_required,
                    }
                )

            created_at = to_utc_z(utc_now())
            snapshot = PostureSnapshot(
                snapshot_id=generate_prefixed_id("snap"),
                endpoint_id=endpoint_id,
                observed_at=observed_at,
                platform_profile=platform_profile,
                created_at=created_at,
            )
            session.add(snapshot)
            session.flush()

            for result in normalized_results:
                session.add(
                    PostureResult(
                        result_id=generate_prefixed_id("res"),
                        snapshot_id=snapshot.snapshot_id,
                        endpoint_id=endpoint_id,
                        control_key=result["control_key"],
                        control_key_normalized=result["control_key_normalized"],
                        status=result["status"],
                        current_value=result["current_value"],
                        recommended_value=result["recommended_value"],
                        severity=result["severity"],
                        evidence_summary=result["evidence_summary"],
                        reboot_required=result["reboot_required"],
                        created_at=created_at,
                    )
                )

            session.flush()
            return {
                "snapshot_id": snapshot.snapshot_id,
                "endpoint_id": endpoint_id,
                "observed_at": observed_at,
                "accepted_result_count": len(normalized_results),
                "created_at": created_at,
            }
