from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from app.schemas.contracts import (
    ApprovalDecisionRequest,
    ApprovalGrantCreateRequest,
    ApprovalGrantListResponse,
    ApprovalGrantResponse,
    ApprovalRequestCreateRequest,
    ApprovalRequestListResponse,
    ApprovalRequestResponse,
    EndpointDetailResponse,
    EndpointEnrollRequest,
    EndpointHeartbeatAck,
    EndpointHeartbeatRequest,
    EndpointInventoryListResponse,
    EndpointResponse,
    InstallerProfileCreateRequest,
    InstallerProfileListResponse,
    InstallerProfileResponse,
    PostureSnapshotAck,
    PostureSnapshotCreateRequest,
)


def shared_contract_models() -> tuple[tuple[str, type[BaseModel]], ...]:
    return (
        ("endpoint-enroll-request.schema.json", EndpointEnrollRequest),
        ("endpoint-response.schema.json", EndpointResponse),
        ("endpoint-heartbeat-request.schema.json", EndpointHeartbeatRequest),
        ("endpoint-heartbeat-ack.schema.json", EndpointHeartbeatAck),
        ("endpoint-inventory-list-response.schema.json", EndpointInventoryListResponse),
        ("endpoint-detail-response.schema.json", EndpointDetailResponse),
        ("posture-snapshot-create-request.schema.json", PostureSnapshotCreateRequest),
        ("posture-snapshot-ack.schema.json", PostureSnapshotAck),
        ("installer-profile-create-request.schema.json", InstallerProfileCreateRequest),
        ("installer-profile-response.schema.json", InstallerProfileResponse),
        ("installer-profile-list-response.schema.json", InstallerProfileListResponse),
        ("approval-request-create-request.schema.json", ApprovalRequestCreateRequest),
        ("approval-decision-request.schema.json", ApprovalDecisionRequest),
        ("approval-request-response.schema.json", ApprovalRequestResponse),
        ("approval-request-list-response.schema.json", ApprovalRequestListResponse),
        ("approval-grant-create-request.schema.json", ApprovalGrantCreateRequest),
        ("approval-grant-response.schema.json", ApprovalGrantResponse),
        ("approval-grant-list-response.schema.json", ApprovalGrantListResponse),
    )


def test_shared_schema_exports_are_checked_in_and_match_contract_models():
    repo_root = Path(__file__).resolve().parents[2]
    output_dir = repo_root / "schemas" / "generated"

    for filename, model in shared_contract_models():
        path = output_dir / filename
        assert path.exists(), (
            f"missing shared schema export {path.relative_to(repo_root)}; "
            "run `uv run python backend/scripts/export_contract_schemas.py`"
        )
        assert json.loads(path.read_text()) == model.model_json_schema(ref_template="#/$defs/{model}")
