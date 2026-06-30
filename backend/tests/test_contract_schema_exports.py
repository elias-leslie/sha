from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from app.schemas.contracts import (
    AgentCapability,
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
    ResponseActionCreateRequest,
    ResponseActionListResponse,
    ResponseActionResponse,
    ResponseActionResultRequest,
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
        ("response-action-create-request.schema.json", ResponseActionCreateRequest),
        ("response-action-result-request.schema.json", ResponseActionResultRequest),
        ("response-action-response.schema.json", ResponseActionResponse),
        ("response-action-list-response.schema.json", ResponseActionListResponse),
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


def test_endpoint_heartbeat_request_schema_exports_agent_capability_enum():
    schema = EndpointHeartbeatRequest.model_json_schema(ref_template="#/$defs/{model}")
    declared_capabilities = schema["properties"]["declared_capabilities"]

    assert declared_capabilities["items"] == {"$ref": "#/$defs/AgentCapability"}
    assert schema["$defs"]["AgentCapability"]["enum"] == [capability.value for capability in AgentCapability]


def test_shared_schema_manifest_matches_contract_models():
    repo_root = Path(__file__).resolve().parents[2]
    output_dir = repo_root / "schemas" / "generated"
    manifest_path = output_dir / "manifest.json"

    assert manifest_path.exists(), (
        f"missing shared schema manifest {manifest_path.relative_to(repo_root)}; "
        "run `uv run python backend/scripts/export_contract_schemas.py`"
    )

    expected_manifest = {
        "schema_version": 1,
        "source_module": "app.schemas.contracts",
        "files": [
            {"filename": filename, "model": model.__name__}
            for filename, model in shared_contract_models()
        ],
    }

    assert json.loads(manifest_path.read_text()) == expected_manifest


def test_endpoint_response_models_require_explicit_nullable_keys():
    endpoint_response_schema = EndpointResponse.model_json_schema(ref_template="#/$defs/{model}")
    endpoint_inventory_schema = EndpointInventoryListResponse.model_json_schema(ref_template="#/$defs/{model}")
    endpoint_detail_schema = EndpointDetailResponse.model_json_schema(ref_template="#/$defs/{model}")
    installer_profile_schema = InstallerProfileResponse.model_json_schema(ref_template="#/$defs/{model}")

    for required_field in ("platform_version", "tenant_id", "site_id"):
        assert required_field in endpoint_response_schema["required"]

    inventory_item_required = endpoint_inventory_schema["$defs"]["EndpointInventoryItemResponse"]["required"]
    for required_field in (
        "platform_version",
        "tenant_id",
        "site_id",
        "connectivity_status",
        "last_heartbeat_at",
        "last_platform_profile",
        "execution_hooks",
        "latest_posture_summary",
    ):
        assert required_field in inventory_item_required

    for required_field in (
        "platform_version",
        "tenant_id",
        "site_id",
        "connectivity_status",
        "last_heartbeat_at",
        "last_platform_profile",
        "execution_hooks",
        "latest_posture_summary",
        "latest_results",
    ):
        assert required_field in endpoint_detail_schema["required"]

    for required_field in ("tenant_id", "site_id"):
        assert required_field in installer_profile_schema["required"]
