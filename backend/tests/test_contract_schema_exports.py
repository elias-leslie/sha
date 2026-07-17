from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from app.schemas.contracts import (
    AgentMeResponse,
    AgentCapability,
    AuthSessionResponse,
    AuditEventListResponse,
    ApprovalDecisionRequest,
    ApprovalGrantCreateRequest,
    ApprovalGrantListResponse,
    ApprovalGrantResponse,
    ApprovalRequestCreateRequest,
    ApprovalRequestListResponse,
    ApprovalRequestResponse,
    ClientCreateRequest,
    ClientListResponse,
    ClientResponse,
    ControlRegistryResponse,
    DeviceCredentialMaterialRequest,
    DeviceCredentialResponse,
    DynamicGroupCreateRequest,
    DynamicGroupListResponse,
    DynamicGroupPreviewResponse,
    DynamicGroupResponse,
    EndpointDetailResponse,
    EndpointEnrollRequest,
    EndpointHeartbeatAck,
    EndpointHeartbeatRequest,
    EndpointInventoryListResponse,
    EndpointResponse,
    EndpointTagAssignmentRequest,
    EndpointTagListResponse,
    EnrollmentExchangeRequest,
    EnrollmentExchangeResponse,
    EnrollmentTokenCreateRequest,
    EnrollmentTokenCreateResponse,
    EnrollmentTokenListResponse,
    EnrollmentTokenResponse,
    InstallerProfileCreateRequest,
    InstallerProfileListResponse,
    InstallerProfileResponse,
    LocationCreateRequest,
    LocationListResponse,
    LocationResponse,
    PostureSnapshotAck,
    PostureSnapshotCreateRequest,
    ResponseActionCreateRequest,
    ResponseActionClaimResponse,
    ResponseActionListResponse,
    ResponseActionResponse,
    ResponseActionResultRequest,
    RoleBindingCreateRequest,
    SavedViewCreateRequest,
    SavedViewListResponse,
    SavedViewResponse,
    SavedViewUpdateRequest,
    TagCreateRequest,
    TagListResponse,
    TagResponse,
    UserStatusUpdateRequest,
)


def shared_contract_models() -> tuple[tuple[str, type[BaseModel]], ...]:
    return (
        ("endpoint-enroll-request.schema.json", EndpointEnrollRequest),
        ("endpoint-response.schema.json", EndpointResponse),
        ("enrollment-token-create-request.schema.json", EnrollmentTokenCreateRequest),
        ("enrollment-token-create-response.schema.json", EnrollmentTokenCreateResponse),
        ("enrollment-token-response.schema.json", EnrollmentTokenResponse),
        ("enrollment-token-list-response.schema.json", EnrollmentTokenListResponse),
        ("enrollment-exchange-request.schema.json", EnrollmentExchangeRequest),
        ("enrollment-exchange-response.schema.json", EnrollmentExchangeResponse),
        ("device-credential-material-request.schema.json", DeviceCredentialMaterialRequest),
        ("device-credential-response.schema.json", DeviceCredentialResponse),
        ("agent-me-response.schema.json", AgentMeResponse),
        ("auth-session-response.schema.json", AuthSessionResponse),
        ("audit-event-list-response.schema.json", AuditEventListResponse),
        ("user-status-update-request.schema.json", UserStatusUpdateRequest),
        ("role-binding-create-request.schema.json", RoleBindingCreateRequest),
        ("endpoint-heartbeat-request.schema.json", EndpointHeartbeatRequest),
        ("endpoint-heartbeat-ack.schema.json", EndpointHeartbeatAck),
        ("endpoint-inventory-list-response.schema.json", EndpointInventoryListResponse),
        ("endpoint-detail-response.schema.json", EndpointDetailResponse),
        ("client-create-request.schema.json", ClientCreateRequest),
        ("client-response.schema.json", ClientResponse),
        ("client-list-response.schema.json", ClientListResponse),
        ("location-create-request.schema.json", LocationCreateRequest),
        ("location-response.schema.json", LocationResponse),
        ("location-list-response.schema.json", LocationListResponse),
        ("tag-create-request.schema.json", TagCreateRequest),
        ("tag-response.schema.json", TagResponse),
        ("tag-list-response.schema.json", TagListResponse),
        ("endpoint-tag-assignment-request.schema.json", EndpointTagAssignmentRequest),
        ("endpoint-tag-list-response.schema.json", EndpointTagListResponse),
        ("saved-view-create-request.schema.json", SavedViewCreateRequest),
        ("saved-view-update-request.schema.json", SavedViewUpdateRequest),
        ("saved-view-response.schema.json", SavedViewResponse),
        ("saved-view-list-response.schema.json", SavedViewListResponse),
        ("dynamic-group-create-request.schema.json", DynamicGroupCreateRequest),
        ("dynamic-group-response.schema.json", DynamicGroupResponse),
        ("dynamic-group-list-response.schema.json", DynamicGroupListResponse),
        ("dynamic-group-preview-response.schema.json", DynamicGroupPreviewResponse),
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
        ("control-registry-response.schema.json", ControlRegistryResponse),
        ("response-action-create-request.schema.json", ResponseActionCreateRequest),
        ("response-action-result-request.schema.json", ResponseActionResultRequest),
        ("response-action-response.schema.json", ResponseActionResponse),
        ("response-action-list-response.schema.json", ResponseActionListResponse),
        ("response-action-claim-response.schema.json", ResponseActionClaimResponse),
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


def test_endpoint_heartbeat_request_schema_exports_typed_agent_capabilities():
    schema = EndpointHeartbeatRequest.model_json_schema(ref_template="#/$defs/{model}")
    declared_capabilities = schema["properties"]["declared_capabilities"]

    assert declared_capabilities["items"]["anyOf"] == [
        {"$ref": "#/$defs/AgentCapability"},
        {
            "pattern": r"^(?:apply_control|rollback_control):[a-z0-9]+(?:[.-][a-z0-9]+)+$",
            "type": "string",
        },
    ]
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

    for required_field in (
        "platform_version",
        "protocol_version",
        "architecture",
        "installation_id",
        "credential_mode",
        "enrollment_token_id",
        "client_id",
        "location_id",
        "tenant_id",
        "site_id",
    ):
        assert required_field in endpoint_response_schema["required"]

    inventory_item_required = endpoint_inventory_schema["$defs"]["EndpointInventoryItemResponse"]["required"]
    for required_field in (
        "platform_version",
        "protocol_version",
        "architecture",
        "installation_id",
        "credential_mode",
        "enrollment_token_id",
        "client_id",
        "location_id",
        "tenant_id",
        "site_id",
        "connectivity_status",
        "last_heartbeat_at",
        "last_platform_profile",
        "execution_hooks",
        "latest_posture_summary",
        "active_credential",
    ):
        assert required_field in inventory_item_required

    for required_field in (
        "platform_version",
        "client_id",
        "location_id",
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

    for required_field in ("client_id", "location_id", "tenant_id", "site_id"):
        assert required_field in installer_profile_schema["required"]


def test_device_bootstrap_schema_requires_capability_identity_and_marks_secrets_write_only():
    exchange_schema = EnrollmentExchangeRequest.model_json_schema(ref_template="#/$defs/{model}")
    assert {"protocol_version", "architecture", "credential_id", "credential_secret"} <= set(
        exchange_schema["required"]
    )
    assert exchange_schema["properties"]["credential_secret"]["writeOnly"] is True

    token_schema = EnrollmentTokenCreateResponse.model_json_schema(ref_template="#/$defs/{model}")
    assert token_schema["properties"]["token"]["writeOnly"] is True


def test_response_action_claim_schema_requires_one_time_lease_token():
    schema = ResponseActionClaimResponse.model_json_schema(ref_template="#/$defs/{model}")

    claim_item = schema["$defs"]["ResponseActionClaimItem"]
    assert "lease_token" in claim_item["required"]
    assert claim_item["properties"]["lease_token"] == {"title": "Lease Token", "type": "string"}
