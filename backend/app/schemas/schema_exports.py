from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from app.schemas.contracts import (
    AgentMeResponse,
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

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_OUTPUT_DIR = REPO_ROOT / "schemas" / "generated"
MANIFEST_FILENAME = "manifest.json"


def exported_contract_models() -> tuple[tuple[str, type[BaseModel]], ...]:
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


def build_exported_schema_documents() -> dict[str, dict[str, object]]:
    return {
        filename: model.model_json_schema(ref_template="#/$defs/{model}")
        for filename, model in exported_contract_models()
    }


def build_schema_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_module": "app.schemas.contracts",
        "files": [
            {
                "filename": filename,
                "model": model.__name__,
            }
            for filename, model in exported_contract_models()
        ],
    }


def write_exported_schema_documents(output_dir: Path | None = None) -> list[Path]:
    target_dir = output_dir or SCHEMA_OUTPUT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    written_paths: list[Path] = []
    for filename, schema in build_exported_schema_documents().items():
        path = target_dir / filename
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
        written_paths.append(path)

    manifest_path = target_dir / MANIFEST_FILENAME
    manifest_path.write_text(json.dumps(build_schema_manifest(), indent=2, sort_keys=True) + "\n")
    written_paths.append(manifest_path)
    return written_paths
