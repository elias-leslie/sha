from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EndpointStatus(str, Enum):
    pending = "pending"
    active = "active"
    stale = "stale"


class EndpointPlatform(str, Enum):
    windows = "windows"
    linux = "linux"


class PostureStatus(str, Enum):
    pass_ = "pass"
    fail = "fail"
    warn = "warn"
    error = "error"
    not_applicable = "not_applicable"


class InstallerChannel(str, Enum):
    stable = "stable"
    preview = "preview"


class InstallerPolicyMode(str, Enum):
    observe = "observe"
    safe_auto = "safe_auto"
    approval_required = "approval_required"


class ApprovalAction(str, Enum):
    collect_security_context = "collect_security_context"
    collect_remediation_evidence = "collect_remediation_evidence"
    inspect_control = "inspect_control"
    apply_control = "apply_control"
    rollback_control = "rollback_control"
    request_elevated_troubleshooting = "request_elevated_troubleshooting"


class ApprovalRequestKind(str, Enum):
    hardening_change = "hardening_change"
    elevated_troubleshooting = "elevated_troubleshooting"


class ApprovalRisk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class TroubleshootingScope(str, Enum):
    service_status = "service_status"
    security_logs = "security_logs"
    firewall_state = "firewall_state"
    identity_state = "identity_state"
    process_inventory = "process_inventory"
    network_bindings = "network_bindings"


class ApprovalGrantStatus(str, Enum):
    approved = "approved"
    expired = "expired"
    revoked = "revoked"


class ApprovalRequestStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"
    revoked = "revoked"


class ApprovalDecision(str, Enum):
    approve = "approve"
    deny = "deny"
    revoke = "revoke"


class EndpointEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_fingerprint: str
    hostname: str
    platform: EndpointPlatform
    platform_version: str | None = None
    agent_version: str
    tenant_id: str | None = None
    site_id: str | None = None


class EndpointResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_id: str
    agent_fingerprint: str
    hostname: str
    platform: EndpointPlatform
    platform_version: str | None = None
    agent_version: str
    tenant_id: str | None = None
    site_id: str | None = None
    status: EndpointStatus
    last_seen_at: str
    created_at: str
    updated_at: str


class PostureResultInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    control_key: str
    status: PostureStatus
    current_value: str | None = None
    recommended_value: str | None = None
    severity: str | None = None
    evidence_summary: str
    reboot_required: bool


class PostureSnapshotCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_id: str
    observed_at: datetime
    platform_profile: str
    results: list[PostureResultInput] = Field(min_length=1)


class PostureSnapshotAck(BaseModel):
    model_config = ConfigDict(extra="ignore")

    snapshot_id: str
    endpoint_id: str
    observed_at: str
    accepted_result_count: int
    created_at: str


class InstallerProfileCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    platform: EndpointPlatform
    channel: InstallerChannel
    control_plane_url: str
    policy_mode: InstallerPolicyMode
    tenant_id: str | None = None
    site_id: str | None = None


class InstallerProfileResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    platform: EndpointPlatform
    channel: InstallerChannel
    control_plane_url: str
    policy_mode: InstallerPolicyMode
    tenant_id: str | None = None
    site_id: str | None = None
    created_at: str
    updated_at: str


class InstallerProfileListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[InstallerProfileResponse]


class ApprovalAuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approval_event_id: str
    event_type: str
    actor: str
    comment: str
    created_at: str


class ApprovalRequestCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_ids: list[str] = Field(min_length=1)
    request_kind: ApprovalRequestKind
    requested_actions: list[ApprovalAction] = Field(min_length=1)
    control_ids: list[str] = Field(default_factory=list)
    troubleshooting_scopes: list[TroubleshootingScope] = Field(default_factory=list)
    requested_ttl_minutes: int
    requested_by: str
    reason: str
    risk: ApprovalRisk


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    decision: ApprovalDecision
    decided_by: str
    decision_comment: str
    expires_at: datetime | None = None


class ApprovalRequestResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approval_request_id: str
    endpoint_ids: list[str]
    request_kind: ApprovalRequestKind
    requested_actions: list[ApprovalAction]
    control_ids: list[str]
    troubleshooting_scopes: list[TroubleshootingScope]
    requested_ttl_minutes: int
    requested_by: str
    reason: str
    risk: ApprovalRisk
    status: ApprovalRequestStatus
    decision_by: str | None = None
    decision_comment: str | None = None
    decision_at: str | None = None
    approval_grant_id: str | None = None
    created_at: str
    updated_at: str
    audit_events: list[ApprovalAuditEventResponse]


class ApprovalRequestListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[ApprovalRequestResponse]


class ApprovalGrantCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_ids: list[str] = Field(min_length=1)
    allowed_actions: list[ApprovalAction] = Field(min_length=1)
    control_ids: list[str] = Field(default_factory=list)
    troubleshooting_scopes: list[TroubleshootingScope] = Field(default_factory=list)
    requested_by: str
    approved_by: str
    reason: str
    expires_at: datetime


class ApprovalGrantResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approval_grant_id: str
    approval_request_id: str | None = None
    endpoint_ids: list[str]
    allowed_actions: list[ApprovalAction]
    control_ids: list[str]
    troubleshooting_scopes: list[TroubleshootingScope]
    requested_by: str
    approved_by: str
    reason: str
    expires_at: str
    status: ApprovalGrantStatus
    created_at: str
    updated_at: str


class ApprovalGrantListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[ApprovalGrantResponse]
