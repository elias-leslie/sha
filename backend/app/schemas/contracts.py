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
    inspect_control = "inspect_control"
    apply_control = "apply_control"
    rollback_control = "rollback_control"
    request_elevated_troubleshooting = "request_elevated_troubleshooting"


class ApprovalGrantStatus(str, Enum):
    approved = "approved"
    expired = "expired"
    revoked = "revoked"


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


class ApprovalGrantCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_ids: list[str] = Field(min_length=1)
    allowed_actions: list[ApprovalAction] = Field(min_length=1)
    requested_by: str
    approved_by: str
    reason: str
    expires_at: datetime


class ApprovalGrantResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approval_grant_id: str
    endpoint_ids: list[str]
    allowed_actions: list[ApprovalAction]
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
