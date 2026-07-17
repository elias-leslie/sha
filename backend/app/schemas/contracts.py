from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.device_identity import (
    is_canonical_credential_id,
    is_canonical_installation_id,
    is_canonical_secret,
)


class EndpointStatus(str, Enum):
    pending = "pending"
    active = "active"
    stale = "stale"


class EndpointPlatform(str, Enum):
    windows = "windows"
    linux = "linux"
    macos = "macos"


class ConnectivityStatus(str, Enum):
    online = "online"
    degraded = "degraded"


class HierarchyState(str, Enum):
    active = "active"
    archived = "archived"
    migration_quarantine = "migration_quarantine"


class AuthorizationScopeType(str, Enum):
    global_ = "global"
    client = "client"
    location = "location"


class AuthUserStatus(str, Enum):
    pending = "pending"
    active = "active"
    disabled = "disabled"


class ApprovalScopeState(str, Enum):
    active = "active"
    migration_quarantine = "migration_quarantine"


class EndpointCredentialMode(str, Enum):
    legacy_shared = "legacy_shared"
    device = "device"


class EndpointAgentMigrationState(str, Enum):
    canonical = "canonical"
    legacy_reporter = "legacy_reporter"


class EnrollmentApprovalPolicy(str, Enum):
    pending = "pending"
    approved = "approved"


class EnrollmentTokenState(str, Enum):
    active = "active"
    expired = "expired"
    exhausted = "exhausted"
    revoked = "revoked"


class DeviceCredentialStatus(str, Enum):
    active = "active"
    replaced = "replaced"
    revoked = "revoked"


class AgentCapability(str, Enum):
    enroll = "enroll"
    heartbeat = "heartbeat"
    collect_posture_snapshot = "collect_posture_snapshot"
    inspect_control = "inspect_control"
    apply_control = "apply_control"
    rollback_control = "rollback_control"
    collect_security_context = "collect_security_context"
    collect_remediation_evidence = "collect_remediation_evidence"
    request_elevated_troubleshooting = "request_elevated_troubleshooting"


ControlActionCapability = Annotated[
    str,
    StringConstraints(pattern=r"^(?:apply_control|rollback_control):[a-z0-9]+(?:[.-][a-z0-9]+)+$"),
]
DeclaredAgentCapability = AgentCapability | ControlActionCapability
ProtocolVersion = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$",
    ),
]
AgentArchitecture = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$",
    ),
]
AgentCapabilityVersion = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$",
    ),
]


class AgentCapabilityKind(str, Enum):
    core = "core"
    collector = "collector"
    action = "action"


class AgentPrivilegeContext(str, Enum):
    elevated = "elevated"
    user = "user"
    unknown = "unknown"


class AgentServiceContext(str, Enum):
    system_service = "system_service"
    interactive = "interactive"
    unknown = "unknown"


class AgentHealthState(str, Enum):
    healthy = "healthy"
    degraded = "degraded"


class AgentCapabilityDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: DeclaredAgentCapability
    kind: AgentCapabilityKind
    versions: list[AgentCapabilityVersion] = Field(min_length=1, max_length=16)

    @field_validator("versions")
    @classmethod
    def validate_versions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("capability versions must be unique")
        return value


class AgentCapabilityRuntime(BaseModel):
    model_config = ConfigDict(extra="forbid")

    privilege: AgentPrivilegeContext
    service_context: AgentServiceContext


class AgentCapabilityFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_upload: bool
    terminal: bool


class AgentCapabilityResourceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_concurrent_jobs: int = Field(ge=1, le=64)
    max_output_bytes: int = Field(ge=0, le=1_073_741_824)
    max_upload_bytes: int = Field(ge=0, le=10_737_418_240)
    command_timeout_seconds: int = Field(ge=1, le=86_400)


class AgentCapabilityHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: AgentHealthState
    reasons: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("reasons")
    @classmethod
    def validate_reasons(cls, value: list[str]) -> list[str]:
        normalized = [reason.strip() for reason in value]
        if any(not reason or len(reason) > 255 for reason in normalized):
            raise ValueError("health reasons must contain 1 to 255 characters")
        if len(normalized) != len(set(normalized)):
            raise ValueError("health reasons must be unique")
        return normalized


class AgentCapabilityManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["sha-agent-capabilities-v1"]
    capabilities: list[AgentCapabilityDescriptor] = Field(min_length=1, max_length=256)
    runtime: AgentCapabilityRuntime
    features: AgentCapabilityFeatures
    resource_limits: AgentCapabilityResourceLimits
    health: AgentCapabilityHealth

    @model_validator(mode="after")
    def validate_capabilities(self) -> "AgentCapabilityManifest":
        identifiers = [str(capability.id) for capability in self.capabilities]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("capability IDs must be unique")
        return self


class AgentProtocolCompatibility(BaseModel):
    model_config = ConfigDict(extra="forbid")

    negotiated_version: ProtocolVersion
    minimum_version: ProtocolVersion
    supported_versions: list[ProtocolVersion] = Field(min_length=1)


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


class InstallerRuntimeKind(str, Enum):
    go_agent = "go_agent"
    legacy_reporter = "legacy_reporter"


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


class ResponseActionStatus(str, Enum):
    queued = "queued"
    leased = "leased"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"


class ControlRegistryAction(str, Enum):
    apply_control = "apply_control"
    rollback_control = "rollback_control"


class ControlRegistryKind(str, Enum):
    benchmark_control = "benchmark_control"
    operational_observation = "operational_observation"


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
    protocol_version: ProtocolVersion = "legacy-v1"
    architecture: AgentArchitecture | None = None
    tenant_id: str | None = None
    site_id: str | None = None


class EndpointResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_id: str
    agent_fingerprint: str
    hostname: str
    platform: EndpointPlatform
    platform_version: str | None
    agent_version: str
    protocol_version: ProtocolVersion
    architecture: AgentArchitecture | None
    installation_id: str | None
    credential_mode: EndpointCredentialMode
    enrollment_token_id: str | None
    migration_state: EndpointAgentMigrationState
    migration_eligible: bool
    client_id: str
    location_id: str
    tenant_id: str | None
    site_id: str | None
    status: EndpointStatus
    last_seen_at: str
    created_at: str
    updated_at: str


class DeviceEndpointResponse(EndpointResponse):
    installation_id: str
    credential_mode: EndpointCredentialMode
    enrollment_token_id: str


class EnrollmentTokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    client_id: str = Field(min_length=1, max_length=64)
    location_id: str = Field(min_length=1, max_length=64)
    installer_profile_id: str | None = Field(default=None, min_length=1, max_length=64)
    platform: EndpointPlatform | None = None
    approval_policy: EnrollmentApprovalPolicy = EnrollmentApprovalPolicy.pending
    expires_in_minutes: int = Field(default=60, ge=1, le=1440)
    max_uses: int = Field(default=1, ge=1, le=1000)


class EnrollmentTokenResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    token_id: str
    client_id: str
    location_id: str
    installer_profile_id: str | None
    platform: EndpointPlatform | None
    approval_policy: EnrollmentApprovalPolicy
    state: EnrollmentTokenState
    expires_at: str
    max_uses: int
    use_count: int
    revoked_at: str | None
    created_by: str
    created_at: str
    updated_at: str


class EnrollmentTokenCreateResponse(EnrollmentTokenResponse):
    token: str = Field(json_schema_extra={"writeOnly": True})


class EnrollmentTokenListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[EnrollmentTokenResponse]


class DeviceCredentialMaterialRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    credential_id: str = Field(min_length=19, max_length=67)
    credential_secret: SecretStr = Field(min_length=43, max_length=128)

    @field_validator("credential_id")
    @classmethod
    def validate_credential_id(cls, value: str) -> str:
        if not is_canonical_credential_id(value):
            raise ValueError("credential_id has an invalid format")
        return value

    @field_validator("credential_secret")
    @classmethod
    def validate_credential_secret(cls, value: SecretStr) -> SecretStr:
        if not is_canonical_secret(value.get_secret_value()):
            raise ValueError("credential_secret has an invalid format")
        return value


class EnrollmentExchangeRequest(DeviceCredentialMaterialRequest):
    installation_id: str = Field(min_length=16, max_length=128)
    agent_fingerprint: str = Field(min_length=1, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    platform: EndpointPlatform
    platform_version: str | None = Field(default=None, max_length=255)
    agent_version: str = Field(min_length=1, max_length=64)
    protocol_version: ProtocolVersion
    architecture: AgentArchitecture

    @field_validator("installation_id")
    @classmethod
    def validate_installation_id(cls, value: str) -> str:
        if not is_canonical_installation_id(value):
            raise ValueError("installation_id has an invalid format")
        return value


class DeviceCredentialResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    credential_id: str
    endpoint_id: str
    status: DeviceCredentialStatus
    replaced_by_credential_id: str | None
    last_used_at: str | None
    expires_at: str | None
    created_at: str
    updated_at: str
    replaced_at: str | None
    revoked_at: str | None


class EnrollmentExchangeResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint: DeviceEndpointResponse
    credential: DeviceCredentialResponse
    protocol: AgentProtocolCompatibility
    replayed: bool


class AgentMeResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint: DeviceEndpointResponse
    credential: DeviceCredentialResponse
    protocol: AgentProtocolCompatibility


class EndpointExecutionHooks(BaseModel):
    model_config = ConfigDict(extra="ignore")

    captures_rollback_artifacts: bool
    reports_execution_results: bool
    supports_dry_run: bool


class EndpointHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_version: str
    protocol_version: ProtocolVersion = "legacy-v1"
    architecture: AgentArchitecture | None = None
    platform_version: str | None = None
    platform_profile: str
    connectivity_status: ConnectivityStatus
    declared_capabilities: list[DeclaredAgentCapability] = Field(min_length=1)
    capability_manifest: AgentCapabilityManifest | None = None
    execution_hooks: EndpointExecutionHooks

    @field_validator("declared_capabilities", mode="before")
    @classmethod
    def normalize_declared_capabilities(cls, value: object) -> object:
        if isinstance(value, list):
            return [item.strip() if isinstance(item, str) else item for item in value]
        return value


class EndpointHeartbeatAck(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_id: str
    status: EndpointStatus
    connectivity_status: ConnectivityStatus
    last_seen_at: str
    last_heartbeat_at: str
    accepted_capability_count: int
    pending_action_count: int
    protocol: AgentProtocolCompatibility
    created_at: str
    updated_at: str


class EndpointLatestPostureSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    snapshot_id: str
    observed_at: str
    platform_profile: str
    pass_count: int
    fail_count: int
    warn_count: int
    error_count: int
    not_applicable_count: int
    reboot_required_count: int


class EndpointLatestResultResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    control_key: str
    status: PostureStatus
    current_value: str | None = None
    recommended_value: str | None = None
    severity: str | None = None
    evidence_summary: str
    reboot_required: bool


class EndpointInventoryItemResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_id: str
    hostname: str
    platform: EndpointPlatform
    platform_version: str | None
    agent_version: str
    protocol_version: ProtocolVersion
    architecture: AgentArchitecture | None
    installation_id: str | None
    credential_mode: EndpointCredentialMode
    enrollment_token_id: str | None
    migration_state: EndpointAgentMigrationState
    migration_eligible: bool
    client_id: str
    location_id: str
    tenant_id: str | None
    site_id: str | None
    status: EndpointStatus
    connectivity_status: ConnectivityStatus | None
    last_seen_at: str
    last_heartbeat_at: str | None
    created_at: str
    updated_at: str
    last_platform_profile: str | None
    declared_capabilities: list[DeclaredAgentCapability]
    capability_manifest: AgentCapabilityManifest | None
    execution_hooks: EndpointExecutionHooks | None
    latest_posture_summary: EndpointLatestPostureSummary | None
    active_credential: DeviceCredentialResponse | None


class EndpointInventoryListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[EndpointInventoryItemResponse]


class EndpointDetailResponse(EndpointInventoryItemResponse):
    latest_results: list[EndpointLatestResultResponse]


class ClientCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    key: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)


class ClientResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    client_id: str
    key: str | None
    name: str
    state: HierarchyState
    is_system: bool
    created_at: str
    updated_at: str


class ClientListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[ClientResponse]


class LocationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    key: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)


class LocationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    location_id: str
    client_id: str
    key: str | None
    name: str
    state: HierarchyState
    is_system: bool
    created_at: str
    updated_at: str


class LocationListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[LocationResponse]


class SavedViewVisibility(str, Enum):
    private = "private"
    shared = "shared"


class EndpointFilterMatch(str, Enum):
    all = "all"
    any = "any"


class EndpointFilterField(str, Enum):
    endpoint_id = "endpoint_id"
    hostname = "hostname"
    platform = "platform"
    status = "status"
    connectivity_status = "connectivity_status"
    agent_version = "agent_version"
    client_id = "client_id"
    location_id = "location_id"
    tag = "tag"


class EndpointFilterOperator(str, Enum):
    eq = "eq"
    neq = "neq"
    contains = "contains"
    starts_with = "starts_with"
    in_ = "in"


class EndpointFilterRule(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    field: EndpointFilterField
    operator: EndpointFilterOperator = Field(alias="op", serialization_alias="op")
    value: str | list[str]

    @model_validator(mode="after")
    def validate_rule(self) -> "EndpointFilterRule":
        allowed_operators: dict[EndpointFilterField, set[EndpointFilterOperator]] = {
            EndpointFilterField.endpoint_id: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.hostname: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.contains,
                EndpointFilterOperator.starts_with,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.platform: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.status: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.connectivity_status: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.agent_version: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.contains,
                EndpointFilterOperator.starts_with,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.client_id: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.location_id: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.in_,
            },
            EndpointFilterField.tag: {
                EndpointFilterOperator.eq,
                EndpointFilterOperator.neq,
                EndpointFilterOperator.in_,
            },
        }
        if self.operator not in allowed_operators[self.field]:
            raise ValueError(f"operator {self.operator.value} is not allowed for {self.field.value}")
        values = self.value if isinstance(self.value, list) else [self.value]
        if self.operator == EndpointFilterOperator.in_ and not isinstance(self.value, list):
            raise ValueError("in operator requires a list value")
        if self.operator != EndpointFilterOperator.in_ and isinstance(self.value, list):
            raise ValueError("only the in operator accepts a list value")
        if not values or len(values) > 50:
            raise ValueError("filter value list must contain between 1 and 50 values")
        normalized = [item.strip() for item in values]
        if any(not item or len(item) > 255 for item in normalized):
            raise ValueError("filter values must contain 1 to 255 characters")
        self.value = normalized if isinstance(self.value, list) else normalized[0]
        return self


class EndpointFilterDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    match: EndpointFilterMatch = EndpointFilterMatch.all
    rules: list[EndpointFilterRule] = Field(min_length=1, max_length=16)


class ScopedFleetResourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_type: AuthorizationScopeType
    client_id: str | None = Field(default=None, min_length=1, max_length=64)
    location_id: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_scope_shape(self) -> "ScopedFleetResourceRequest":
        if self.scope_type == AuthorizationScopeType.global_:
            valid = self.client_id is None and self.location_id is None
        elif self.scope_type == AuthorizationScopeType.client:
            valid = self.client_id is not None and self.location_id is None
        else:
            valid = self.client_id is not None and self.location_id is not None
        if not valid:
            raise ValueError("client_id and location_id do not match scope_type")
        return self


class TagCreateRequest(ScopedFleetResourceRequest):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)


class TagResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tag_id: str
    name: str
    description: str | None
    scope_type: AuthorizationScopeType
    client_id: str | None
    location_id: str | None
    created_by: str
    created_at: str
    updated_at: str


class TagListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TagResponse]


class EndpointTagAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tag_id: str = Field(min_length=1, max_length=64)


class EndpointTagResponse(TagResponse):
    assigned_by: str
    assigned_at: str


class EndpointTagListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EndpointTagResponse]


class SavedViewCreateRequest(ScopedFleetResourceRequest):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    visibility: SavedViewVisibility = SavedViewVisibility.private
    filter: EndpointFilterDefinition


class SavedViewUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filter: EndpointFilterDefinition


class SavedViewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    saved_view_id: str
    name: str
    description: str | None
    visibility: SavedViewVisibility
    scope_type: AuthorizationScopeType
    client_id: str | None
    location_id: str | None
    owner_user_id: str | None
    owner_actor: str
    current_version: int
    current_filter: EndpointFilterDefinition
    content_hash: str
    created_at: str
    updated_at: str


class SavedViewListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SavedViewResponse]


class DynamicGroupCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    saved_view_id: str = Field(min_length=1, max_length=64)


class DynamicGroupResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dynamic_group_id: str
    name: str
    description: str | None
    scope_type: AuthorizationScopeType
    client_id: str | None
    location_id: str | None
    saved_view_id: str
    saved_view_version: int
    filter_hash: str
    owner_user_id: str | None
    owner_actor: str
    created_at: str
    updated_at: str


class DynamicGroupListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DynamicGroupResponse]


class DynamicGroupMemberResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_id: str
    hostname: str
    platform: EndpointPlatform
    status: EndpointStatus
    connectivity_status: ConnectivityStatus | None
    client_id: str
    location_id: str


class DynamicGroupPreviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dynamic_group_id: str
    saved_view_id: str
    saved_view_version: int
    filter_hash: str
    evaluated_endpoint_count: int
    matched_endpoint_count: int
    result_limit: int
    truncated: bool
    items: list[DynamicGroupMemberResponse]


class AuthScopeBindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    binding_id: str
    role: str
    scope_type: AuthorizationScopeType
    client_id: str | None
    location_id: str | None
    permissions: list[str]


class AuthSessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str
    display_name: str
    status: AuthUserStatus
    authentication_method: str
    bindings: list[AuthScopeBindingResponse]
    csrf_token: str | None


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_event_id: str
    event_type: str
    outcome: str
    actor: str
    user_id: str | None
    auth_method: str
    client_id: str | None
    location_id: str | None
    endpoint_id: str | None
    target_type: str | None
    target_id: str | None
    request_id: str | None
    metadata: dict[str, object]
    created_at: str


class AuditEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[AuditEventResponse]


class UserStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AuthUserStatus


class RoleBindingCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_key: str = Field(min_length=1, max_length=64)
    scope_type: AuthorizationScopeType
    client_id: str | None = Field(default=None, max_length=64)
    location_id: str | None = Field(default=None, max_length=64)


class ControlRegistryItemResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    control_id: str
    title: str
    platform: EndpointPlatform
    kind: ControlRegistryKind
    observation_aliases: list[str]
    supported_actions: list[ControlRegistryAction]


class ControlRegistryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[ControlRegistryItemResponse]


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
    client_id: str | None = None
    location_id: str | None = None
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
    runtime_kind: InstallerRuntimeKind
    client_id: str
    location_id: str
    tenant_id: str | None
    site_id: str | None
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
    requested_by: str | None = None
    reason: str
    risk: ApprovalRisk


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    decision: ApprovalDecision
    decided_by: str | None = None
    decision_comment: str
    expires_at: datetime | None = None


class ApprovalRequestResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approval_request_id: str
    scope_state: ApprovalScopeState
    client_id: str | None
    location_id: str | None
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
    requested_by: str | None = None
    approved_by: str | None = None
    reason: str
    expires_at: datetime


class ApprovalGrantResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approval_grant_id: str
    approval_request_id: str | None = None
    scope_state: ApprovalScopeState
    client_id: str | None
    location_id: str | None
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


class ResponseActionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_id: str
    approval_grant_id: str
    action: ApprovalAction
    control_id: str | None = None
    troubleshooting_scope: TroubleshootingScope | None = None
    idempotency_key: str | None = Field(default=None, max_length=128)
    requested_by: str | None = None
    reason: str


class ResponseActionResultRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: ResponseActionStatus
    result_summary: str
    lease_token: str = Field(min_length=32, max_length=256)


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    response_action_id: str
    endpoint_id: str
    approval_grant_id: str
    action: ApprovalAction
    control_id: str | None = None
    troubleshooting_scope: TroubleshootingScope | None = None
    idempotency_key: str
    requested_by: str
    reason: str
    status: ResponseActionStatus
    lease_expires_at: str | None = None
    leased_at: str | None = None
    attempt_count: int
    result_summary: str | None = None
    created_at: str
    updated_at: str
    completed_at: str | None = None


class ResponseActionListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[ResponseActionResponse]


class ResponseActionClaimItem(ResponseActionResponse):
    lease_token: str


class ResponseActionClaimResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[ResponseActionClaimItem]
