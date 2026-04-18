export type Platform = "windows" | "linux";
export type EndpointState = "healthy" | "degraded" | "needs-attention";
export type ControlStatus = "active" | "review" | "planned";
export type ApprovalRisk = "low" | "medium" | "high" | "critical";
export type ApprovalRequestKind = "hardening_change" | "elevated_troubleshooting";
export type ApprovalRequestStatus = "pending" | "approved" | "denied" | "expired" | "revoked";
export type ApprovalGrantStatus = "approved" | "expired" | "revoked";
export type ApprovalAction =
  | "collect_security_context"
  | "collect_remediation_evidence"
  | "inspect_control"
  | "apply_control"
  | "rollback_control"
  | "request_elevated_troubleshooting";
export type TroubleshootingScope =
  | "service_status"
  | "security_logs"
  | "firewall_state"
  | "identity_state"
  | "process_inventory"
  | "network_bindings";

export interface EndpointSummary {
  id: string;
  hostname: string;
  platform: Platform;
  state: EndpointState;
  hardeningScore: number;
  lastCheckIn: string;
  controls: readonly string[];
  note: string;
}

export interface ControlPolicy {
  id: string;
  name: string;
  scope: string;
  status: ControlStatus;
  description: string;
}

export interface ApprovalAuditEvent {
  approval_event_id: string;
  event_type: "requested" | "approved" | "denied" | "revoked" | "expired";
  actor: string;
  comment: string;
  created_at: string;
}

export interface ApprovalRequest {
  approval_request_id: string;
  endpoint_ids: readonly string[];
  request_kind: ApprovalRequestKind;
  requested_actions: readonly ApprovalAction[];
  control_ids: readonly string[];
  troubleshooting_scopes: readonly TroubleshootingScope[];
  requested_ttl_minutes: number;
  requested_by: string;
  reason: string;
  risk: ApprovalRisk;
  status: ApprovalRequestStatus;
  decision_by: string | null;
  decision_comment: string | null;
  decision_at: string | null;
  approval_grant_id: string | null;
  created_at: string;
  updated_at: string;
  audit_events: readonly ApprovalAuditEvent[];
}

export interface ApprovalGrant {
  approval_grant_id: string;
  approval_request_id: string | null;
  endpoint_ids: readonly string[];
  allowed_actions: readonly ApprovalAction[];
  control_ids: readonly string[];
  troubleshooting_scopes: readonly TroubleshootingScope[];
  requested_by: string;
  approved_by: string;
  reason: string;
  expires_at: string;
  status: ApprovalGrantStatus;
  created_at: string;
  updated_at: string;
}

export interface InstallerProfile {
  id: string;
  platform: Platform;
  displayName: string;
  packageName: string;
  description: string;
}

export interface FleetSummary {
  totalEndpoints: number;
  healthyEndpoints: number;
  degradedEndpoints: number;
  needsAttentionEndpoints: number;
  windowsEndpoints: number;
  linuxEndpoints: number;
  pendingApprovals: number;
  averageScore: number;
}

const ENDPOINT_FIXTURES = [
  {
    id: "ep_demo_linux_01",
    hostname: "build-lnx-01",
    platform: "linux",
    state: "healthy",
    hardeningScore: 91,
    lastCheckIn: "4 minutes ago",
    controls: ["SSH baseline", "Auditd coverage", "Kernel sysctl profile"],
    note: "Primary Linux fixture used by the endpoint detail route.",
  },
  {
    id: "ep_demo_windows_01",
    hostname: "eng-win-17",
    platform: "windows",
    state: "degraded",
    hardeningScore: 84,
    lastCheckIn: "11 minutes ago",
    controls: ["Defender baseline", "PowerShell policy", "BitLocker enforcement"],
    note: "Windows endpoint fixture for the fleet shell.",
  },
  {
    id: "ep_demo_windows_02",
    hostname: "ops-win-04",
    platform: "windows",
    state: "needs-attention",
    hardeningScore: 72,
    lastCheckIn: "26 minutes ago",
    controls: ["Local admin cleanup", "LAPS rollout", "RDP restriction"],
    note: "Needs approval before the next package refresh.",
  },
] satisfies readonly EndpointSummary[];

const CONTROL_POLICIES = [
  {
    id: "ctrl_ssh_baseline",
    name: "SSH hardening profile",
    scope: "Linux endpoints",
    status: "active",
    description: "Locks down SSH defaults, disables password auth, and trims unnecessary services.",
  },
  {
    id: "ctrl_powershell_policy",
    name: "PowerShell execution policy",
    scope: "Windows endpoints",
    status: "review",
    description: "Reserves a signed-script lane for future Windows package generation.",
  },
  {
    id: "ctrl_admin_baseline",
    name: "Local admin baseline",
    scope: "All endpoints",
    status: "planned",
    description: "Cleans up shared admin accounts and prepares for rollout approvals.",
  },
] satisfies readonly ControlPolicy[];

const APPROVAL_REQUESTS = [
  {
    approval_request_id: "apr_windows_rdp_rollout",
    endpoint_ids: ["ep_demo_windows_01"],
    request_kind: "hardening_change",
    requested_actions: ["apply_control"],
    control_ids: ["control.windows.rdp-network-level-authentication"],
    troubleshooting_scopes: [],
    requested_ttl_minutes: 45,
    requested_by: "SHAna",
    reason: "Approve RDP network level authentication rollout",
    risk: "high",
    status: "pending",
    decision_by: null,
    decision_comment: null,
    decision_at: null,
    approval_grant_id: null,
    created_at: "2026-04-18T20:15:00Z",
    updated_at: "2026-04-18T20:15:00Z",
    audit_events: [
      {
        approval_event_id: "ape_windows_rdp_requested",
        event_type: "requested",
        actor: "SHAna",
        comment: "Approve RDP network level authentication rollout",
        created_at: "2026-04-18T20:15:00Z",
      },
    ],
  },
  {
    approval_request_id: "apr_windows_ops_troubleshoot",
    endpoint_ids: ["ep_demo_windows_02"],
    request_kind: "elevated_troubleshooting",
    requested_actions: ["request_elevated_troubleshooting", "inspect_control", "collect_security_context"],
    control_ids: [],
    troubleshooting_scopes: ["security_logs", "service_status"],
    requested_ttl_minutes: 60,
    requested_by: "SHAna",
    reason: "Temporary elevated troubleshooting for ops-win-04",
    risk: "critical",
    status: "pending",
    decision_by: null,
    decision_comment: null,
    decision_at: null,
    approval_grant_id: null,
    created_at: "2026-04-18T20:20:00Z",
    updated_at: "2026-04-18T20:20:00Z",
    audit_events: [
      {
        approval_event_id: "ape_windows_ops_requested",
        event_type: "requested",
        actor: "SHAna",
        comment: "Temporary elevated troubleshooting for ops-win-04",
        created_at: "2026-04-18T20:20:00Z",
      },
    ],
  },
  {
    approval_request_id: "apr_windows_ops_active",
    endpoint_ids: ["ep_demo_windows_02"],
    request_kind: "elevated_troubleshooting",
    requested_actions: ["request_elevated_troubleshooting", "inspect_control", "collect_security_context"],
    control_ids: [],
    troubleshooting_scopes: ["security_logs", "service_status"],
    requested_ttl_minutes: 60,
    requested_by: "SHAna",
    reason: "Active elevated troubleshooting window for ops-win-04",
    risk: "high",
    status: "approved",
    decision_by: "secops",
    decision_comment: "Approved for a 60 minute diagnostic window.",
    decision_at: "2026-04-18T20:25:00Z",
    approval_grant_id: "grant_windows_ops_troubleshoot",
    created_at: "2026-04-18T20:20:00Z",
    updated_at: "2026-04-18T20:25:00Z",
    audit_events: [
      {
        approval_event_id: "ape_windows_ops_active_requested",
        event_type: "requested",
        actor: "SHAna",
        comment: "Active elevated troubleshooting window for ops-win-04",
        created_at: "2026-04-18T20:20:00Z",
      },
      {
        approval_event_id: "ape_windows_ops_active_approved",
        event_type: "approved",
        actor: "secops",
        comment: "Approved for a 60 minute diagnostic window.",
        created_at: "2026-04-18T20:25:00Z",
      },
    ],
  },
  {
    approval_request_id: "apr_linux_ssh_denied",
    endpoint_ids: ["ep_demo_linux_01"],
    request_kind: "hardening_change",
    requested_actions: ["apply_control"],
    control_ids: ["control.linux.ssh.disable-password-authentication"],
    troubleshooting_scopes: [],
    requested_ttl_minutes: 30,
    requested_by: "SHAna",
    reason: "Disable SSH password authentication on build-lnx-01",
    risk: "high",
    status: "denied",
    decision_by: "secops",
    decision_comment: "Too disruptive for the current maintenance window.",
    decision_at: "2026-04-18T18:10:00Z",
    approval_grant_id: null,
    created_at: "2026-04-18T18:00:00Z",
    updated_at: "2026-04-18T18:10:00Z",
    audit_events: [
      {
        approval_event_id: "ape_linux_ssh_requested",
        event_type: "requested",
        actor: "SHAna",
        comment: "Disable SSH password authentication on build-lnx-01",
        created_at: "2026-04-18T18:00:00Z",
      },
      {
        approval_event_id: "ape_linux_ssh_denied",
        event_type: "denied",
        actor: "secops",
        comment: "Too disruptive for the current maintenance window.",
        created_at: "2026-04-18T18:10:00Z",
      },
    ],
  },
  {
    approval_request_id: "apr_windows_firewall_expired",
    endpoint_ids: ["ep_demo_windows_02"],
    request_kind: "hardening_change",
    requested_actions: ["apply_control"],
    control_ids: ["control.windows.firewall-all-profiles"],
    troubleshooting_scopes: [],
    requested_ttl_minutes: 30,
    requested_by: "SHAna",
    reason: "Apply Windows firewall all-profiles baseline",
    risk: "medium",
    status: "expired",
    decision_by: "secops",
    decision_comment: "Approved for a narrow rollout window.",
    decision_at: "2026-04-18T17:05:00Z",
    approval_grant_id: "grant_windows_firewall_expired",
    created_at: "2026-04-18T17:00:00Z",
    updated_at: "2026-04-18T17:36:00Z",
    audit_events: [
      {
        approval_event_id: "ape_windows_firewall_requested",
        event_type: "requested",
        actor: "SHAna",
        comment: "Apply Windows firewall all-profiles baseline",
        created_at: "2026-04-18T17:00:00Z",
      },
      {
        approval_event_id: "ape_windows_firewall_approved",
        event_type: "approved",
        actor: "secops",
        comment: "Approved for a narrow rollout window.",
        created_at: "2026-04-18T17:05:00Z",
      },
      {
        approval_event_id: "ape_windows_firewall_expired",
        event_type: "expired",
        actor: "secops",
        comment: "Grant expired automatically.",
        created_at: "2026-04-18T17:36:00Z",
      },
    ],
  },
] satisfies readonly ApprovalRequest[];

const APPROVAL_GRANTS = [
  {
    approval_grant_id: "grant_windows_ops_troubleshoot",
    approval_request_id: "apr_windows_ops_active",
    endpoint_ids: ["ep_demo_windows_02"],
    allowed_actions: ["request_elevated_troubleshooting", "inspect_control", "collect_security_context"],
    control_ids: [],
    troubleshooting_scopes: ["security_logs", "service_status"],
    requested_by: "SHAna",
    approved_by: "secops",
    reason: "Active elevated troubleshooting window for ops-win-04",
    expires_at: "2026-04-18T21:25:00Z",
    status: "approved",
    created_at: "2026-04-18T20:25:00Z",
    updated_at: "2026-04-18T20:25:00Z",
  },
  {
    approval_grant_id: "grant_linux_manual_context",
    approval_request_id: null,
    endpoint_ids: ["ep_demo_linux_01"],
    allowed_actions: ["collect_security_context", "inspect_control", "request_elevated_troubleshooting"],
    control_ids: [],
    troubleshooting_scopes: ["network_bindings"],
    requested_by: "ops",
    approved_by: "secops",
    reason: "Manual emergency context collection for build-lnx-01",
    expires_at: "2026-04-18T23:45:00Z",
    status: "approved",
    created_at: "2026-04-18T20:40:00Z",
    updated_at: "2026-04-18T20:40:00Z",
  },
  {
    approval_grant_id: "grant_windows_firewall_expired",
    approval_request_id: "apr_windows_firewall_expired",
    endpoint_ids: ["ep_demo_windows_02"],
    allowed_actions: ["apply_control"],
    control_ids: ["control.windows.firewall-all-profiles"],
    troubleshooting_scopes: [],
    requested_by: "SHAna",
    approved_by: "secops",
    reason: "Apply Windows firewall all-profiles baseline",
    expires_at: "2026-04-18T17:35:00Z",
    status: "expired",
    created_at: "2026-04-18T17:05:00Z",
    updated_at: "2026-04-18T17:36:00Z",
  },
] satisfies readonly ApprovalGrant[];

const INSTALLER_PROFILES = [
  {
    id: "profile_windows_workstation",
    platform: "windows",
    displayName: "Windows workstation profile",
    packageName: "sha-windows-agent",
    description: "Prepares a signed installer shape for controlled Windows rollout.",
  },
  {
    id: "profile_linux_server",
    platform: "linux",
    displayName: "Linux server profile",
    packageName: "sha-linux-agent",
    description: "Reserves a Linux packaging lane for DEB/RPM or script generation.",
  },
] satisfies readonly InstallerProfile[];

const ENDPOINT_LABELS = new Map(ENDPOINT_FIXTURES.map((endpoint) => [endpoint.id, endpoint.hostname]));

export function getFleetEndpoints() {
  return ENDPOINT_FIXTURES;
}

export function getEndpointById(endpointId: string) {
  return ENDPOINT_FIXTURES.find((endpoint) => endpoint.id === endpointId);
}

export function getControlPolicies() {
  return CONTROL_POLICIES;
}

export function getApprovalRequests() {
  return APPROVAL_REQUESTS;
}

export function getApprovalGrants() {
  return APPROVAL_GRANTS;
}

export function getInstallerProfiles() {
  return INSTALLER_PROFILES;
}

export function getFleetSummary(): FleetSummary {
  const totalEndpoints = ENDPOINT_FIXTURES.length;
  const healthyEndpoints = ENDPOINT_FIXTURES.filter((endpoint) => endpoint.state === "healthy").length;
  const degradedEndpoints = ENDPOINT_FIXTURES.filter((endpoint) => endpoint.state === "degraded").length;
  const needsAttentionEndpoints = ENDPOINT_FIXTURES.filter((endpoint) => endpoint.state === "needs-attention").length;
  const windowsEndpoints = ENDPOINT_FIXTURES.filter((endpoint) => endpoint.platform === "windows").length;
  const linuxEndpoints = ENDPOINT_FIXTURES.filter((endpoint) => endpoint.platform === "linux").length;
  const pendingApprovals = APPROVAL_REQUESTS.filter((request) => request.status === "pending").length;
  const averageScore = Math.round(
    ENDPOINT_FIXTURES.reduce((total, endpoint) => total + endpoint.hardeningScore, 0) / totalEndpoints,
  );

  return {
    totalEndpoints,
    healthyEndpoints,
    degradedEndpoints,
    needsAttentionEndpoints,
    windowsEndpoints,
    linuxEndpoints,
    pendingApprovals,
    averageScore,
  };
}

export function platformDisplayName(platform: Platform) {
  return platform === "windows" ? "Windows" : "Linux";
}

export function endpointStateDisplay(state: EndpointState) {
  switch (state) {
    case "healthy":
      return "Healthy";
    case "degraded":
      return "Degraded";
    case "needs-attention":
      return "Needs attention";
  }
}

export function endpointStateTone(state: EndpointState): "success" | "warning" | "danger" {
  switch (state) {
    case "healthy":
      return "success";
    case "degraded":
      return "warning";
    case "needs-attention":
      return "danger";
  }
}

export function controlStatusDisplay(status: ControlStatus) {
  switch (status) {
    case "active":
      return "Active";
    case "review":
      return "Review";
    case "planned":
      return "Planned";
  }
}

export function controlStatusTone(status: ControlStatus): "success" | "warning" | "info" {
  switch (status) {
    case "active":
      return "success";
    case "review":
      return "warning";
    case "planned":
      return "info";
  }
}

export function approvalStatusDisplay(status: ApprovalRequestStatus | ApprovalGrantStatus) {
  switch (status) {
    case "pending":
      return "Pending";
    case "approved":
      return "Approved";
    case "denied":
      return "Denied";
    case "expired":
      return "Expired";
    case "revoked":
      return "Revoked";
  }
}

export function approvalStatusTone(
  status: ApprovalRequestStatus | ApprovalGrantStatus,
): "warning" | "success" | "danger" | "info" {
  switch (status) {
    case "pending":
      return "warning";
    case "approved":
      return "success";
    case "denied":
    case "revoked":
      return "danger";
    case "expired":
      return "info";
  }
}

export function approvalRiskTone(risk: ApprovalRisk): "info" | "warning" | "danger" {
  switch (risk) {
    case "low":
      return "info";
    case "medium":
      return "warning";
    case "high":
    case "critical":
      return "danger";
  }
}

export function approvalRiskDisplay(risk: ApprovalRisk) {
  switch (risk) {
    case "low":
      return "Low";
    case "medium":
      return "Medium";
    case "high":
      return "High";
    case "critical":
      return "Critical";
  }
}

export function approvalActionDisplay(action: ApprovalAction) {
  switch (action) {
    case "collect_security_context":
      return "collect_security_context";
    case "collect_remediation_evidence":
      return "collect_remediation_evidence";
    case "inspect_control":
      return "inspect_control";
    case "apply_control":
      return "apply_control";
    case "rollback_control":
      return "rollback_control";
    case "request_elevated_troubleshooting":
      return "request_elevated_troubleshooting";
  }
}

export function troubleshootingScopeDisplay(scope: TroubleshootingScope) {
  switch (scope) {
    case "service_status":
      return "Service status";
    case "security_logs":
      return "Security logs";
    case "firewall_state":
      return "Firewall state";
    case "identity_state":
      return "Identity state";
    case "process_inventory":
      return "Process inventory";
    case "network_bindings":
      return "Network bindings";
  }
}

export function approvalRequestKindDisplay(kind: ApprovalRequestKind) {
  return kind === "hardening_change" ? "Hardening change" : "Elevated troubleshooting";
}

export function describeApprovalRequest(request: ApprovalRequest) {
  return request.reason;
}

export function describeApprovalGrant(grant: ApprovalGrant) {
  return grant.reason;
}

export function endpointListDisplay(endpointIds: readonly string[]) {
  return endpointIds.map((endpointId) => ENDPOINT_LABELS.get(endpointId) ?? endpointId).join(", ");
}
