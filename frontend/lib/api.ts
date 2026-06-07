export type Platform = "windows" | "linux";
export type EndpointStatus = "pending" | "active" | "stale";
export type ConnectivityStatus = "online" | "degraded" | null;
export type PostureStatus = "pass" | "fail" | "warn" | "error" | "not_applicable";
export type Tone = "success" | "warning" | "danger" | "info";
export type InstallerChannel = "stable" | "preview";
export type InstallerPolicyMode = "observe" | "safe_auto" | "approval_required";
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

export interface EndpointLatestPostureSummary {
  snapshot_id: string;
  observed_at: string;
  platform_profile: string;
  pass_count: number;
  fail_count: number;
  warn_count: number;
  error_count: number;
  not_applicable_count: number;
  reboot_required_count: number;
}

export interface EndpointLatestResult {
  control_key: string;
  status: PostureStatus;
  current_value: string | null;
  recommended_value: string | null;
  severity: string | null;
  evidence_summary: string;
  reboot_required: boolean;
}

export interface EndpointInventoryItem {
  endpoint_id: string;
  hostname: string;
  platform: Platform;
  platform_version: string | null;
  agent_version: string;
  tenant_id: string | null;
  site_id: string | null;
  status: EndpointStatus;
  connectivity_status: ConnectivityStatus;
  last_seen_at: string;
  last_heartbeat_at: string | null;
  created_at: string;
  updated_at: string;
  last_platform_profile: string | null;
  declared_capabilities: string[];
  execution_hooks: Record<string, boolean> | null;
  latest_posture_summary: EndpointLatestPostureSummary | null;
}

export interface EndpointDetail extends EndpointInventoryItem {
  latest_results: EndpointLatestResult[];
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
  name: string;
  platform: Platform;
  channel: InstallerChannel;
  control_plane_url: string;
  policy_mode: InstallerPolicyMode;
  tenant_id: string | null;
  site_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface InstallerProfileCreatePayload {
  name: string;
  platform: Platform;
  channel: InstallerChannel;
  control_plane_url: string;
  policy_mode: InstallerPolicyMode;
  tenant_id?: string | null;
  site_id?: string | null;
}

export interface ApprovalRequestCreatePayload {
  endpoint_ids: string[];
  request_kind: ApprovalRequestKind;
  requested_actions: ApprovalAction[];
  control_ids: string[];
  troubleshooting_scopes: TroubleshootingScope[];
  requested_ttl_minutes: number;
  requested_by: string;
  reason: string;
  risk: ApprovalRisk;
}

export interface ApprovalGrantCreatePayload {
  endpoint_ids: string[];
  allowed_actions: ApprovalAction[];
  control_ids: string[];
  troubleshooting_scopes: TroubleshootingScope[];
  requested_by: string;
  approved_by: string;
  reason: string;
  expires_at: string;
}

export interface ApprovalDecisionPayload {
  decision: "approve" | "deny" | "revoke";
  decided_by: string;
  decision_comment: string;
  expires_at?: string | null;
}

export interface EndpointEnrollPayload {
  agent_fingerprint: string;
  hostname: string;
  platform: Platform;
  platform_version?: string | null;
  agent_version: string;
  tenant_id?: string | null;
  site_id?: string | null;
}

export interface EndpointHeartbeatPayload {
  agent_version: string;
  platform_version?: string | null;
  platform_profile: string;
  connectivity_status: Exclude<ConnectivityStatus, null>;
  declared_capabilities: string[];
  execution_hooks: Record<string, boolean>;
}

export interface EndpointHeartbeatAck {
  endpoint_id: string;
  status: EndpointStatus;
  connectivity_status: Exclude<ConnectivityStatus, null>;
  last_seen_at: string;
  last_heartbeat_at: string;
  accepted_capability_count: number;
  pending_action_count: number;
  created_at: string;
  updated_at: string;
}

export interface PostureSnapshotPayload {
  endpoint_id: string;
  observed_at: string;
  platform_profile: string;
  results: Array<{
    control_key: string;
    status: PostureStatus;
    current_value?: string | null;
    recommended_value?: string | null;
    severity?: string | null;
    evidence_summary: string;
    reboot_required: boolean;
  }>;
}

export interface PostureSnapshotAck {
  snapshot_id: string;
  endpoint_id: string;
  observed_at: string;
  accepted_result_count: number;
  created_at: string;
}

export interface FleetSummary {
  totalEndpoints: number;
  activeEndpoints: number;
  connectedEndpoints: number;
  degradedEndpoints: number;
  unscannedEndpoints: number;
  pendingApprovals: number;
  activeGrants: number;
  averageScore: number;
}

export interface SourcePackSummary {
  pack_id: string;
  source_family: string;
  source_name: string;
  source_version: string;
  control_count: number;
}

export interface SourcePackDetail extends SourcePackSummary {
  generated_at: string;
  source_url: string;
  platforms: Platform[];
  profiles: string[];
  summary: string;
  controls: Array<{
    control_id: string;
    title: string;
    platform: Platform;
    profiles: string[];
    severity: string;
    disruption: string;
    rollback_complexity: string;
    auto_remediation_candidate: boolean;
    reboot_required: boolean;
    guidance_summary: string;
    detection_summary: string;
    remediation_summary: string;
    rollback_summary: string;
    provenance: {
      source_locator: string;
      notes: string;
    };
    mappings: {
      nist_csf_ids: string[];
      sp80053_ids: string[];
      stig_ids: string[];
      cisa_reference_ids: string[];
    };
  }>;
}

export interface InstallerArtifact {
  filename: string;
  mediaType: string;
  sha256: string;
  content: string;
}

export interface ControlLibraryEntry {
  id: string;
  title: string;
  description: string;
  scope: string;
  phase: "enforced" | "watch" | "queued";
}

export interface ControlRollup {
  controlKey: string;
  title: string;
  failCount: number;
  warnCount: number;
  passCount: number;
  errorCount: number;
  rebootCount: number;
  openRequestCount: number;
  impactedEndpoints: string[];
  tone: Tone;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function toInventoryItem(detail: EndpointDetail): EndpointInventoryItem {
  const { latest_results: _latestResults, ...inventory } = detail;
  return inventory;
}

const FIXTURE_ENDPOINT_DETAILS: Record<string, EndpointDetail> = {
  ep_demo_linux_01: {
    endpoint_id: "ep_demo_linux_01",
    hostname: "demo-linux-01",
    platform: "linux",
    platform_version: "Ubuntu 24.04 LTS",
    agent_version: "1.3.2",
    tenant_id: "tenant-demo",
    site_id: "site-demo-west",
    status: "active",
    connectivity_status: "online",
    last_seen_at: "2026-04-19T12:04:00Z",
    last_heartbeat_at: "2026-04-19T12:04:00Z",
    created_at: "2026-04-18T18:20:00Z",
    updated_at: "2026-04-19T12:04:00Z",
    last_platform_profile: "linux_cis_l1",
    declared_capabilities: ["enroll", "heartbeat", "collect_posture_snapshot", "inspect_control"],
    execution_hooks: {
      captures_rollback_artifacts: false,
      reports_execution_results: false,
      supports_dry_run: false,
    },
    latest_posture_summary: {
      snapshot_id: "snap_demo_linux_01",
      observed_at: "2026-04-19T12:02:00Z",
      platform_profile: "linux_cis_l1",
      pass_count: 15,
      fail_count: 0,
      warn_count: 2,
      error_count: 0,
      not_applicable_count: 1,
      reboot_required_count: 0,
    },
    latest_results: [
      {
        control_key: "linux.ssh.disable_password_authentication",
        status: "pass",
        current_value: "PasswordAuthentication no",
        recommended_value: "PasswordAuthentication no",
        severity: "high",
        evidence_summary: "Password authentication disabled in sshd_config.",
        reboot_required: false,
      },
      {
        control_key: "linux.auditd.ruleset_integrity",
        status: "warn",
        current_value: "23 custom rules loaded",
        recommended_value: "26 baseline rules loaded",
        severity: "medium",
        evidence_summary: "Auditd rule coverage is missing file deletion telemetry for /var/log/demo.",
        reboot_required: false,
      },
      {
        control_key: "linux.kernel.ipv4_source_route",
        status: "pass",
        current_value: "0",
        recommended_value: "0",
        severity: "medium",
        evidence_summary: "Source-routed packets remain disabled.",
        reboot_required: false,
      },
    ],
  },
  ep_demo_windows_01: {
    endpoint_id: "ep_demo_windows_01",
    hostname: "demo-windows-01",
    platform: "windows",
    platform_version: "Windows 11 24H2",
    agent_version: "1.3.2",
    tenant_id: "tenant-demo",
    site_id: "site-demo-lab",
    status: "active",
    connectivity_status: "degraded",
    last_seen_at: "2026-04-19T11:56:00Z",
    last_heartbeat_at: "2026-04-19T11:56:00Z",
    created_at: "2026-04-18T18:40:00Z",
    updated_at: "2026-04-19T11:56:00Z",
    last_platform_profile: "windows_defender_baseline",
    declared_capabilities: ["enroll", "heartbeat", "collect_posture_snapshot", "inspect_control"],
    execution_hooks: {
      captures_rollback_artifacts: false,
      reports_execution_results: false,
      supports_dry_run: false,
    },
    latest_posture_summary: {
      snapshot_id: "snap_demo_windows_01",
      observed_at: "2026-04-19T11:55:00Z",
      platform_profile: "windows_defender_baseline",
      pass_count: 11,
      fail_count: 2,
      warn_count: 1,
      error_count: 0,
      not_applicable_count: 1,
      reboot_required_count: 1,
    },
    latest_results: [
      {
        control_key: "windows.rdp.network_level_authentication",
        status: "fail",
        current_value: "Disabled",
        recommended_value: "Enabled",
        severity: "high",
        evidence_summary: "RDP NLA is disabled on the primary engineering workstation image.",
        reboot_required: false,
      },
      {
        control_key: "windows.defender.real_time_protection",
        status: "pass",
        current_value: "Enabled",
        recommended_value: "Enabled",
        severity: "critical",
        evidence_summary: "Microsoft Defender real-time protection is active.",
        reboot_required: false,
      },
      {
        control_key: "windows.powershell.constrained_language_mode",
        status: "warn",
        current_value: "Audit only",
        recommended_value: "Enforced",
        severity: "medium",
        evidence_summary: "PowerShell policy remains in audit mode during the current change window.",
        reboot_required: false,
      },
    ],
  },
  ep_demo_windows_02: {
    endpoint_id: "ep_demo_windows_02",
    hostname: "demo-windows-02",
    platform: "windows",
    platform_version: "Windows 11 24H2",
    agent_version: "1.3.1",
    tenant_id: "tenant-demo",
    site_id: "site-demo-ops",
    status: "active",
    connectivity_status: "degraded",
    last_seen_at: "2026-04-19T11:43:00Z",
    last_heartbeat_at: "2026-04-19T11:43:00Z",
    created_at: "2026-04-18T17:55:00Z",
    updated_at: "2026-04-19T11:43:00Z",
    last_platform_profile: "windows_ops_recovery",
    declared_capabilities: ["enroll", "heartbeat", "collect_posture_snapshot", "inspect_control"],
    execution_hooks: {
      captures_rollback_artifacts: false,
      reports_execution_results: false,
      supports_dry_run: false,
    },
    latest_posture_summary: {
      snapshot_id: "snap_demo_windows_02",
      observed_at: "2026-04-19T11:42:00Z",
      platform_profile: "windows_ops_recovery",
      pass_count: 8,
      fail_count: 3,
      warn_count: 2,
      error_count: 1,
      not_applicable_count: 0,
      reboot_required_count: 1,
    },
    latest_results: [
      {
        control_key: "windows.local_admin.laps",
        status: "fail",
        current_value: "Static local admin password pattern detected",
        recommended_value: "Per-device managed local-admin password",
        severity: "high",
        evidence_summary: "Local admin rotation still uses a shared password pattern.",
        reboot_required: false,
      },
      {
        control_key: "windows.firewall.all_profiles",
        status: "fail",
        current_value: "Domain:on Private:off Public:on",
        recommended_value: "All profiles on",
        severity: "high",
        evidence_summary: "Private firewall profile remains disabled after emergency troubleshooting.",
        reboot_required: false,
      },
      {
        control_key: "windows.security_log.forwarding",
        status: "error",
        current_value: null,
        recommended_value: "WinRM forwarding active",
        severity: "critical",
        evidence_summary: "Forwarding agent returned no telemetry during the last collection window.",
        reboot_required: false,
      },
    ],
  },
};

const FIXTURE_APPROVAL_REQUESTS = [
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
    reason: "Temporary elevated troubleshooting for demo-windows-02",
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
        comment: "Temporary elevated troubleshooting for demo-windows-02",
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
    reason: "Active elevated troubleshooting window for demo-windows-02",
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
        comment: "Active elevated troubleshooting window for demo-windows-02",
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
    reason: "Disable SSH password authentication on demo-linux-01",
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
        comment: "Disable SSH password authentication on demo-linux-01",
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

const FIXTURE_APPROVAL_GRANTS = [
  {
    approval_grant_id: "grant_windows_ops_troubleshoot",
    approval_request_id: "apr_windows_ops_active",
    endpoint_ids: ["ep_demo_windows_02"],
    allowed_actions: ["request_elevated_troubleshooting", "inspect_control", "collect_security_context"],
    control_ids: [],
    troubleshooting_scopes: ["security_logs", "service_status"],
    requested_by: "SHAna",
    approved_by: "secops",
    reason: "Active elevated troubleshooting window for demo-windows-02",
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
    reason: "Manual emergency context collection for demo-linux-01",
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

const FIXTURE_INSTALLER_PROFILES = [
  {
    id: "ip_windows_workstation",
    name: "Windows Workstation",
    platform: "windows",
    channel: "stable",
    control_plane_url: "https://sha.example.test",
    policy_mode: "approval_required",
    tenant_id: "tenant-demo",
    site_id: "site-demo-lab",
    created_at: "2026-04-18T19:10:00Z",
    updated_at: "2026-04-18T19:10:00Z",
  },
  {
    id: "ip_linux_server",
    name: "Linux Server",
    platform: "linux",
    channel: "preview",
    control_plane_url: "https://sha.example.test",
    policy_mode: "safe_auto",
    tenant_id: "tenant-demo",
    site_id: "site-demo-west",
    created_at: "2026-04-18T19:18:00Z",
    updated_at: "2026-04-18T19:18:00Z",
  },
] satisfies readonly InstallerProfile[];

const CONTROL_LIBRARY = [
  {
    id: "ctrl_linux_ssh",
    title: "SSH entrypoint lockdown",
    description: "Disables password auth, restricts root login, and constrains remote ingress to break-glass lanes.",
    scope: "Linux production hosts",
    phase: "enforced",
  },
  {
    id: "ctrl_windows_exec",
    title: "Windows script execution boundary",
    description: "Moves PowerShell into signed-only execution and constrains unmanaged modules.",
    scope: "Windows managed workstations",
    phase: "watch",
  },
  {
    id: "ctrl_identity_lifecycle",
    title: "Privileged identity rotation",
    description: "Eliminates shared local admin credentials and stages LAPS-backed per-host rotation.",
    scope: "All operator endpoints",
    phase: "queued",
  },
] satisfies readonly ControlLibraryEntry[];

async function parseApiError(response: Response) {
  try {
    const body = (await response.json()) as { detail?: string };
    return body.detail ?? `request failed with status ${response.status}`;
  } catch {
    return `request failed with status ${response.status}`;
  }
}

export async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    throw new Error(await parseApiError(response));
  }

  return (await response.json()) as T;
}

export async function fetchText(path: string, init?: RequestInit): Promise<{ content: string; response: Response }> {
  const response = await fetch(path, init);
  if (!response.ok) {
    throw new Error(await parseApiError(response));
  }
  return {
    content: await response.text(),
    response,
  };
}

export async function listEndpoints() {
  const data = await fetchJson<{ items: EndpointInventoryItem[] }>("/api/endpoints");
  return data.items;
}

export async function getEndpoint(endpointId: string) {
  return fetchJson<EndpointDetail>(`/api/endpoints/${endpointId}`);
}

export async function enrollEndpoint(payload: EndpointEnrollPayload) {
  return fetchJson<EndpointInventoryItem>("/api/endpoints/enroll", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function sendEndpointHeartbeat(endpointId: string, payload: EndpointHeartbeatPayload) {
  return fetchJson<EndpointHeartbeatAck>(`/api/endpoints/${endpointId}/heartbeat`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function recordPostureSnapshot(payload: PostureSnapshotPayload) {
  return fetchJson<PostureSnapshotAck>("/api/posture-snapshots", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function listApprovalRequests() {
  const data = await fetchJson<{ items: ApprovalRequest[] }>("/api/approval-requests");
  return data.items;
}

export async function createApprovalRequest(payload: ApprovalRequestCreatePayload) {
  return fetchJson<ApprovalRequest>("/api/approval-requests", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function decideApprovalRequest(approvalRequestId: string, payload: ApprovalDecisionPayload) {
  return fetchJson<ApprovalRequest>(`/api/approval-requests/${approvalRequestId}/decisions`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function listApprovalGrants() {
  const data = await fetchJson<{ items: ApprovalGrant[] }>("/api/approval-grants");
  return data.items;
}

export async function createApprovalGrant(payload: ApprovalGrantCreatePayload) {
  return fetchJson<ApprovalGrant>("/api/approval-grants", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function listInstallerProfiles() {
  const data = await fetchJson<{ items: InstallerProfile[] }>("/api/installer-profiles");
  return data.items;
}

export async function getInstallerArtifact(profileId: string) {
  const { content, response } = await fetchText(`/api/installer-profiles/${profileId}/artifact`);
  const disposition = response.headers.get("content-disposition") ?? "";
  const filenameMatch = disposition.match(/filename="?([^\"]+)"?/i);
  return {
    filename: filenameMatch?.[1] ?? `sha-installer-${profileId}.txt`,
    mediaType: response.headers.get("content-type") ?? "text/plain",
    sha256: response.headers.get("x-sha-artifact-sha256") ?? "",
    content,
  } satisfies InstallerArtifact;
}

export function getInstallerArtifactUrl(profileId: string) {
  return `/api/installer-profiles/${profileId}/artifact`;
}

export async function listSourcePacks() {
  const data = await fetchJson<{ packs: SourcePackSummary[] }>("/api/source-packs");
  return data.packs;
}

export async function getSourcePack(packId: string) {
  return fetchJson<SourcePackDetail>(`/api/source-packs/${encodeURIComponent(packId)}`);
}

export async function createInstallerProfile(payload: InstallerProfileCreatePayload) {
  return fetchJson<InstallerProfile>("/api/installer-profiles", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getFixtureEndpoints() {
  return clone(Object.values(FIXTURE_ENDPOINT_DETAILS).map(toInventoryItem));
}

export function getFixtureEndpoint(endpointId: string) {
  const endpoint = FIXTURE_ENDPOINT_DETAILS[endpointId];
  return endpoint ? clone(endpoint) : undefined;
}

export function getFixtureEndpointDetails() {
  return clone(Object.values(FIXTURE_ENDPOINT_DETAILS));
}

export function getFixtureApprovalRequests() {
  return clone(FIXTURE_APPROVAL_REQUESTS);
}

export function getFixtureApprovalGrants() {
  return clone(FIXTURE_APPROVAL_GRANTS);
}

export function getFixtureInstallerProfiles() {
  return clone(FIXTURE_INSTALLER_PROFILES);
}

export function getControlLibrary() {
  return clone(CONTROL_LIBRARY);
}

export function platformDisplayName(platform: Platform) {
  return platform === "windows" ? "Windows" : "Linux";
}

export function connectivityDisplay(status: ConnectivityStatus) {
  switch (status) {
    case "online":
      return "Linked";
    case "degraded":
      return "Degraded";
    default:
      return "Pending heartbeat";
  }
}

export function connectivityTone(status: ConnectivityStatus): Tone {
  switch (status) {
    case "online":
      return "success";
    case "degraded":
      return "warning";
    default:
      return "info";
  }
}

export function endpointScore(endpoint: EndpointInventoryItem | EndpointDetail) {
  const summary = endpoint.latest_posture_summary;
  if (!summary) {
    return null;
  }

  const total =
    summary.pass_count +
    summary.fail_count +
    summary.warn_count +
    summary.error_count +
    summary.not_applicable_count;

  if (!total) {
    return null;
  }

  const weighted =
    summary.pass_count +
    summary.warn_count * 0.55 +
    summary.not_applicable_count * 0.7 +
    Math.max(0, summary.error_count * -0.1);

  return Math.max(0, Math.min(100, Math.round((weighted / total) * 100)));
}

export function endpointStateLabel(endpoint: EndpointInventoryItem | EndpointDetail) {
  const summary = endpoint.latest_posture_summary;
  if (!summary) {
    return "Awaiting posture";
  }
  if (summary.error_count > 0 || summary.fail_count > 1) {
    return "Action required";
  }
  if (summary.fail_count > 0 || summary.warn_count > 0 || endpoint.connectivity_status === "degraded") {
    return "Containment drift";
  }
  return "Contained";
}

export function endpointTone(endpoint: EndpointInventoryItem | EndpointDetail): Tone {
  const summary = endpoint.latest_posture_summary;
  if (!summary) {
    return "info";
  }
  if (summary.error_count > 0 || summary.fail_count > 1) {
    return "danger";
  }
  if (summary.fail_count > 0 || summary.warn_count > 0 || endpoint.connectivity_status === "degraded") {
    return "warning";
  }
  return "success";
}

export function fleetSummary(
  endpoints: EndpointInventoryItem[],
  requests: ApprovalRequest[] = [],
  grants: ApprovalGrant[] = [],
): FleetSummary {
  const scores = endpoints.map(endpointScore).filter((score): score is number => typeof score === "number");

  return {
    totalEndpoints: endpoints.length,
    activeEndpoints: endpoints.filter((endpoint) => endpoint.status === "active").length,
    connectedEndpoints: endpoints.filter((endpoint) => endpoint.connectivity_status === "online").length,
    degradedEndpoints: endpoints.filter((endpoint) => endpointTone(endpoint) !== "success").length,
    unscannedEndpoints: endpoints.filter((endpoint) => !endpoint.latest_posture_summary).length,
    pendingApprovals: requests.filter((request) => request.status === "pending").length,
    activeGrants: grants.filter((grant) => grant.status === "approved").length,
    averageScore: scores.length ? Math.round(scores.reduce((total, score) => total + score, 0) / scores.length) : 0,
  };
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

export function approvalStatusTone(status: ApprovalRequestStatus | ApprovalGrantStatus): Tone {
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

export function approvalRiskTone(risk: ApprovalRisk): Tone {
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

export function approvalRequestKindDisplay(kind: ApprovalRequestKind) {
  return kind === "hardening_change" ? "Hardening change" : "Elevated troubleshooting";
}

export function approvalActionDisplay(action: ApprovalAction) {
  switch (action) {
    case "collect_security_context":
      return "Collect security context";
    case "collect_remediation_evidence":
      return "Collect remediation evidence";
    case "inspect_control":
      return "Inspect control";
    case "apply_control":
      return "Apply control";
    case "rollback_control":
      return "Rollback control";
    case "request_elevated_troubleshooting":
      return "Request elevated troubleshooting";
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

export function endpointLabel(endpointId: string, endpoints: EndpointInventoryItem[]) {
  return endpoints.find((endpoint) => endpoint.endpoint_id === endpointId)?.hostname ?? endpointId;
}

export function endpointListDisplay(endpointIds: readonly string[], endpoints: EndpointInventoryItem[]) {
  return endpointIds.map((endpointId) => endpointLabel(endpointId, endpoints)).join(", ");
}

export function installerChannelDisplay(channel: InstallerChannel) {
  return channel === "stable" ? "Stable" : "Preview";
}

export function policyModeDisplay(mode: InstallerPolicyMode) {
  switch (mode) {
    case "observe":
      return "Observe";
    case "safe_auto":
      return "Safe auto";
    case "approval_required":
      return "Approval required";
  }
}

export function policyModeTone(mode: InstallerPolicyMode): Tone {
  switch (mode) {
    case "observe":
      return "info";
    case "safe_auto":
      return "success";
    case "approval_required":
      return "warning";
  }
}

export function titleCaseKey(value: string) {
  return value
    .split(/[._-]/g)
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(" ");
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "Not available";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

export function formatRelativeTime(value: string | null | undefined) {
  if (!value) {
    return "No signal";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const deltaMinutes = Math.round((Date.now() - date.getTime()) / 60000);
  if (Math.abs(deltaMinutes) < 1) {
    return "just now";
  }
  if (Math.abs(deltaMinutes) < 60) {
    return `${Math.abs(deltaMinutes)}m ${deltaMinutes >= 0 ? "ago" : "ahead"}`;
  }
  const hours = Math.round(Math.abs(deltaMinutes) / 60);
  if (hours < 24) {
    return `${hours}h ${deltaMinutes >= 0 ? "ago" : "ahead"}`;
  }
  const days = Math.round(hours / 24);
  return `${days}d ${deltaMinutes >= 0 ? "ago" : "ahead"}`;
}

export function formatLocalInputValue(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const offset = date.getTimezoneOffset();
  const local = new Date(date.getTime() - offset * 60_000);
  return local.toISOString().slice(0, 16);
}

export function futureIso(minutes: number) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

export function localInputToIso(value: string) {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  return date.toISOString();
}

export function approvalDecisionSummary(request: ApprovalRequest) {
  if (!request.decision_by) {
    return "Awaiting human decision";
  }
  return `${approvalStatusDisplay(request.status)} by ${request.decision_by}`;
}

export function describeGrant(grant: ApprovalGrant, endpoints: EndpointInventoryItem[]) {
  return `${grant.reason} • ${endpointListDisplay(grant.endpoint_ids, endpoints)}`;
}

export function aggregateControlRollup(details: EndpointDetail[], requests: ApprovalRequest[]) {
  const map = new Map<string, ControlRollup>();

  for (const detail of details) {
    for (const result of detail.latest_results) {
      const existing = map.get(result.control_key) ?? {
        controlKey: result.control_key,
        title: titleCaseKey(result.control_key),
        failCount: 0,
        warnCount: 0,
        passCount: 0,
        errorCount: 0,
        rebootCount: 0,
        openRequestCount: 0,
        impactedEndpoints: [],
        tone: "info" as Tone,
      };

      existing.impactedEndpoints = Array.from(new Set([...existing.impactedEndpoints, detail.hostname]));
      existing.rebootCount += result.reboot_required ? 1 : 0;

      switch (result.status) {
        case "fail":
          existing.failCount += 1;
          break;
        case "warn":
          existing.warnCount += 1;
          break;
        case "pass":
          existing.passCount += 1;
          break;
        case "error":
          existing.errorCount += 1;
          break;
        case "not_applicable":
          break;
      }

      map.set(result.control_key, existing);
    }
  }

  for (const request of requests.filter((item) => item.status === "pending")) {
    for (const controlId of request.control_ids) {
      const title = titleCaseKey(controlId.replace(/^control\./, ""));
      const existing = map.get(controlId) ?? {
        controlKey: controlId,
        title,
        failCount: 0,
        warnCount: 0,
        passCount: 0,
        errorCount: 0,
        rebootCount: 0,
        openRequestCount: 0,
        impactedEndpoints: [],
        tone: "warning" as Tone,
      };
      existing.openRequestCount += 1;
      map.set(controlId, existing);
    }
  }

  return Array.from(map.values())
    .map((item) => {
      let tone: Tone = "info";
      if (item.errorCount > 0 || item.failCount > 0) {
        tone = "danger";
      } else if (item.warnCount > 0 || item.openRequestCount > 0) {
        tone = "warning";
      } else if (item.passCount > 0) {
        tone = "success";
      }
      return { ...item, tone };
    })
    .sort((left, right) => {
      const leftSeverity = left.errorCount * 4 + left.failCount * 3 + left.warnCount * 2 + left.openRequestCount;
      const rightSeverity = right.errorCount * 4 + right.failCount * 3 + right.warnCount * 2 + right.openRequestCount;
      return rightSeverity - leftSeverity || left.title.localeCompare(right.title);
    });
}
