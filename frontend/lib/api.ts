export type Platform = "windows" | "linux";
export type EndpointState = "healthy" | "degraded" | "needs-attention";
export type ControlStatus = "active" | "review" | "planned";
export type ApprovalStatus = "pending" | "approved";

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

export interface ApprovalRequest {
  id: string;
  target: string;
  requestedBy: string;
  risk: "low" | "medium" | "high";
  status: ApprovalStatus;
  reason: string;
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
    id: "apr_linux_rollout",
    target: "Deploy Linux hardening package",
    requestedBy: "SHA planner",
    risk: "medium",
    status: "pending",
    reason: "Requires sign-off before rolling to ep_demo_linux_01.",
  },
  {
    id: "apr_windows_signing",
    target: "Elevate Windows package signing",
    requestedBy: "Installer lane",
    risk: "high",
    status: "pending",
    reason: "Future package generation placeholder for Windows installers.",
  },
] satisfies readonly ApprovalRequest[];

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

export function approvalStatusDisplay(status: ApprovalStatus) {
  switch (status) {
    case "pending":
      return "Pending";
    case "approved":
      return "Approved";
  }
}

export function approvalStatusTone(status: ApprovalStatus): "warning" | "success" {
  switch (status) {
    case "pending":
      return "warning";
    case "approved":
      return "success";
  }
}
