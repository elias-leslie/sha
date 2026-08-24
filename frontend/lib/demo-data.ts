// Demo fixtures for public demonstrations of the SHA control plane.
//
// Everything in this file is invented. There are no real tenants, sites,
// hostnames, users, or addresses here, and nothing is read from the live
// deployment. Demo mode serves these records instead of contacting the API so
// the console can be shown to another person without exposing a real fleet.

import type {
  Client,
  ConnectivityStatus,
  EndpointInventoryItem,
  EndpointLatestPostureSummary,
  EndpointStatus,
  Location,
  Platform,
} from "./api";

const NOW = Date.parse("2026-08-23T15:40:00Z");

function isoMinutesAgo(minutes: number) {
  return new Date(NOW - minutes * 60_000).toISOString();
}

export const DEMO_CLIENTS: readonly Client[] = [
  {
    client_id: "tenant_northwind",
    key: "northwind",
    name: "Northwind Trading Co.",
    state: "active",
    is_system: false,
    created_at: "2026-01-12T14:00:00Z",
    updated_at: "2026-08-20T09:12:00Z",
  },
  {
    client_id: "tenant_cascade",
    key: "cascade-ortho",
    name: "Cascade Orthopedics",
    state: "active",
    is_system: false,
    created_at: "2026-02-03T16:30:00Z",
    updated_at: "2026-08-21T11:45:00Z",
  },
  {
    client_id: "tenant_vela",
    key: "vela-legal",
    name: "Vela Legal Group",
    state: "active",
    is_system: false,
    created_at: "2026-03-19T13:20:00Z",
    updated_at: "2026-08-22T18:05:00Z",
  },
  {
    client_id: "tenant_harborpoint",
    key: "harbor-point",
    name: "Harbor Point School District",
    state: "active",
    is_system: false,
    created_at: "2026-04-07T15:10:00Z",
    updated_at: "2026-08-23T08:30:00Z",
  },
];

export const DEMO_LOCATIONS: readonly Location[] = [
  loc("site_northwind_hq", "tenant_northwind", "hq", "Headquarters — Rivermont"),
  loc("site_northwind_dc", "tenant_northwind", "dc-east", "Distribution Center — East"),
  loc("site_cascade_clinic", "tenant_cascade", "clinic-main", "Main Clinic"),
  loc("site_cascade_surgery", "tenant_cascade", "surgery-center", "Surgery Center"),
  loc("site_vela_office", "tenant_vela", "downtown", "Downtown Office"),
  loc("site_harborpoint_admin", "tenant_harborpoint", "admin", "Administration Building"),
  loc("site_harborpoint_north", "tenant_harborpoint", "north-campus", "North Campus"),
];

function loc(location_id: string, client_id: string, key: string, name: string): Location {
  return {
    location_id,
    client_id,
    key,
    name,
    state: "active",
    is_system: false,
    created_at: "2026-04-18T18:00:00Z",
    updated_at: "2026-08-20T18:00:00Z",
  };
}

function posture(
  pass_count: number,
  fail_count: number,
  warn_count: number,
  error_count: number,
  not_applicable_count: number,
  reboot_required_count = 0,
  minutesAgo = 20,
): EndpointLatestPostureSummary {
  return {
    snapshot_id: `snap_demo_${pass_count}_${fail_count}_${warn_count}_${minutesAgo}`,
    observed_at: isoMinutesAgo(minutesAgo),
    platform_profile: "demo",
    pass_count,
    fail_count,
    warn_count,
    error_count,
    not_applicable_count,
    reboot_required_count,
  };
}

type DemoEndpointSeed = {
  id: string;
  hostname: string;
  platform: Platform;
  platform_version: string;
  client_id: string;
  location_id: string;
  status: EndpointStatus;
  connectivity: ConnectivityStatus;
  minutesAgo: number;
  summary: EndpointLatestPostureSummary | null;
  capabilities?: string[];
};

const SEEDS: DemoEndpointSeed[] = [
  // Northwind Trading Co. — Headquarters
  seed("nw-fin-ws-014", "windows", "Windows 11 Pro 24H2", "tenant_northwind", "site_northwind_hq", "active", "online", 4, posture(21, 0, 1, 0, 2)),
  seed("nw-fin-ws-018", "windows", "Windows 11 Pro 24H2", "tenant_northwind", "site_northwind_hq", "active", "online", 7, posture(19, 2, 2, 0, 1, 1)),
  seed("nw-exec-mbp-03", "macos", "macOS 15.6 Sequoia", "tenant_northwind", "site_northwind_hq", "active", "online", 11, posture(18, 0, 3, 0, 3)),
  seed("nw-app-srv-01", "windows", "Windows Server 2022", "tenant_northwind", "site_northwind_hq", "active", "online", 3, posture(23, 0, 0, 0, 1)),
  seed("nw-edge-fw-01", "linux", "Debian 12.7", "tenant_northwind", "site_northwind_hq", "active", "online", 6, posture(22, 0, 1, 0, 1)),
  // Northwind — Distribution Center
  seed("nw-dc-scan-07", "windows", "Windows 10 IoT Enterprise", "tenant_northwind", "site_northwind_dc", "active", "degraded", 46, posture(14, 4, 3, 1, 2, 1)),
  seed("nw-dc-ws-021", "windows", "Windows 11 Pro 24H2", "tenant_northwind", "site_northwind_dc", "active", "online", 9, posture(20, 1, 1, 0, 2)),
  // Cascade Orthopedics — Main Clinic
  seed("cas-clin-ws-102", "windows", "Windows 11 Pro 24H2", "tenant_cascade", "site_cascade_clinic", "active", "online", 5, posture(22, 0, 1, 0, 1)),
  seed("cas-clin-ws-107", "windows", "Windows 11 Pro 24H2", "tenant_cascade", "site_cascade_clinic", "active", "online", 12, posture(17, 3, 2, 0, 2, 1)),
  seed("cas-img-srv-02", "linux", "Ubuntu 24.04 LTS", "tenant_cascade", "site_cascade_clinic", "active", "online", 2, posture(24, 0, 0, 0, 1)),
  seed("cas-rec-mac-05", "macos", "macOS 14.7 Sonoma", "tenant_cascade", "site_cascade_clinic", "stale", "degraded", 2_880, posture(15, 2, 4, 1, 2)),
  // Cascade — Surgery Center
  seed("cas-surg-ws-201", "windows", "Windows 11 Pro 24H2", "tenant_cascade", "site_cascade_surgery", "active", "online", 8, posture(21, 0, 2, 0, 1)),
  seed("cas-surg-srv-01", "windows", "Windows Server 2022", "tenant_cascade", "site_cascade_surgery", "active", "online", 4, posture(23, 1, 0, 0, 1)),
  // Vela Legal Group
  seed("vela-atty-mbp-11", "macos", "macOS 15.6 Sequoia", "tenant_vela", "site_vela_office", "active", "online", 6, posture(20, 0, 2, 0, 2)),
  seed("vela-atty-mbp-14", "macos", "macOS 15.5 Sequoia", "tenant_vela", "site_vela_office", "active", "online", 15, posture(18, 1, 3, 0, 2)),
  seed("vela-para-ws-08", "windows", "Windows 11 Pro 23H2", "tenant_vela", "site_vela_office", "active", "online", 10, posture(19, 2, 1, 0, 2, 1)),
  seed("vela-dms-srv-01", "linux", "Rocky Linux 9.4", "tenant_vela", "site_vela_office", "active", "online", 3, posture(24, 0, 1, 0, 0)),
  seed("vela-vpn-gw-01", "linux", "Debian 12.7", "tenant_vela", "site_vela_office", "active", "online", 5, posture(23, 0, 0, 0, 1)),
  // Harbor Point School District — Administration
  seed("hp-admin-ws-041", "windows", "Windows 11 Education 24H2", "tenant_harborpoint", "site_harborpoint_admin", "active", "online", 7, posture(20, 1, 2, 0, 2)),
  seed("hp-admin-ws-046", "windows", "Windows 11 Education 24H2", "tenant_harborpoint", "site_harborpoint_admin", "pending", null, 1, null),
  seed("hp-sis-srv-01", "linux", "Ubuntu 24.04 LTS", "tenant_harborpoint", "site_harborpoint_admin", "active", "online", 4, posture(22, 0, 2, 0, 1)),
  // Harbor Point — North Campus
  seed("hp-lab-ws-311", "windows", "Windows 11 Education 24H2", "tenant_harborpoint", "site_harborpoint_north", "active", "degraded", 38, posture(13, 5, 3, 1, 2, 1)),
  seed("hp-lab-ws-318", "windows", "Windows 11 Education 24H2", "tenant_harborpoint", "site_harborpoint_north", "active", "online", 13, posture(19, 1, 2, 0, 2)),
  seed("hp-media-mac-02", "macos", "macOS 14.7 Sonoma", "tenant_harborpoint", "site_harborpoint_north", "active", "online", 22, posture(17, 0, 4, 0, 3)),
];

function seed(
  hostname: string,
  platform: Platform,
  platform_version: string,
  client_id: string,
  location_id: string,
  status: EndpointStatus,
  connectivity: ConnectivityStatus,
  minutesAgo: number,
  summary: EndpointLatestPostureSummary | null,
): DemoEndpointSeed {
  return {
    id: `ep_demo_${hostname.replace(/-/g, "_")}`,
    hostname,
    platform,
    platform_version,
    client_id,
    location_id,
    status,
    connectivity,
    minutesAgo,
    summary,
  };
}

const CAPABILITIES_BY_PLATFORM: Record<Platform, string[]> = {
  windows: ["posture.report", "control.inspect", "control.apply", "context.collect", "terminal.session"],
  linux: ["posture.report", "control.inspect", "control.apply", "context.collect", "terminal.session"],
  macos: ["posture.report", "control.inspect", "context.collect"],
};

export const DEMO_ENDPOINTS: readonly EndpointInventoryItem[] = SEEDS.map((entry) => ({
  endpoint_id: entry.id,
  hostname: entry.hostname,
  platform: entry.platform,
  platform_version: entry.platform_version,
  agent_version: "0.9.4",
  client_id: entry.client_id,
  location_id: entry.location_id,
  tenant_id: entry.client_id,
  site_id: entry.location_id,
  status: entry.status,
  connectivity_status: entry.connectivity,
  last_seen_at: isoMinutesAgo(entry.minutesAgo),
  last_heartbeat_at: entry.status === "pending" ? null : isoMinutesAgo(entry.minutesAgo),
  created_at: "2026-05-02T12:00:00Z",
  updated_at: isoMinutesAgo(entry.minutesAgo),
  last_platform_profile: entry.summary ? entry.summary.platform_profile : null,
  declared_capabilities: CAPABILITIES_BY_PLATFORM[entry.platform],
  execution_hooks: { posture: true, control: entry.platform !== "macos" },
  latest_posture_summary: entry.summary,
}));

export const DEMO_AUTH_SESSION = {
  subject: "demo:operator",
  display_name: "Demo operator",
  status: "active",
  authentication_method: "demo",
  bindings: [
    {
      binding_id: "binding_demo_global",
      role: "READ_ONLY",
      scope_type: "global" as const,
      client_id: null,
      location_id: null,
      permissions: ["endpoints:read", "controls:read", "approvals:read", "installers:read"],
    },
  ],
  csrf_token: null,
};

// Invented primary-user labels for the demo fleet. Real deployments resolve
// this from directory data; nothing here corresponds to a real person.
export const DEMO_PRIMARY_USERS: Record<string, string> = {
  "nw-fin-ws-014": "a.okafor (Finance)",
  "nw-fin-ws-018": "r.delgado (Finance)",
  "nw-exec-mbp-03": "j.whitfield (Exec)",
  "nw-app-srv-01": "svc_apphost",
  "nw-edge-fw-01": "svc_netedge",
  "nw-dc-scan-07": "shiftops (Warehouse)",
  "nw-dc-ws-021": "m.barros (Logistics)",
  "cas-clin-ws-102": "t.nakamura (Clinical)",
  "cas-clin-ws-107": "p.ellery (Clinical)",
  "cas-img-srv-02": "svc_imaging",
  "cas-rec-mac-05": "front-desk (Shared)",
  "cas-surg-ws-201": "d.varga (Surgical)",
  "cas-surg-srv-01": "svc_surgsched",
  "vela-atty-mbp-11": "k.underwood (Partner)",
  "vela-atty-mbp-14": "s.rahimi (Associate)",
  "vela-para-ws-08": "n.castellanos (Paralegal)",
  "vela-dms-srv-01": "svc_docstore",
  "vela-vpn-gw-01": "svc_vpngw",
  "hp-admin-ws-041": "b.iyer (Registrar)",
  "hp-admin-ws-046": "unassigned",
  "hp-sis-srv-01": "svc_sis",
  "hp-lab-ws-311": "lab-station (Shared)",
  "hp-lab-ws-318": "lab-station (Shared)",
  "hp-media-mac-02": "c.mbeki (Media Lab)",
};
