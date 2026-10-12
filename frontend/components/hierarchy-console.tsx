"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  type EndpointInventoryItem,
  createClient,
  createLocation,
  endpointScore,
  endpointTone,
  getDemoEndpoints,
  isDemoMode,
  listEndpoints,
} from "../lib/api";
import { DEMO_PRIMARY_USERS } from "../lib/demo-data";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";
import { hierarchyDisplayName, useScope } from "./scope-context";

type PlatformFilter = "all" | "windows" | "linux" | "macos";
type InspectorTab = "overview" | "checks" | "audit";

// Primary-user labels are supplied by the deployment, never hard-coded here.
// A checked-in map would publish real operator names and internal hostnames in
// a public repository, so unmapped hosts fall back to a neutral principal.
// Demo mode layers in invented labels so the column reads realistically.
const HOST_PRIMARY_USERS: Record<string, string> = {};

export default function HierarchyConsole({ demoMode = isDemoMode() }: { demoMode?: boolean }) {
  const primaryUsers = demoMode ? { ...HOST_PRIMARY_USERS, ...DEMO_PRIMARY_USERS } : HOST_PRIMARY_USERS;
  const { clients, locations, loading: hierarchyLoading, error: hierarchyError, setScope } = useScope();

  const [endpoints, setEndpoints] = useState<EndpointInventoryItem[]>([]);
  const [endpointsLoading, setEndpointsLoading] = useState(true);
  const [endpointsError, setEndpointsError] = useState<string | null>(null);

  // Active selections
  const [selectedClientId, setSelectedClientId] = useState<string | null>(null);
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(null);
  const [isExpandedRealEstate, setIsExpandedRealEstate] = useState(false);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [platformFilter, setPlatformFilter] = useState<PlatformFilter>("all");

  // Inspector tab
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("checks");

  // Selection Checkboxes state
  const [selectedHostIds, setSelectedHostIds] = useState<Set<string>>(new Set());

  // Creation Modals state
  const [showClientModal, setShowClientModal] = useState(false);
  const [newClientName, setNewClientName] = useState("");
  const [newClientKey, setNewClientKey] = useState("");
  const [clientCreatePending, setClientCreatePending] = useState(false);
  const [clientCreateError, setClientCreateError] = useState<string | null>(null);

  const [showLocationModal, setShowLocationModal] = useState(false);
  const [newLocClientId, setNewLocClientId] = useState("");
  const [newLocName, setNewLocName] = useState("");
  const [newLocKey, setNewLocKey] = useState("");
  const [locCreatePending, setLocCreatePending] = useState(false);
  const [locCreateError, setLocCreateError] = useState<string | null>(null);

  // Action status message
  const [actionFeedback, setActionFeedback] = useState<{ type: "success" | "danger" | "info"; message: string } | null>(null);

  // Load endpoints
  useEffect(() => {
    if (demoMode) {
      setEndpoints(getDemoEndpoints());
      setEndpointsLoading(false);
      return;
    }
    let cancelled = false;
    async function loadData() {
      setEndpointsLoading(true);
      setEndpointsError(null);
      try {
        const response = await listEndpoints();
        if (!cancelled) {
          const list = Array.isArray(response)
            ? response
            : ((response as unknown) as { items?: EndpointInventoryItem[] })?.items || [];
          setEndpoints(list);
        }
      } catch (err) {
        if (!cancelled) {
          setEndpointsError(err instanceof Error ? err.message : "Failed to load endpoints.");
        }
      } finally {
        if (!cancelled) {
          setEndpointsLoading(false);
        }
      }
    }
    void loadData();
    return () => {
      cancelled = true;
    };
  }, [demoMode]);

  // The inventory opens collapsed. Auto-expanding the first host pushed the
  // rest of the fleet below the fold on every visit, so detail is opened on
  // demand instead.

  // Client and location lookup maps
  const clientMap = useMemo(() => new Map(clients.map((c) => [c.client_id, c])), [clients]);
  const locationMap = useMemo(() => new Map(locations.map((l) => [l.location_id, l])), [locations]);

  // Endpoint count per client
  const endpointCountByClient = useMemo(() => {
    const map = new Map<string, number>();
    for (const ep of endpoints) {
      if (ep.client_id) {
        map.set(ep.client_id, (map.get(ep.client_id) || 0) + 1);
      }
    }
    return map;
  }, [endpoints]);

  // Filtered endpoints master list
  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      // Client filter
      if (selectedClientId && ep.client_id !== selectedClientId) {
        return false;
      }
      // Platform filter
      if (platformFilter !== "all" && ep.platform !== platformFilter) {
        return false;
      }
      // Text search
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const clientName = (clientMap.get(ep.client_id || "")?.name || "").toLowerCase();
        const siteName = (locationMap.get(ep.location_id || "")?.name || "").toLowerCase();
        const user = (primaryUsers[ep.hostname] || primaryUsers[ep.endpoint_id] || "").toLowerCase();
        const match =
          ep.hostname.toLowerCase().includes(q) ||
          ep.endpoint_id.toLowerCase().includes(q) ||
          clientName.includes(q) ||
          siteName.includes(q) ||
          user.includes(q);
        if (!match) return false;
      }
      return true;
    });
  }, [endpoints, selectedClientId, platformFilter, searchQuery, clientMap, locationMap]);

  // Currently inspected endpoint
  const inspectedEndpoint = useMemo(() => {
    if (selectedEndpointId) {
      return endpoints.find((e) => e.endpoint_id === selectedEndpointId) || null;
    }
    return null;
  }, [selectedEndpointId, endpoints]);

  const inspectedScore = useMemo(() => {
    if (!inspectedEndpoint) return null;
    return endpointScore(inspectedEndpoint);
  }, [inspectedEndpoint]);

  // Toggle selection
  const toggleSelectHost = (id: string) => {
    setSelectedHostIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedHostIds.size === filteredEndpoints.length) {
      setSelectedHostIds(new Set());
    } else {
      setSelectedHostIds(new Set(filteredEndpoints.map((e) => e.endpoint_id)));
    }
  };

  // Client Creation
  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newClientName.trim() || !newClientKey.trim()) return;
    setClientCreatePending(true);
    setClientCreateError(null);
    try {
      if (!demoMode) {
        await createClient({ name: newClientName.trim(), key: newClientKey.trim() });
      }
      setShowClientModal(false);
      setNewClientName("");
      setNewClientKey("");
      setActionFeedback({ type: "success", message: "Client company registered successfully." });
      window.location.reload();
    } catch (err) {
      setClientCreateError(err instanceof Error ? err.message : "Failed to create client company.");
    } finally {
      setClientCreatePending(false);
    }
  };

  // Location Creation
  const handleCreateLocation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newLocClientId || !newLocName.trim() || !newLocKey.trim()) return;
    setLocCreatePending(true);
    setLocCreateError(null);
    try {
      if (!demoMode) {
        await createLocation(newLocClientId, { name: newLocName.trim(), key: newLocKey.trim() });
      }
      setShowLocationModal(false);
      setNewLocName("");
      setNewLocKey("");
      setActionFeedback({ type: "success", message: "Site location added successfully." });
      window.location.reload();
    } catch (err) {
      setLocCreateError(err instanceof Error ? err.message : "Failed to create site location.");
    } finally {
      setLocCreatePending(false);
    }
  };

  // Render Tab Navigation & Header Bar for Device Inspector
  const renderDetailHeader = (ep: EndpointInventoryItem, score: number | null, isMaximized: boolean) => {
    const client = clientMap.get(ep.client_id || "");
    const location = locationMap.get(ep.location_id || "");
    const clientName = client ? hierarchyDisplayName(client) : ep.client_id || "Unassigned";
    const siteName = location ? hierarchyDisplayName(location) : ep.location_id || "Main Office";
    const user = primaryUsers[ep.hostname] || primaryUsers[ep.endpoint_id] || "System Principal";

    return (
      <div className="inline-detail-header">
        <div className="inline-detail-identity">
          <span className="inline-detail-icon">
            {ep.platform === "windows" ? "🪟" : ep.platform === "macos" ? "🍏" : "🐧"}
          </span>
          <div>
            <div className="inline-detail-title-group">
              <h3 className="inline-detail-title">{ep.hostname}</h3>
              <Badge tone={endpointTone(ep)}>
                Score: {score !== null ? `${score}%` : "Pending"}
              </Badge>
              <span className="tone tone--info" style={{ fontSize: "0.68rem" }}>
                ID: {ep.endpoint_id}
              </span>
            </div>
            <p className="inline-detail-meta">
              Client: <strong>{clientName}</strong> • Site: <strong>{siteName}</strong> • Primary User: <strong>{user}</strong>
            </p>
          </div>
        </div>

        <div className="inline-detail-actions-group">
          <div className="inline-detail-tabs">
            <button
              className={`action-button ${inspectorTab === "checks" ? "action-button--primary" : "action-button--ghost"}`}
              style={{ fontSize: "0.76rem", padding: "0.3rem 0.65rem" }}
              type="button"
              onClick={() => setInspectorTab("checks")}
            >
              🛡️ Compliance Checks
            </button>
            <button
              className={`action-button ${inspectorTab === "overview" ? "action-button--primary" : "action-button--ghost"}`}
              style={{ fontSize: "0.76rem", padding: "0.3rem 0.65rem" }}
              type="button"
              onClick={() => setInspectorTab("overview")}
            >
              📊 Specs & Identity
            </button>
            <button
              className={`action-button ${inspectorTab === "audit" ? "action-button--primary" : "action-button--ghost"}`}
              style={{ fontSize: "0.76rem", padding: "0.3rem 0.65rem" }}
              type="button"
              onClick={() => setInspectorTab("audit")}
            >
              📜 Recent Activity
            </button>
          </div>

          <div style={{ display: "flex", gap: "0.4rem", alignItems: "center" }}>
            {!isMaximized ? (
              <button
                className="action-button action-button--primary"
                style={{ fontSize: "0.75rem", padding: "0.3rem 0.65rem" }}
                title="Expand view to take up maximum web page real estate"
                type="button"
                onClick={() => setIsExpandedRealEstate(true)}
              >
                🗖 Expand Real Estate
              </button>
            ) : (
              <button
                className="action-button action-button--secondary"
                style={{ fontSize: "0.75rem", padding: "0.3rem 0.65rem" }}
                title="Return to inline view"
                type="button"
                onClick={() => setIsExpandedRealEstate(false)}
              >
                🗕 Restore Inline View
              </button>
            )}
            <button
              className="action-button action-button--ghost"
              style={{ fontSize: "0.85rem", padding: "0.3rem 0.5rem" }}
              title="Close details"
              type="button"
              onClick={() => {
                setIsExpandedRealEstate(false);
                setSelectedEndpointId(null);
              }}
            >
              ✕
            </button>
          </div>
        </div>
      </div>
    );
  };

  // Render Active Tab Body for Device Inspector
  const renderTabContent = (ep: EndpointInventoryItem, score: number | null) => {
    switch (inspectorTab) {
      case "checks":
        return (
          <div style={{ display: "grid", gap: "0.8rem" }}>
            <h4 style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
              Latest posture summary
            </h4>
            {ep.latest_posture_summary ? (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                <span className="tone tone--success">Pass {ep.latest_posture_summary.pass_count}</span>
                <span className="tone tone--danger">Fail {ep.latest_posture_summary.fail_count}</span>
                <span className="tone tone--warning">Warn {ep.latest_posture_summary.warn_count}</span>
                <span className="tone tone--info">Not applicable {ep.latest_posture_summary.not_applicable_count}</span>
              </div>
            ) : (
              <EmptyState title="No posture evidence" body="This endpoint has not reported a posture snapshot yet." />
            )}
            <p style={{ fontSize: "0.78rem", color: "var(--muted)", margin: 0 }}>
              Per-control results and approval-gated response actions are on the{" "}
              <a href={`/endpoints/${ep.endpoint_id}`}>endpoint detail page</a>.
            </p>
          </div>
        );

      case "overview":
        return (
          <div className="dashboard-grid dashboard-grid--three-up" style={{ gap: "0.8rem" }}>
            <StatCard
              label="Host Platform"
              meta="OS Kernel"
              value={ep.platform_version || ep.platform}
            />
            <StatCard
              label="Agent Version"
              meta="Control Plane Client"
              value={`v${ep.agent_version}`}
            />
            <StatCard
              label="Connectivity"
              meta="Heartbeat Signal"
              value={(ep.connectivity_status || "offline").toUpperCase()}
            />
          </div>
        );

      case "audit":
        return (
          <div style={{ display: "grid", gap: "0.5rem" }}>
            <h4 style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
              Recent activity for {ep.hostname}
            </h4>
            <div className="timeline-list">
              {ep.latest_posture_summary ? (
                <div className="timeline-list__item">
                  <span className="timeline-list__dot timeline-list__dot--info" />
                  <div>
                    <strong>Posture snapshot recorded</strong>
                    <p>
                      Observed {ep.latest_posture_summary.observed_at}
                      {score !== null ? ` • Posture score ${score}%` : ""}
                    </p>
                  </div>
                </div>
              ) : null}
              <div className="timeline-list__item">
                <span className="timeline-list__dot timeline-list__dot--success" />
                <div>
                  <strong>Last heartbeat</strong>
                  <p>
                    {ep.last_heartbeat_at ?? "No heartbeat yet"} • Agent version v{ep.agent_version} • Status: {ep.status}
                  </p>
                </div>
              </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="hierarchy-console-container" style={{ display: "grid", gap: "1rem" }}>
      {actionFeedback && (
        <div
          className={`inline-feedback inline-feedback--${actionFeedback.type}`}
          style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
        >
          <span>{actionFeedback.message}</span>
          <button
            style={{ background: "none", border: "none", color: "inherit", cursor: "pointer" }}
            type="button"
            onClick={() => setActionFeedback(null)}
          >
            ✕
          </button>
        </div>
      )}

      {/* Main RMM Grid Layout: Fixed Left Client Sidebar + Master Endpoint Table */}
      <div
        className="rmm-layout"
        style={{
          display: "grid",
          gridTemplateColumns: "264px 1fr",
          gap: "1.2rem",
          minHeight: "540px",
        }}
      >
        {/* Left Sidebar: Client Organizations Selector */}
        <Panel>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.8rem" }}>
            <h3 style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
              Clients & Companies
            </h3>
            <button
              className="action-button action-button--ghost"
              style={{ fontSize: "0.7rem", padding: "0.2rem 0.4rem" }}
              title="Register Client"
              type="button"
              onClick={() => setShowClientModal(true)}
            >
              + Add
            </button>
          </div>

          <div style={{ display: "grid", gap: "0.3rem" }}>
            {/* All Clients Entry */}
            <div
              className="tree-item"
              data-selected={selectedClientId === null ? "true" : "false"}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "0.55rem 0.75rem",
                borderRadius: "10px",
                border: selectedClientId === null ? "1px solid var(--accent-strong)" : "1px solid var(--border)",
                background: selectedClientId === null ? "rgba(255, 208, 138, 0.12)" : "rgba(255, 255, 255, 0.02)",
                cursor: "pointer",
                fontWeight: 600,
                fontSize: "0.83rem",
              }}
              onClick={() => {
                setSelectedClientId(null);
                setScope({ client_id: null, location_id: null });
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span>🌐</span>
                <span>All Clients</span>
              </div>
              <span className="tone tone--info" style={{ fontSize: "0.68rem" }}>
                {endpoints.length}
              </span>
            </div>

            {/* Individual Client List */}
            {clients.map((client) => {
              const isSelected = selectedClientId === client.client_id;
              const count = endpointCountByClient.get(client.client_id) || 0;
              const displayName = hierarchyDisplayName(client);

              return (
                <div
                  key={client.client_id}
                  className="tree-item"
                  data-selected={isSelected ? "true" : "false"}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.5rem 0.75rem",
                    borderRadius: "10px",
                    border: isSelected ? "1px solid var(--accent-strong)" : "1px solid var(--border)",
                    background: isSelected ? "rgba(255, 208, 138, 0.1)" : "rgba(255, 255, 255, 0.01)",
                    cursor: "pointer",
                    fontSize: "0.82rem",
                  }}
                  onClick={() => {
                    setSelectedClientId(client.client_id);
                    setScope({ client_id: client.client_id, location_id: null });
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.45rem", overflow: "hidden" }}>
                    <span>🏢</span>
                    <span
                      style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        fontWeight: isSelected ? 600 : 400,
                      }}
                    >
                      {displayName}
                    </span>
                  </div>
                  <span className="tone tone--info" style={{ fontSize: "0.66rem" }}>
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        </Panel>

        {/* Right Main Region: Filter Bar + Master Systems Table */}
        <div style={{ display: "grid", gap: "1rem", alignContent: "start" }}>
          {/* Top Filter Bar & Platform Selector */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "rgba(255, 255, 255, 0.02)",
              padding: "0.7rem 1rem",
              borderRadius: "14px",
              border: "1px solid var(--border)",
              flexWrap: "wrap",
              gap: "0.8rem",
            }}
          >
            {/* Search and Platform Tabs */}
            <div style={{ display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
              <input
                className="field__input"
                placeholder="Search hostname, client, site, user..."
                style={{ width: "280px", padding: "0.42rem 0.8rem", fontSize: "0.82rem" }}
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />

              <div style={{ display: "flex", gap: "0.3rem", background: "rgba(0,0,0,0.3)", padding: "0.2rem", borderRadius: "8px" }}>
                {(["all", "windows", "linux", "macos"] as PlatformFilter[]).map((pf) => (
                  <button
                    key={pf}
                    type="button"
                    style={{
                      background: platformFilter === pf ? "var(--accent-strong)" : "none",
                      color: platformFilter === pf ? "#000" : "var(--foreground)",
                      border: "none",
                      padding: "0.25rem 0.6rem",
                      borderRadius: "6px",
                      fontSize: "0.76rem",
                      fontWeight: platformFilter === pf ? 600 : 400,
                      cursor: "pointer",
                      textTransform: "capitalize",
                    }}
                    onClick={() => setPlatformFilter(pf)}
                  >
                    {pf === "all" ? "All Systems" : pf === "windows" ? "🪟 Windows" : pf === "linux" ? "🐧 Linux" : "🍏 macOS"}
                  </button>
                ))}
              </div>
            </div>

            {/* Right Action Buttons */}
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <button
                className="action-button action-button--secondary"
                style={{ fontSize: "0.76rem", padding: "0.35rem 0.7rem" }}
                type="button"
                onClick={() => setShowClientModal(true)}
              >
                + Register Client
              </button>
              <button
                className="action-button action-button--secondary"
                style={{ fontSize: "0.76rem", padding: "0.35rem 0.7rem" }}
                type="button"
                onClick={() => setShowLocationModal(true)}
              >
                + Add Site
              </button>
            </div>
          </div>

          {/* Master RMM Systems & Compliance Table */}
          <Panel style={{ padding: 0, overflowX: "auto" }}>
            {endpointsLoading || hierarchyLoading ? (
              <div style={{ padding: "2rem", textAlign: "center", color: "var(--muted)" }}>
                Loading system posture inventory...
              </div>
            ) : filteredEndpoints.length === 0 ? (
              <div style={{ padding: "2rem" }}>
                <EmptyState
                  body="No host systems match the active client or filter criteria."
                  title="No systems found"
                />
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem", textAlign: "left" }}>
                  <thead>
                    <tr
                      style={{
                        background: "rgba(255, 255, 255, 0.03)",
                        borderBottom: "1px solid var(--border)",
                        color: "var(--muted)",
                        textTransform: "uppercase",
                        fontSize: "0.7rem",
                        letterSpacing: "0.06em",
                      }}
                    >
                      <th style={{ padding: "0.35rem 0.6rem", width: "32px" }}>
                        <input
                          checked={selectedHostIds.size === filteredEndpoints.length && filteredEndpoints.length > 0}
                          type="checkbox"
                          onChange={toggleSelectAll}
                        />
                      </th>
                      <th style={{ padding: "0.35rem 0.6rem", width: "40px" }}>OS</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>Status</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>Client Company</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>Site / Location</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>Hostname</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>Primary User</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>OS Version</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>Posture Score</th>
                      <th style={{ padding: "0.35rem 0.6rem" }}>Signal</th>
                      <th style={{ padding: "0.35rem 0.6rem", textAlign: "right" }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEndpoints.map((ep) => {
                      const isInspected = inspectedEndpoint?.endpoint_id === ep.endpoint_id;
                      const isChecked = selectedHostIds.has(ep.endpoint_id);
                      const client = clientMap.get(ep.client_id || "");
                      const location = locationMap.get(ep.location_id || "");
                      const clientName = client ? hierarchyDisplayName(client) : ep.client_id || "Unassigned";
                      const siteName = location ? hierarchyDisplayName(location) : ep.location_id || "Main Office";
                      const user = primaryUsers[ep.hostname] || primaryUsers[ep.endpoint_id] || "System Principal";
                      const score = endpointScore(ep);
                      const tone = endpointTone(ep);

                      return (
                        <React.Fragment key={ep.endpoint_id}>
                          <tr
                            style={{
                              borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                              background: isInspected
                                ? "rgba(56, 189, 248, 0.12)"
                                : isChecked
                                  ? "rgba(255, 255, 255, 0.03)"
                                  : "transparent",
                              cursor: "pointer",
                            }}
                            onClick={() => setSelectedEndpointId((prev) => (prev === ep.endpoint_id ? null : ep.endpoint_id))}
                          >
                            <td style={{ padding: "0.35rem 0.6rem" }} onClick={(e) => e.stopPropagation()}>
                              <input
                                checked={isChecked}
                                type="checkbox"
                                onChange={() => toggleSelectHost(ep.endpoint_id)}
                              />
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem", fontSize: "1.1rem" }}>
                              {ep.platform === "windows"
                                ? "🪟"
                                : ep.platform === "macos"
                                  ? "🍏"
                                  : ep.platform === "linux"
                                    ? "🐧"
                                    : ep.platform === "router"
                                      ? "🌐"
                                      : ep.platform === "switch"
                                        ? "🔌"
                                        : ep.platform === "nas" || ep.platform === "san"
                                          ? "💾"
                                          : ep.platform === "camera"
                                            ? "📷"
                                            : ep.platform === "printer"
                                              ? "🖨️"
                                              : "💻"}
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem" }}>
                              <Badge tone={tone}>
                                {score !== null && score >= 90
                                  ? "✔ Compliant"
                                  : score !== null && score >= 75
                                    ? "⚠️ Audit Needed"
                                    : "❌ Drift Detected"}
                              </Badge>
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem", fontWeight: 500 }} title={clientName}>
                              {clientName}
                            </td>
                            <td
                              style={{ padding: "0.35rem 0.6rem", color: "var(--muted)" }}
                              title={siteName}
                            >
                              📍 {siteName}
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem" }}>
                              <strong style={{ color: "var(--accent-strong)" }}>
                                {isInspected ? "▼ " : "▶ "}
                                {ep.hostname}
                              </strong>
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem", fontSize: "0.78rem" }}>{user}</td>
                            <td style={{ padding: "0.35rem 0.6rem", color: "var(--muted)" }}>
                              {ep.platform_version || ep.platform}
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem" }}>
                              <strong style={{ fontSize: "0.85rem" }}>{score !== null ? `${score}%` : "--"}</strong>
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem" }}>
                              <span className="tone tone--success" style={{ fontSize: "0.68rem" }}>
                                ● {ep.connectivity_status}
                              </span>
                            </td>
                            <td style={{ padding: "0.35rem 0.6rem", textAlign: "right" }} onClick={(e) => e.stopPropagation()}>
                              <button
                                className={`action-button ${isInspected ? "action-button--primary" : "action-button--ghost"}`}
                                style={{ fontSize: "0.72rem", padding: "0.25rem 0.5rem" }}
                                type="button"
                                onClick={() => setSelectedEndpointId((prev) => (prev === ep.endpoint_id ? null : ep.endpoint_id))}
                              >
                                {isInspected ? "Collapse ▲" : "Details ▼"}
                              </button>
                            </td>
                          </tr>

                          {/* Inline Detail Expansion Directly Beneath Selected Device */}
                          {isInspected && (
                            <tr className="inline-detail-row">
                              <td colSpan={11} style={{ padding: 0 }}>
                                <div className="inline-detail-container">
                                  {renderDetailHeader(ep, score, false)}
                                  <div className="inline-detail-body">
                                    {renderTabContent(ep, score)}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
      </div>

      {/* Expanded Real Estate Workspace Modal Overlay */}
      {isExpandedRealEstate && inspectedEndpoint && (
        <div className="expanded-workspace-backdrop" onClick={() => setIsExpandedRealEstate(false)}>
          <div className="expanded-workspace-modal" onClick={(e) => e.stopPropagation()}>
            {renderDetailHeader(inspectedEndpoint, inspectedScore, true)}
            <div className="expanded-workspace-body">
              {renderTabContent(inspectedEndpoint, inspectedScore)}
            </div>
          </div>
        </div>
      )}

      {/* Modal: Register Client Company */}
      {showClientModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
            padding: "1rem",
          }}
        >
          <div
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: "16px",
              padding: "1.5rem",
              maxWidth: "460px",
              width: "100%",
              display: "grid",
              gap: "1.2rem",
            }}
          >
            <SectionHeader
              description="Register a client company or corporate organization entity."
              eyebrow="Client Management"
              title="Register Client Company"
            />
            {clientCreateError && (
              <p className="inline-feedback inline-feedback--danger">{clientCreateError}</p>
            )}
            <form onSubmit={handleCreateClient} style={{ display: "grid", gap: "1rem" }}>
              <label className="field">
                <span className="field__label">Client Company Name</span>
                <input
                  className="field__control"
                  placeholder="e.g. Acme Financial Group"
                  required
                  type="text"
                  value={newClientName}
                  onChange={(e) => {
                    setNewClientName(e.target.value);
                    if (!newClientKey) {
                      setNewClientKey(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, "-"));
                    }
                  }}
                />
              </label>
              <label className="field">
                <span className="field__label">Client Code / Key</span>
                <input
                  className="field__control"
                  placeholder="e.g. acme-financial"
                  required
                  type="text"
                  value={newClientKey}
                  onChange={(e) => setNewClientKey(e.target.value)}
                />
              </label>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.8rem", marginTop: "0.5rem" }}>
                <button
                  className="action-button action-button--ghost"
                  type="button"
                  onClick={() => setShowClientModal(false)}
                >
                  Cancel
                </button>
                <button
                  className="action-button action-button--primary"
                  disabled={clientCreatePending}
                  type="submit"
                >
                  {clientCreatePending ? "Registering..." : "Register Client"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Add Site Location */}
      {showLocationModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
            padding: "1rem",
          }}
        >
          <div
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: "16px",
              padding: "1.5rem",
              maxWidth: "460px",
              width: "100%",
              display: "grid",
              gap: "1.2rem",
            }}
          >
            <SectionHeader
              description="Add a physical site office or datacenter location to a client company."
              eyebrow="Site Configuration"
              title="Add Site Location"
            />
            {locCreateError && (
              <p className="inline-feedback inline-feedback--danger">{locCreateError}</p>
            )}
            <form onSubmit={handleCreateLocation} style={{ display: "grid", gap: "1rem" }}>
              <label className="field">
                <span className="field__label">Client Company</span>
                <select
                  className="field__control"
                  required
                  value={newLocClientId}
                  onChange={(e) => setNewLocClientId(e.target.value)}
                >
                  <option value="">Select client...</option>
                  {clients.map((c) => (
                    <option key={c.client_id} value={c.client_id}>
                      {hierarchyDisplayName(c)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="field__label">Site Location Name</span>
                <input
                  className="field__control"
                  placeholder="e.g. Wall St Trading Floor"
                  required
                  type="text"
                  value={newLocName}
                  onChange={(e) => {
                    setNewLocName(e.target.value);
                    if (!newLocKey) {
                      setNewLocKey(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, "-"));
                    }
                  }}
                />
              </label>
              <label className="field">
                <span className="field__label">Site Key / Code</span>
                <input
                  className="field__control"
                  placeholder="e.g. wallst-floor"
                  required
                  type="text"
                  value={newLocKey}
                  onChange={(e) => setNewLocKey(e.target.value)}
                />
              </label>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.8rem", marginTop: "0.5rem" }}>
                <button
                  className="action-button action-button--ghost"
                  type="button"
                  onClick={() => setShowLocationModal(false)}
                >
                  Cancel
                </button>
                <button
                  className="action-button action-button--primary"
                  disabled={locCreatePending}
                  type="submit"
                >
                  {locCreatePending ? "Adding..." : "Add Site"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
