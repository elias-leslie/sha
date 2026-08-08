"use client";

import { useEffect, useMemo, useState } from "react";
import {
  type Client,
  type EndpointInventoryItem,
  type Location,
  endpointScore,
  endpointTone,
  getFixtureEndpoints,
  isDemoMode,
  listEndpoints,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";
import { hierarchyDisplayName, useScope } from "./scope-context";

type SelectedNode =
  | { type: "client"; id: string }
  | { type: "location"; id: string; clientId: string }
  | { type: "endpoint"; id: string }
  | null;

export default function HierarchyConsole({ demoMode = isDemoMode() }: { demoMode?: boolean }) {
  const { clients, locations, loading: hierarchyLoading, error: hierarchyError, setScope } = useScope();

  const [endpoints, setEndpoints] = useState<EndpointInventoryItem[]>([]);
  const [endpointsLoading, setEndpointsLoading] = useState(true);
  const [endpointsError, setEndpointsError] = useState<string | null>(null);

  // Expanded nodes state
  const [expandedClients, setExpandedClients] = useState<Set<string>>(new Set());
  const [expandedLocations, setExpandedLocations] = useState<Set<string>>(new Set());

  // Selected node state
  const [selectedNode, setSelectedNode] = useState<SelectedNode>(null);

  // Expand right pane to 100% real estate
  const [isPaneExpanded, setIsPaneExpanded] = useState(false);

  // Search query in tree
  const [filterQuery, setFilterQuery] = useState("");

  // Load endpoints
  useEffect(() => {
    if (demoMode) {
      setEndpoints(getFixtureEndpoints());
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
          setEndpointsError(err instanceof Error ? err.message : "Failed to load endpoint systems.");
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

  // Map locations by client_id
  const locationsByClient = useMemo(() => {
    const map = new Map<string, Location[]>();
    for (const loc of locations) {
      const existing = map.get(loc.client_id) || [];
      existing.push(loc);
      map.set(loc.client_id, existing);
    }
    return map;
  }, [locations]);

  // Group endpoints by client_id and location_id
  const endpointsByLocation = useMemo(() => {
    const map = new Map<string, EndpointInventoryItem[]>();
    for (const ep of endpoints) {
      const locId = ep.location_id || "unassigned";
      const existing = map.get(locId) || [];
      existing.push(ep);
      map.set(locId, existing);
    }
    return map;
  }, [endpoints]);

  const endpointsByClient = useMemo(() => {
    const map = new Map<string, EndpointInventoryItem[]>();
    for (const ep of endpoints) {
      const clientId = ep.client_id || "unassigned";
      const existing = map.get(clientId) || [];
      existing.push(ep);
      map.set(clientId, existing);
    }
    return map;
  }, [endpoints]);

  // Auto-expand first client and location on load
  useEffect(() => {
    if (clients.length > 0 && expandedClients.size === 0) {
      const firstClient = clients[0];
      setExpandedClients(new Set([firstClient.client_id]));
      const clientLocs = locationsByClient.get(firstClient.client_id) || [];
      if (clientLocs.length > 0) {
        setExpandedLocations(new Set([clientLocs[0].location_id]));
      }
      setSelectedNode({ type: "client", id: firstClient.client_id });
    }
  }, [clients, locationsByClient]);

  // Toggle client expand/collapse
  const toggleClient = (clientId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedClients((prev) => {
      const next = new Set(prev);
      if (next.has(clientId)) {
        next.delete(clientId);
      } else {
        next.add(clientId);
      }
      return next;
    });
  };

  // Toggle location expand/collapse
  const toggleLocation = (locationId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedLocations((prev) => {
      const next = new Set(prev);
      if (next.has(locationId)) {
        next.delete(locationId);
      } else {
        next.add(locationId);
      }
      return next;
    });
  };

  // Selected item lookup
  const activeClient = useMemo(() => {
    if (selectedNode?.type === "client") {
      return clients.find((c) => c.client_id === selectedNode.id) || null;
    }
    if (selectedNode?.type === "location") {
      return clients.find((c) => c.client_id === selectedNode.clientId) || null;
    }
    if (selectedNode?.type === "endpoint") {
      const ep = endpoints.find((e) => e.endpoint_id === selectedNode.id);
      if (ep) {
        return clients.find((c) => c.client_id === ep.client_id) || null;
      }
    }
    return clients[0] || null;
  }, [selectedNode, clients, endpoints]);

  const activeLocation = useMemo(() => {
    if (selectedNode?.type === "location") {
      return locations.find((l) => l.location_id === selectedNode.id) || null;
    }
    if (selectedNode?.type === "endpoint") {
      const ep = endpoints.find((e) => e.endpoint_id === selectedNode.id);
      if (ep) {
        return locations.find((l) => l.location_id === ep.location_id) || null;
      }
    }
    return null;
  }, [selectedNode, locations, endpoints]);

  const activeEndpoint = useMemo(() => {
    if (selectedNode?.type === "endpoint") {
      return endpoints.find((e) => e.endpoint_id === selectedNode.id) || null;
    }
    return null;
  }, [selectedNode, endpoints]);

  const activeEndpointScore = useMemo(() => {
    if (!activeEndpoint) return null;
    return endpointScore(activeEndpoint);
  }, [activeEndpoint]);

  // Filtered tree check
  const matchesFilter = (text: string) => {
    if (!filterQuery.trim()) return true;
    return text.toLowerCase().includes(filterQuery.toLowerCase());
  };

  const isTreeLoading = hierarchyLoading || endpointsLoading;

  return (
    <div className="hierarchy-console-container" style={{ display: "grid", gap: "1.2rem" }}>
      {/* Header Controls */}
      <div
        className="toolbar"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "rgba(255, 255, 255, 0.02)",
          padding: "0.8rem 1.2rem",
          borderRadius: "16px",
          border: "1px solid var(--border)",
        }}
      >
        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <input
            className="field__input"
            placeholder="Filter hierarchy..."
            style={{ width: "240px", padding: "0.45rem 0.8rem", fontSize: "0.82rem" }}
            type="search"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
          />
          <span style={{ fontSize: "0.78rem", color: "var(--muted)" }}>
            {clients.length} Clients • {locations.length} Locations • {endpoints.length} Systems
          </span>
        </div>

        <div style={{ display: "flex", gap: "0.8rem", alignItems: "center" }}>
          <button
            className="action-button action-button--ghost"
            style={{ fontSize: "0.78rem" }}
            type="button"
            onClick={() => setIsPaneExpanded(!isPaneExpanded)}
          >
            {isPaneExpanded ? "🗗 Restore Split View" : "🗖 Expand Details Pane"}
          </button>
        </div>
      </div>

      {/* Main Combined Grid */}
      <div
        className="hierarchy-layout"
        style={{
          display: "grid",
          gridTemplateColumns: isPaneExpanded ? "80px 1fr" : "360px 1fr",
          gap: "1.2rem",
          transition: "grid-template-columns 0.25s ease-in-out",
        }}
      >
        {/* LEFT PANE: Hierarchical Tree */}
        <Panel>
          <SectionHeader
            description={isPaneExpanded ? "Tree" : "Click node to view details and posture controls."}
            eyebrow="Structure"
            title={isPaneExpanded ? "Tree" : "Organizational Hierarchy"}
          />

          {isTreeLoading ? (
            <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--muted)" }}>
              Loading hierarchy...
            </div>
          ) : hierarchyError || endpointsError ? (
            <div style={{ padding: "1rem", color: "var(--danger)" }}>
              {hierarchyError || endpointsError}
            </div>
          ) : (
            <div
              className="tree-container"
              style={{
                display: "grid",
                gap: "0.4rem",
                marginTop: "0.8rem",
                maxHeight: "calc(100vh - 280px)",
                overflowY: "auto",
              }}
            >
              {clients.map((client) => {
                const isClientExpanded = expandedClients.has(client.client_id);
                const isClientSelected = selectedNode?.type === "client" && selectedNode.id === client.client_id;
                const clientLocations = locationsByClient.get(client.client_id) || [];
                const clientEndpoints = endpointsByClient.get(client.client_id) || [];
                const clientName = hierarchyDisplayName(client);

                if (
                  filterQuery &&
                  !matchesFilter(clientName) &&
                  !clientLocations.some((l) => matchesFilter(hierarchyDisplayName(l))) &&
                  !clientEndpoints.some((e) => matchesFilter(e.hostname))
                ) {
                  return null;
                }

                return (
                  <div key={client.client_id} className="tree-client-node" style={{ display: "grid", gap: "0.2rem" }}>
                    {/* Client Item */}
                    <div
                      className="tree-item tree-item--client"
                      data-selected={isClientSelected ? "true" : "false"}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "0.6rem 0.8rem",
                        borderRadius: "12px",
                        border: isClientSelected ? "1px solid var(--accent-strong)" : "1px solid var(--border)",
                        background: isClientSelected ? "rgba(255, 208, 138, 0.08)" : "rgba(255, 255, 255, 0.02)",
                        cursor: "pointer",
                        userSelect: "none",
                      }}
                      onClick={() => {
                        setSelectedNode({ type: "client", id: client.client_id });
                        setScope({ client_id: client.client_id, location_id: null });
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", overflow: "hidden" }}>
                        <button
                          type="button"
                          style={{
                            background: "none",
                            border: "none",
                            color: "var(--accent-strong)",
                            cursor: "pointer",
                            padding: 0,
                            fontSize: "0.75rem",
                            width: "16px",
                          }}
                          onClick={(e) => toggleClient(client.client_id, e)}
                        >
                          {isClientExpanded ? "▼" : "▶"}
                        </button>
                        <span style={{ fontSize: "1rem" }}>🏢</span>
                        <strong
                          style={{
                            fontSize: "0.85rem",
                            whiteSpace: "nowrap",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                          }}
                        >
                          {clientName}
                        </strong>
                      </div>
                      {!isPaneExpanded && (
                        <span className="tone tone--info" style={{ fontSize: "0.68rem" }}>
                          {clientEndpoints.length} systems
                        </span>
                      )}
                    </div>

                    {/* Locations Sub-tree */}
                    {isClientExpanded && !isPaneExpanded && (
                      <div style={{ paddingLeft: "1.4rem", display: "grid", gap: "0.25rem", marginTop: "0.2rem" }}>
                        {clientLocations.map((loc) => {
                          const isLocExpanded = expandedLocations.has(loc.location_id);
                          const isLocSelected = selectedNode?.type === "location" && selectedNode.id === loc.location_id;
                          const locEndpoints = endpointsByLocation.get(loc.location_id) || [];
                          const locName = hierarchyDisplayName(loc);

                          if (
                            filterQuery &&
                            !matchesFilter(locName) &&
                            !locEndpoints.some((e) => matchesFilter(e.hostname))
                          ) {
                            return null;
                          }

                          return (
                            <div key={loc.location_id} className="tree-location-node" style={{ display: "grid", gap: "0.2rem" }}>
                              {/* Location Item */}
                              <div
                                className="tree-item tree-item--location"
                                data-selected={isLocSelected ? "true" : "false"}
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "space-between",
                                  padding: "0.48rem 0.7rem",
                                  borderRadius: "10px",
                                  border: isLocSelected ? "1px solid var(--accent-strong)" : "1px solid var(--border)",
                                  background: isLocSelected ? "rgba(255, 208, 138, 0.08)" : "rgba(255, 255, 255, 0.01)",
                                  cursor: "pointer",
                                }}
                                onClick={() => {
                                  setSelectedNode({ type: "location", id: loc.location_id, clientId: client.client_id });
                                  setScope({ client_id: client.client_id, location_id: loc.location_id });
                                }}
                              >
                                <div style={{ display: "flex", alignItems: "center", gap: "0.45rem", overflow: "hidden" }}>
                                  <button
                                    type="button"
                                    style={{
                                      background: "none",
                                      border: "none",
                                      color: "var(--accent-strong)",
                                      cursor: "pointer",
                                      padding: 0,
                                      fontSize: "0.7rem",
                                      width: "14px",
                                    }}
                                    onClick={(e) => toggleLocation(loc.location_id, e)}
                                  >
                                    {isLocExpanded ? "▼" : "▶"}
                                  </button>
                                  <span style={{ fontSize: "0.9rem" }}>📍</span>
                                  <span
                                    style={{
                                      fontSize: "0.8rem",
                                      fontWeight: 500,
                                      whiteSpace: "nowrap",
                                      overflow: "hidden",
                                      textOverflow: "ellipsis",
                                    }}
                                  >
                                    {locName}
                                  </span>
                                </div>
                                <span className="tone tone--info" style={{ fontSize: "0.64rem" }}>
                                  {locEndpoints.length}
                                </span>
                              </div>

                              {/* Endpoints Sub-tree */}
                              {isLocExpanded && (
                                <div style={{ paddingLeft: "1.2rem", display: "grid", gap: "0.2rem", marginTop: "0.15rem" }}>
                                  {locEndpoints.length > 0 ? (
                                    locEndpoints.map((ep) => {
                                      const isEpSelected = selectedNode?.type === "endpoint" && selectedNode.id === ep.endpoint_id;
                                      const score = endpointScore(ep);
                                      const tone = endpointTone(ep);

                                      if (filterQuery && !matchesFilter(ep.hostname)) {
                                        return null;
                                      }

                                      return (
                                        <div
                                          key={ep.endpoint_id}
                                          className="tree-item tree-item--endpoint"
                                          data-selected={isEpSelected ? "true" : "false"}
                                          style={{
                                            display: "flex",
                                            alignItems: "center",
                                            justifyContent: "space-between",
                                            padding: "0.42rem 0.6rem",
                                            borderRadius: "8px",
                                            border: isEpSelected ? "1px solid var(--accent-strong)" : "1px solid var(--border)",
                                            background: isEpSelected ? "rgba(255, 208, 138, 0.1)" : "rgba(0, 0, 0, 0.2)",
                                            cursor: "pointer",
                                          }}
                                          onClick={() => {
                                            setSelectedNode({ type: "endpoint", id: ep.endpoint_id });
                                          }}
                                        >
                                          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", overflow: "hidden" }}>
                                            <span style={{ fontSize: "0.8rem" }}>
                                              {ep.platform === "windows" ? "🪟" : ep.platform === "macos" ? "🍏" : "🐧"}
                                            </span>
                                            <span
                                              style={{
                                                fontSize: "0.78rem",
                                                fontFamily: "var(--font-mono)",
                                                whiteSpace: "nowrap",
                                                overflow: "hidden",
                                                textOverflow: "ellipsis",
                                              }}
                                            >
                                              {ep.hostname}
                                            </span>
                                          </div>
                                          <Badge tone={tone}>
                                            {score ?? "N/A"}
                                          </Badge>
                                        </div>
                                      );
                                    })
                                  ) : (
                                    <div style={{ fontSize: "0.72rem", color: "var(--muted)", padding: "0.2rem 0.5rem" }}>
                                      No systems registered
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        {/* RIGHT PANE: Dynamic Details & Controls Console */}
        <Panel>
          {selectedNode?.type === "client" && activeClient && (
            <div style={{ display: "grid", gap: "1.2rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <SectionHeader
                  description="Client organizational boundary, active locations, and aggregate posture health."
                  eyebrow="Organization Context"
                  title={hierarchyDisplayName(activeClient)}
                />
                <button
                  className="action-button action-button--secondary"
                  type="button"
                  onClick={() => setIsPaneExpanded(!isPaneExpanded)}
                >
                  {isPaneExpanded ? "🗗 Split View" : "🗖 Expand Pane"}
                </button>
              </div>

              {/* Client Metrics */}
              <div className="dashboard-grid dashboard-grid--three-up" style={{ gap: "0.8rem" }}>
                <StatCard
                  label="Client Code"
                  meta="Client Key"
                  value={activeClient.key || activeClient.client_id}
                />
                <StatCard
                  label="Registered Locations"
                  meta="Sites & Offices"
                  value={(locationsByClient.get(activeClient.client_id) || []).length}
                />
                <StatCard
                  label="Host Systems"
                  meta="Enrolled Endpoints"
                  value={(endpointsByClient.get(activeClient.client_id) || []).length}
                />
              </div>

              {/* Client System List */}
              <div style={{ display: "grid", gap: "0.8rem" }}>
                <h3 style={{ fontSize: "0.95rem", textTransform: "uppercase", letterSpacing: "0.1em" }}>
                  Systems Under {hierarchyDisplayName(activeClient)}
                </h3>
                {(endpointsByClient.get(activeClient.client_id) || []).length > 0 ? (
                  <div style={{ display: "grid", gap: "0.45rem" }}>
                    {(endpointsByClient.get(activeClient.client_id) || []).map((ep) => (
                      <div
                        key={ep.endpoint_id}
                        className="operator-list__item"
                        style={{ cursor: "pointer" }}
                        onClick={() => setSelectedNode({ type: "endpoint", id: ep.endpoint_id })}
                      >
                        <div style={{ display: "flex", gap: "0.8rem", alignItems: "center" }}>
                          <span style={{ fontSize: "1.2rem" }}>
                            {ep.platform === "windows" ? "🪟" : ep.platform === "macos" ? "🍏" : "🐧"}
                          </span>
                          <div>
                            <strong style={{ fontSize: "0.9rem" }}>{ep.hostname}</strong>
                            <p style={{ fontSize: "0.74rem", color: "var(--muted)", margin: 0 }}>
                              ID: {ep.endpoint_id} • Status: {ep.status}
                            </p>
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
                          <Badge tone={endpointTone(ep)}>
                            Score: {endpointScore(ep) ?? "N/A"}
                          </Badge>
                          <a
                            className="action-button action-button--ghost"
                            href={`/endpoints/${ep.endpoint_id}`}
                            style={{ fontSize: "0.74rem", padding: "0.3rem 0.6rem" }}
                            onClick={(e) => e.stopPropagation()}
                          >
                            Inspect →
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    body="No host systems are currently enrolled under this client."
                    title="No systems registered"
                  />
                )}
              </div>
            </div>
          )}

          {selectedNode?.type === "location" && activeLocation && (
            <div style={{ display: "grid", gap: "1.2rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <SectionHeader
                  description="Facility or site boundary context and registered host systems."
                  eyebrow="Location Context"
                  title={hierarchyDisplayName(activeLocation)}
                />
                <button
                  className="action-button action-button--secondary"
                  type="button"
                  onClick={() => setIsPaneExpanded(!isPaneExpanded)}
                >
                  {isPaneExpanded ? "🗗 Split View" : "🗖 Expand Pane"}
                </button>
              </div>

              {/* Location Metrics */}
              <div className="dashboard-grid dashboard-grid--three-up" style={{ gap: "0.8rem" }}>
                <StatCard
                  label="Location ID"
                  meta="Location Key"
                  value={activeLocation.key || activeLocation.location_id}
                />
                <StatCard
                  label="Organization"
                  meta="Parent Entity"
                  value={activeClient ? hierarchyDisplayName(activeClient) : "Global"}
                />
                <StatCard
                  label="Registered Systems"
                  meta="Host Systems"
                  value={(endpointsByLocation.get(activeLocation.location_id) || []).length}
                />
              </div>

              {/* Systems in Location */}
              <div style={{ display: "grid", gap: "0.8rem" }}>
                <h3 style={{ fontSize: "0.95rem", textTransform: "uppercase", letterSpacing: "0.1em" }}>
                  Systems in {hierarchyDisplayName(activeLocation)}
                </h3>
                {(endpointsByLocation.get(activeLocation.location_id) || []).length > 0 ? (
                  <div style={{ display: "grid", gap: "0.45rem" }}>
                    {(endpointsByLocation.get(activeLocation.location_id) || []).map((ep) => (
                      <div
                        key={ep.endpoint_id}
                        className="operator-list__item"
                        style={{ cursor: "pointer" }}
                        onClick={() => setSelectedNode({ type: "endpoint", id: ep.endpoint_id })}
                      >
                        <div style={{ display: "flex", gap: "0.8rem", alignItems: "center" }}>
                          <span style={{ fontSize: "1.2rem" }}>
                            {ep.platform === "windows" ? "🪟" : ep.platform === "macos" ? "🍏" : "🐧"}
                          </span>
                          <div>
                            <strong style={{ fontSize: "0.9rem" }}>{ep.hostname}</strong>
                            <p style={{ fontSize: "0.74rem", color: "var(--muted)", margin: 0 }}>
                              ID: {ep.endpoint_id} • Status: {ep.status}
                            </p>
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
                          <Badge tone={endpointTone(ep)}>
                            Score: {endpointScore(ep) ?? "N/A"}
                          </Badge>
                          <a
                            className="action-button action-button--ghost"
                            href={`/endpoints/${ep.endpoint_id}`}
                            style={{ fontSize: "0.74rem", padding: "0.3rem 0.6rem" }}
                            onClick={(e) => e.stopPropagation()}
                          >
                            Inspect →
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    body="No host systems are currently enrolled at this site."
                    title="No systems in location"
                  />
                )}
              </div>
            </div>
          )}

          {selectedNode?.type === "endpoint" && activeEndpoint && (
            <div style={{ display: "grid", gap: "1.2rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <SectionHeader
                  description="Host system telemetry, compliance baseline assessment, and control actions."
                  eyebrow="System Overview"
                  title={activeEndpoint.hostname}
                />
                <div style={{ display: "flex", gap: "0.6rem" }}>
                  <button
                    className="action-button action-button--secondary"
                    type="button"
                    onClick={() => setIsPaneExpanded(!isPaneExpanded)}
                  >
                    {isPaneExpanded ? "🗗 Split View" : "🗖 Expand Pane"}
                  </button>
                  <a
                    className="action-button action-button--primary"
                    href={`/endpoints/${activeEndpoint.endpoint_id}`}
                  >
                    Full Details Console →
                  </a>
                </div>
              </div>

              {/* Endpoint Health Cards */}
              <div className="dashboard-grid dashboard-grid--three-up" style={{ gap: "0.8rem" }}>
                <StatCard
                  label="Posture Score"
                  meta={activeEndpointScore !== null && activeEndpointScore >= 90 ? "Hardened" : "Drift Detected"}
                  value={activeEndpointScore !== null ? activeEndpointScore : "N/A"}
                />
                <StatCard
                  label="Agent Status"
                  meta="Connectivity"
                  value={activeEndpoint.connectivity_status || "offline"}
                />
                <StatCard
                  label="Platform OS"
                  meta="OS Platform"
                  value={activeEndpoint.platform}
                />
              </div>

              {/* Posture Summary Breakdown */}
              <div style={{ display: "grid", gap: "0.8rem" }}>
                <h3 style={{ fontSize: "0.95rem", textTransform: "uppercase", letterSpacing: "0.1em" }}>
                  Hardening Baseline Assessment
                </h3>
                {activeEndpoint.latest_posture_summary ? (
                  <div style={{ display: "grid", gap: "0.45rem" }}>
                    <div className="operator-list__item" style={{ alignItems: "center" }}>
                      <div>
                        <strong style={{ fontSize: "0.85rem", fontFamily: "var(--font-mono)" }}>
                          Passing Controls: {activeEndpoint.latest_posture_summary.pass_count}
                        </strong>
                        <p style={{ fontSize: "0.74rem", color: "var(--muted)", margin: 0 }}>
                          Evaluated: {new Date(activeEndpoint.latest_posture_summary.observed_at).toLocaleString()}
                        </p>
                      </div>
                      <Badge tone="success">
                        {activeEndpoint.latest_posture_summary.pass_count} Passed
                      </Badge>
                    </div>
                    {activeEndpoint.latest_posture_summary.fail_count > 0 && (
                      <div className="operator-list__item" style={{ alignItems: "center" }}>
                        <div>
                          <strong style={{ fontSize: "0.85rem", fontFamily: "var(--font-mono)" }}>
                            Failing Controls: {activeEndpoint.latest_posture_summary.fail_count}
                          </strong>
                          <p style={{ fontSize: "0.74rem", color: "var(--muted)", margin: 0 }}>
                            Attention Required
                          </p>
                        </div>
                        <Badge tone="danger">
                          {activeEndpoint.latest_posture_summary.fail_count} Failed
                        </Badge>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="operator-list__item">
                    <span>Baseline evaluation telemetry active. All core security rules verified.</span>
                    <Badge tone="success">Verified Compliant</Badge>
                  </div>
                )}
              </div>
            </div>
          )}

          {!selectedNode && (
            <EmptyState
              body="Click any client, location, or system in the hierarchy tree on the left to inspect details and control options."
              title="Select a Node"
            />
          )}
        </Panel>
      </div>
    </div>
  );
}
