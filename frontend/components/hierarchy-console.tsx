"use client";

import { useEffect, useMemo, useState } from "react";
import {
  type Client,
  type EndpointInventoryItem,
  type Location,
  createClient,
  createLocation,
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
          setEndpointsError(err instanceof Error ? err.message : "Failed to load computer & server endpoints.");
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

  // Auto expand clients and select first client when clients arrive
  useEffect(() => {
    if (clients.length > 0) {
      setExpandedClients((prev) => {
        if (prev.size === 0) {
          const allClientIds = clients.map((c) => c.client_id);
          return new Set(allClientIds);
        }
        return prev;
      });

      if (!selectedNode) {
        const firstClient = clients.find((c) => !c.is_system) || clients[0];
        if (firstClient) {
          setSelectedNode({ type: "client", id: firstClient.client_id });
        }
      }
    }
  }, [clients, selectedNode]);

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

  // Map endpoints by location_id and client_id
  const endpointsByLocation = useMemo(() => {
    const map = new Map<string, EndpointInventoryItem[]>();
    for (const ep of endpoints) {
      if (ep.location_id) {
        const existing = map.get(ep.location_id) || [];
        existing.push(ep);
        map.set(ep.location_id, existing);
      }
    }
    return map;
  }, [endpoints]);

  const endpointsByClient = useMemo(() => {
    const map = new Map<string, EndpointInventoryItem[]>();
    for (const ep of endpoints) {
      if (ep.client_id) {
        const existing = map.get(ep.client_id) || [];
        existing.push(ep);
        map.set(ep.client_id, existing);
      }
    }
    return map;
  }, [endpoints]);

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

  const activeClient = useMemo(() => {
    if (selectedNode?.type === "client") {
      return clients.find((c) => c.client_id === selectedNode.id) || null;
    }
    if (selectedNode?.type === "location") {
      return clients.find((c) => c.client_id === selectedNode.clientId) || null;
    }
    if (selectedNode?.type === "endpoint") {
      const ep = endpoints.find((e) => e.endpoint_id === selectedNode.id);
      if (ep?.client_id) {
        return clients.find((c) => c.client_id === ep.client_id) || null;
      }
    }
    return null;
  }, [selectedNode, clients, endpoints]);

  const activeLocation = useMemo(() => {
    if (selectedNode?.type === "location") {
      return locations.find((l) => l.location_id === selectedNode.id) || null;
    }
    if (selectedNode?.type === "endpoint") {
      const ep = endpoints.find((e) => e.endpoint_id === selectedNode.id);
      if (ep?.location_id) {
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

  // Handle Client Creation
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
      window.location.reload();
    } catch (err) {
      setClientCreateError(err instanceof Error ? err.message : "Failed to create client company.");
    } finally {
      setClientCreatePending(false);
    }
  };

  // Handle Location Creation
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
      window.location.reload();
    } catch (err) {
      setLocCreateError(err instanceof Error ? err.message : "Failed to create branch location.");
    } finally {
      setLocCreatePending(false);
    }
  };

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
          flexWrap: "wrap",
          gap: "0.8rem",
        }}
      >
        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <input
            className="field__input"
            placeholder="Filter organizations, sites, hosts..."
            style={{ width: "260px", padding: "0.45rem 0.8rem", fontSize: "0.82rem" }}
            type="search"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
          />
          <span style={{ fontSize: "0.78rem", color: "var(--muted)" }}>
            <strong>{clients.length}</strong> Organizations • <strong>{locations.length}</strong> Sites • <strong>{endpoints.length}</strong> Systems
          </span>
        </div>

        <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
          <button
            className="action-button action-button--secondary"
            style={{ fontSize: "0.78rem", padding: "0.4rem 0.8rem" }}
            type="button"
            onClick={() => setShowClientModal(true)}
          >
            + Add Organization
          </button>
          <button
            className="action-button action-button--secondary"
            style={{ fontSize: "0.78rem", padding: "0.4rem 0.8rem" }}
            type="button"
            onClick={() => {
              if (activeClient) setNewLocClientId(activeClient.client_id);
              setShowLocationModal(true);
            }}
          >
            + Add Site Location
          </button>
          <button
            className="action-button action-button--ghost"
            style={{ fontSize: "0.78rem", padding: "0.4rem 0.8rem" }}
            type="button"
            onClick={() => setIsPaneExpanded(!isPaneExpanded)}
          >
            {isPaneExpanded ? "🗗 Restore Split View" : "🗖 Expand Details Pane"}
          </button>
        </div>
      </div>

      {/* Main Split / Expanded Layout */}
      <div
        className="hierarchy-layout"
        style={{
          display: "grid",
          gridTemplateColumns: isPaneExpanded ? "80px 1fr" : "360px 1fr",
          gap: "1.2rem",
          transition: "grid-template-columns 0.25s ease-in-out",
        }}
      >
        {/* Left Pane: Interactive Organizational Tree View */}
        <Panel>
          <SectionHeader
            description={isPaneExpanded ? "" : "Hierarchical view of MSP Clients, Branch Locations, and Host Systems."}
            eyebrow="Structure"
            title={isPaneExpanded ? "Tree" : "Client Organizations & Sites"}
          />

          {hierarchyError || endpointsError ? (
            <div style={{ padding: "0.8rem", color: "var(--danger)", fontSize: "0.8rem" }}>
              {hierarchyError || endpointsError}
            </div>
          ) : isTreeLoading ? (
            <div style={{ padding: "1rem", color: "var(--muted)", fontSize: "0.85rem" }}>
              Loading organization hierarchy...
            </div>
          ) : (
            <div
              className="tree-container"
              style={{
                display: "grid",
                gap: "0.4rem",
                marginTop: "0.8rem",
                maxHeight: "720px",
                overflowY: "auto",
                paddingRight: "0.3rem",
              }}
            >
              {clients.map((client) => {
                const clientName = hierarchyDisplayName(client);
                const clientLocations = locationsByClient.get(client.client_id) || [];
                const clientEndpoints = endpointsByClient.get(client.client_id) || [];
                const isClientExpanded = expandedClients.has(client.client_id);
                const isClientSelected = selectedNode?.type === "client" && selectedNode.id === client.client_id;

                if (filterQuery && !matchesFilter(clientName) && !clientLocations.some((l) => matchesFilter(hierarchyDisplayName(l))) && !clientEndpoints.some((e) => matchesFilter(e.hostname))) {
                  return null;
                }

                return (
                  <div key={client.client_id} className="tree-client-node" style={{ display: "grid", gap: "0.2rem" }}>
                    {/* Client Company Row */}
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
                        background: isClientSelected ? "rgba(255, 208, 138, 0.12)" : "rgba(255, 255, 255, 0.02)",
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
                      <span className="tone tone--info" style={{ fontSize: "0.68rem" }}>
                        {clientEndpoints.length} {isPaneExpanded ? "" : "systems"}
                      </span>
                    </div>

                    {/* Locations Sub-tree */}
                    {isClientExpanded && (
                      <div style={{ paddingLeft: "1.4rem", display: "grid", gap: "0.25rem", marginTop: "0.2rem" }}>
                        {clientLocations.length > 0 ? (
                          clientLocations.map((loc) => {
                            const locName = hierarchyDisplayName(loc);
                            const locEndpoints = endpointsByLocation.get(loc.location_id) || [];
                            const isLocExpanded = expandedLocations.has(loc.location_id);
                            const isLocSelected = selectedNode?.type === "location" && selectedNode.id === loc.location_id;

                            if (filterQuery && !matchesFilter(locName) && !locEndpoints.some((e) => matchesFilter(e.hostname))) {
                              return null;
                            }

                            return (
                              <div key={loc.location_id} className="tree-location-node" style={{ display: "grid", gap: "0.15rem" }}>
                                {/* Location Branch Row */}
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

                                {/* Computers / Endpoints Sub-tree */}
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
                                              background: isEpSelected ? "rgba(255, 208, 138, 0.15)" : "rgba(255, 255, 255, 0.005)",
                                              cursor: "pointer",
                                            }}
                                            onClick={() => {
                                              setSelectedNode({ type: "endpoint", id: ep.endpoint_id });
                                              setScope({ client_id: client.client_id, location_id: loc.location_id });
                                            }}
                                          >
                                            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", overflow: "hidden" }}>
                                              <span style={{ fontSize: "0.85rem" }}>
                                                {ep.platform === "windows" ? "🪟" : ep.platform === "macos" ? "🍏" : "🐧"}
                                              </span>
                                              <span
                                                style={{
                                                  fontSize: "0.78rem",
                                                  whiteSpace: "nowrap",
                                                  overflow: "hidden",
                                                  textOverflow: "ellipsis",
                                                }}
                                              >
                                                {ep.hostname}
                                              </span>
                                            </div>
                                            {score !== null && (
                                              <span className={`tone tone--${tone}`} style={{ fontSize: "0.62rem" }}>
                                                {score}
                                              </span>
                                            )}
                                          </div>
                                        );
                                      })
                                    ) : (
                                      <div style={{ fontSize: "0.72rem", color: "var(--muted)", padding: "0.2rem 0.5rem" }}>
                                        No computers registered
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            );
                          })
                        ) : (
                          <div style={{ fontSize: "0.74rem", color: "var(--muted)", padding: "0.2rem 0.5rem" }}>
                            No sites configured
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        {/* Right Pane: Entity Details & Control Panel */}
        <Panel>
          {selectedNode?.type === "client" && activeClient && (
            <div style={{ display: "grid", gap: "1.2rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <SectionHeader
                  description="Organizational boundary, configured site locations, and system posture health."
                  eyebrow="Organization Boundary"
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
                  label="Organization Code"
                  meta="Organization Identifier"
                  value={activeClient.key || activeClient.client_id}
                />
                <StatCard
                  label="Configured Sites"
                  meta="Branch Offices & DCs"
                  value={(locationsByClient.get(activeClient.client_id) || []).length}
                />
                <StatCard
                  label="Enrolled Systems"
                  meta="Computers & Servers"
                  value={(endpointsByClient.get(activeClient.client_id) || []).length}
                />
              </div>

              {/* Branch Sites List */}
              <div style={{ display: "grid", gap: "0.8rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <h3 style={{ fontSize: "0.95rem", textTransform: "uppercase", letterSpacing: "0.1em", margin: 0 }}>
                    Sites & Locations under {hierarchyDisplayName(activeClient)}
                  </h3>
                  <button
                    className="action-button action-button--secondary"
                    style={{ fontSize: "0.75rem", padding: "0.3rem 0.6rem" }}
                    type="button"
                    onClick={() => {
                      setNewLocClientId(activeClient.client_id);
                      setShowLocationModal(true);
                    }}
                  >
                    + Add Site Location
                  </button>
                </div>
                {(locationsByClient.get(activeClient.client_id) || []).length > 0 ? (
                  <div style={{ display: "grid", gap: "0.5rem", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}>
                    {(locationsByClient.get(activeClient.client_id) || []).map((loc) => {
                      const locEps = endpointsByLocation.get(loc.location_id) || [];
                      return (
                        <div
                          key={loc.location_id}
                          className="operator-list__item"
                          style={{ cursor: "pointer", flexDirection: "column", alignItems: "flex-start", gap: "0.4rem" }}
                          onClick={() => {
                            setSelectedNode({ type: "location", id: loc.location_id, clientId: activeClient.client_id });
                            setScope({ client_id: activeClient.client_id, location_id: loc.location_id });
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                            <strong style={{ fontSize: "0.9rem" }}>📍 {hierarchyDisplayName(loc)}</strong>
                            <span className="tone tone--info" style={{ fontSize: "0.7rem" }}>
                              {locEps.length} systems
                            </span>
                          </div>
                          <p style={{ fontSize: "0.75rem", color: "var(--muted)", margin: 0 }}>
                            Key: {loc.key || loc.location_id} • Status: {loc.state}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <EmptyState
                    body="No site locations or offices have been configured for this client company."
                    title="No branch sites registered"
                  />
                )}
              </div>

              {/* Client Systems List */}
              <div style={{ display: "grid", gap: "0.8rem", marginTop: "0.5rem" }}>
                <h3 style={{ fontSize: "0.95rem", textTransform: "uppercase", letterSpacing: "0.1em" }}>
                  Enrolled Computers & Servers
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
                              OS: {ep.platform_version || ep.platform} • Connectivity: {ep.connectivity_status}
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
                    body="No computers or servers are currently enrolled under this client company."
                    title="No computers registered"
                  />
                )}
              </div>
            </div>
          )}

          {selectedNode?.type === "location" && activeLocation && (
            <div style={{ display: "grid", gap: "1.2rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <SectionHeader
                  description="Branch office or datacenter location context and registered systems."
                  eyebrow="Branch Site Location"
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
                  meta="Site Key"
                  value={activeLocation.key || activeLocation.location_id}
                />
                <StatCard
                  label="Parent Client Company"
                  meta="MSP Client"
                  value={activeClient ? hierarchyDisplayName(activeClient) : activeLocation.client_id}
                />
                <StatCard
                  label="Registered Computers"
                  meta="Site Systems"
                  value={(endpointsByLocation.get(activeLocation.location_id) || []).length}
                />
              </div>

              {/* Location Systems */}
              <div style={{ display: "grid", gap: "0.8rem" }}>
                <h3 style={{ fontSize: "0.95rem", textTransform: "uppercase", letterSpacing: "0.1em" }}>
                  Computers & Servers at {hierarchyDisplayName(activeLocation)}
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
                              OS: {ep.platform_version || ep.platform} • Connectivity: {ep.connectivity_status}
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
                    body="No computers or servers are registered to this site location."
                    title="No site systems"
                  />
                )}
              </div>
            </div>
          )}

          {selectedNode?.type === "endpoint" && activeEndpoint && (
            <div style={{ display: "grid", gap: "1.2rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <SectionHeader
                  description="Enrolled computer or server posture, security compliance, and control actions."
                  eyebrow="Host System Detail"
                  title={activeEndpoint.hostname}
                />
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <a
                    className="action-button action-button--primary"
                    href={`/endpoints/${activeEndpoint.endpoint_id}`}
                    style={{ fontSize: "0.78rem", padding: "0.4rem 0.8rem" }}
                  >
                    Open Posture Console →
                  </a>
                  <button
                    className="action-button action-button--secondary"
                    type="button"
                    onClick={() => setIsPaneExpanded(!isPaneExpanded)}
                  >
                    {isPaneExpanded ? "🗗 Split View" : "🗖 Expand Pane"}
                  </button>
                </div>
              </div>

              {/* Endpoint Telemetry Stat Grid */}
              <div className="dashboard-grid dashboard-grid--three-up" style={{ gap: "0.8rem" }}>
                <StatCard
                  label="Posture Score"
                  meta="Compliance Baseline"
                  value={activeEndpointScore !== null ? `${activeEndpointScore}%` : "Pending"}
                />
                <StatCard
                  label="Agent Connectivity"
                  meta="Heartbeat Signal"
                  value={(activeEndpoint.connectivity_status || "offline").toUpperCase()}
                />
                <StatCard
                  label="Platform OS"
                  meta="Operating System"
                  value={activeEndpoint.platform_version || activeEndpoint.platform}
                />
              </div>

              {/* Detailed Specs Card */}
              <div
                style={{
                  display: "grid",
                  gap: "0.8rem",
                  background: "rgba(255, 255, 255, 0.015)",
                  padding: "1.2rem",
                  borderRadius: "14px",
                  border: "1px solid var(--border)",
                }}
              >
                <h3 style={{ fontSize: "0.9rem", textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
                  System Specifications & Ownership
                </h3>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "1rem", fontSize: "0.82rem" }}>
                  <div>
                    <span style={{ color: "var(--muted)", display: "block" }}>Endpoint ID</span>
                    <strong>{activeEndpoint.endpoint_id}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--muted)", display: "block" }}>MSP Client Company</span>
                    <strong>{activeClient ? hierarchyDisplayName(activeClient) : activeEndpoint.client_id}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--muted)", display: "block" }}>Branch Site Location</span>
                    <strong>{activeLocation ? hierarchyDisplayName(activeLocation) : activeEndpoint.location_id}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--muted)", display: "block" }}>Agent Version</span>
                    <strong>v{activeEndpoint.agent_version}</strong>
                  </div>
                </div>
              </div>
            </div>
          )}

          {!selectedNode && (
            <EmptyState
              body="Select any MSP client company, branch site location, or host system from the tree view to inspect posture and management controls."
              title="No entity selected"
            />
          )}
        </Panel>
      </div>

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
              description="Add a customer company, corporate entity, or workspace boundary to your control plane."
              eyebrow="Organization Registration"
              title="Add New Organization"
            />
            {clientCreateError && (
              <p className="inline-feedback inline-feedback--danger">{clientCreateError}</p>
            )}
            <form onSubmit={handleCreateClient} style={{ display: "grid", gap: "1rem" }}>
              <label className="field">
                <span className="field__label">Organization Name</span>
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
                <span className="field__label">Organization Code / Key</span>
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
                  {clientCreatePending ? "Adding..." : "Add Organization"}
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
              description="Add a physical branch office, datacenter, room, or site boundary to an organization."
              eyebrow="Location Configuration"
              title="Add Site Location"
            />
            {locCreateError && (
              <p className="inline-feedback inline-feedback--danger">{locCreateError}</p>
            )}
            <form onSubmit={handleCreateLocation} style={{ display: "grid", gap: "1rem" }}>
              <label className="field">
                <span className="field__label">Parent Organization</span>
                <select
                  className="field__control"
                  required
                  value={newLocClientId}
                  onChange={(e) => setNewLocClientId(e.target.value)}
                >
                  <option value="">Select organization...</option>
                  {clients.map((c) => (
                    <option key={c.client_id} value={c.client_id}>
                      {hierarchyDisplayName(c)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="field__label">Branch Site Name</span>
                <input
                  className="field__control"
                  placeholder="e.g. Chicago Operations Hub"
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
                <span className="field__label">Site Key / Identifier</span>
                <input
                  className="field__control"
                  placeholder="e.g. chi-ops-hub"
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
                  {locCreatePending ? "Creating..." : "Add Branch Site"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
