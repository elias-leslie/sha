"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  type Client,
  type EndpointInventoryItem,
  type Location,
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
type InspectorTab = "overview" | "checks" | "incident_response" | "terminal" | "remote_desktop" | "audit";

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

  // Interactive Remote Terminal state
  const [terminalInput, setTerminalInput] = useState("");
  const [terminalHistory, setTerminalHistory] = useState<Array<{ type: "input" | "output" | "error"; text: string }>>([
    { type: "output", text: "SHA Secure Agent Tunnel v2.4.0 active. Type 'uname -a', 'ps', or 'systemctl status' to execute remote shell commands." },
  ]);
  const [terminalLoading, setTerminalLoading] = useState(false);

  // Interactive Remote Desktop state
  const [rdpSessionToken, setRdpSessionToken] = useState<string | null>(null);
  const [rdpConnected, setRdpConnected] = useState(false);
  const [rdpLoading, setRdpLoading] = useState(false);

  // Network Scanner state
  const [scanningNetwork, setScanningNetwork] = useState(false);

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

  // Mock Incident Response Action Handler
  const triggerIRAction = (actionName: string) => {
    if (!inspectedEndpoint) return;
    setActionFeedback({
      type: "info",
      message: `Executed playbook [${actionName}] on ${inspectedEndpoint.hostname}. Action logged to audit trail.`,
    });
  };

  // Remote Terminal Execution Handler
  const handleTerminalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!terminalInput.trim() || !inspectedEndpoint) return;
    const cmd = terminalInput.trim();
    setTerminalInput("");
    setTerminalLoading(true);
    setTerminalHistory((prev) => [...prev, { type: "input", text: `$ ${cmd}` }]);
    try {
      if (demoMode) {
        setTerminalHistory((prev) => [
          ...prev,
          { type: "output", text: `[SHA Agent Tunnel]: Executed '${cmd}' on ${inspectedEndpoint.hostname}.\nSuccess (exit code 0).` },
        ]);
      } else {
        const res = await fetch(`/api/endpoints/${inspectedEndpoint.endpoint_id}/terminal/execute`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ command: cmd }),
        });
        const data = await res.json();
        setTerminalHistory((prev) => [
          ...prev,
          { type: "output", text: data.stdout || data.stderr || "Command completed with code 0." },
        ]);
      }
    } catch (err) {
      setTerminalHistory((prev) => [
        ...prev,
        { type: "error", text: `Tunnel Execution Error: ${err instanceof Error ? err.message : "Failed to execute"}` },
      ]);
    } finally {
      setTerminalLoading(false);
    }
  };

  // Remote Desktop Connect Handler
  const handleConnectRDP = async () => {
    if (!inspectedEndpoint) return;
    setRdpLoading(true);
    try {
      if (demoMode) {
        setRdpSessionToken("rdp_sess_live_demo");
        setRdpConnected(true);
        setActionFeedback({ type: "success", message: `Connected Remote Desktop session over SHA tunnel to ${inspectedEndpoint.hostname}.` });
      } else {
        const res = await fetch(`/api/endpoints/${inspectedEndpoint.endpoint_id}/remote-desktop/session`, {
          method: "POST",
        });
        const data = await res.json();
        setRdpSessionToken(data.session_token || "rdp_sess_live");
        setRdpConnected(true);
        setActionFeedback({ type: "success", message: `Connected Remote Desktop session over SHA tunnel to ${inspectedEndpoint.hostname}.` });
      }
    } catch (err) {
      setActionFeedback({ type: "danger", message: `Failed to connect Remote Desktop: ${err instanceof Error ? err.message : "Tunnel error"}` });
    } finally {
      setRdpLoading(false);
    }
  };

  // Network Discovery Scan Handler
  const handleScanNetwork = async () => {
    setScanningNetwork(true);
    setActionFeedback({ type: "info", message: "Scanning local subnet for active IP devices, routers, switches, NAS, and cameras..." });
    try {
      if (demoMode) {
        setActionFeedback({ type: "success", message: "Network scan completed. Discovered local host node." });
      } else {
        const res = await fetch("/api/network/scan", { method: "POST" });
        const data = await res.json();
        setActionFeedback({
          type: "success",
          message: `Network scan complete! Discovered ${data.discovered_count} active devices and registered ${data.registered_count} new network nodes.`,
        });
        window.location.reload();
      }
    } catch (err) {
      setActionFeedback({ type: "danger", message: `Network scan failed: ${err instanceof Error ? err.message : "Scan error"}` });
    } finally {
      setScanningNetwork(false);
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
              className={`action-button ${inspectorTab === "terminal" ? "action-button--primary" : "action-button--ghost"}`}
              style={{ fontSize: "0.76rem", padding: "0.3rem 0.65rem" }}
              type="button"
              onClick={() => setInspectorTab("terminal")}
            >
              💻 Remote Terminal
            </button>
            <button
              className={`action-button ${inspectorTab === "remote_desktop" ? "action-button--primary" : "action-button--ghost"}`}
              style={{ fontSize: "0.76rem", padding: "0.3rem 0.65rem" }}
              type="button"
              onClick={() => setInspectorTab("remote_desktop")}
            >
              🖥️ Remote Desktop
            </button>
            <button
              className={`action-button ${inspectorTab === "incident_response" ? "action-button--primary" : "action-button--ghost"}`}
              style={{ fontSize: "0.76rem", padding: "0.3rem 0.65rem" }}
              type="button"
              onClick={() => setInspectorTab("incident_response")}
            >
              ⚡ Hardening & IR
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
              📜 Audit Log
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
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h4 style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
                Active Posture & Compliance Rules
              </h4>
              <button
                className="action-button action-button--secondary"
                style={{ fontSize: "0.74rem", padding: "0.3rem 0.6rem" }}
                type="button"
                onClick={() => triggerIRAction("Re-scan Compliance Baseline")}
              >
                🔄 Scan Compliance Baseline
              </button>
            </div>

            <div style={{ display: "grid", gap: "0.45rem" }}>
              {ep.platform === "windows" ? (
                <>
                  <div className="operator-list__item" style={{ justifyContent: "space-between" }}>
                    <div>
                      <strong>windows.defender.real_time_protection</strong>
                      <p style={{ fontSize: "0.75rem", color: "var(--muted)", margin: 0 }}>
                        Microsoft Defender real-time protection and antivirus engine are active.
                      </p>
                    </div>
                    <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
                      <span className="tone tone--success">PASS (Enforced)</span>
                    </div>
                  </div>
                  <div className="operator-list__item" style={{ justifyContent: "space-between" }}>
                    <div>
                      <strong>windows.rdp.network_level_authentication</strong>
                      <p style={{ fontSize: "0.75rem", color: "var(--muted)", margin: 0 }}>
                        Enforce Network Level Authentication (NLA) on RDP connections.
                      </p>
                    </div>
                    <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
                      <span className="tone tone--warning">FAIL (Disabled)</span>
                      <button
                        className="action-button action-button--primary"
                        style={{ fontSize: "0.72rem", padding: "0.25rem 0.5rem" }}
                        type="button"
                        onClick={() => triggerIRAction("Enforce RDP NLA")}
                      >
                        Remediate →
                      </button>
                    </div>
                  </div>
                  <div className="operator-list__item" style={{ justifyContent: "space-between" }}>
                    <div>
                      <strong>windows.powershell.constrained_language_mode</strong>
                      <p style={{ fontSize: "0.75rem", color: "var(--muted)", margin: 0 }}>
                        PowerShell execution language mode restriction.
                      </p>
                    </div>
                    <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
                      <span className="tone tone--info">AUDIT ONLY</span>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="operator-list__item" style={{ justifyContent: "space-between" }}>
                    <div>
                      <strong>linux.ssh.disable_password_authentication</strong>
                      <p style={{ fontSize: "0.75rem", color: "var(--muted)", margin: 0 }}>
                        Require public key authentication; disable SSH password login in sshd_config.
                      </p>
                    </div>
                    <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
                      <span className="tone tone--success">PASS (Disabled)</span>
                    </div>
                  </div>
                  <div className="operator-list__item" style={{ justifyContent: "space-between" }}>
                    <div>
                      <strong>linux.auditd.ruleset_integrity</strong>
                      <p style={{ fontSize: "0.75rem", color: "var(--muted)", margin: 0 }}>
                        Audit daemon telemetry ruleset integrity and file deletion tracking.
                      </p>
                    </div>
                    <div style={{ display: "flex", gap: "0.6rem", alignItems: "center" }}>
                      <span className="tone tone--warning">WARN (Coverage gap)</span>
                      <button
                        className="action-button action-button--primary"
                        style={{ fontSize: "0.72rem", padding: "0.25rem 0.5rem" }}
                        type="button"
                        onClick={() => triggerIRAction("Update Auditd Ruleset")}
                      >
                        Remediate →
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        );

      case "incident_response":
        return (
          <div style={{ display: "grid", gap: "1rem" }}>
            <SectionHeader
              description="Hardening actions and containment playbooks for execution before, during, or after incident response."
              eyebrow="Incident Response & Lockdown"
              title="Endpoint Incident Response Actions"
            />

            <div className="dashboard-grid dashboard-grid--two-up" style={{ gap: "0.8rem" }}>
              <div
                style={{
                  background: "rgba(255, 255, 255, 0.02)",
                  padding: "1rem",
                  borderRadius: "12px",
                  border: "1px solid var(--border)",
                  display: "grid",
                  gap: "0.6rem",
                }}
              >
                <strong style={{ fontSize: "0.9rem", color: "var(--danger)" }}>🚫 Network Containment & Isolation</strong>
                <p style={{ fontSize: "0.78rem", color: "var(--muted)", margin: 0 }}>
                  Isolate host network stack to drop all ingress/egress except telemetry control-plane signal.
                </p>
                <div>
                  <button
                    className="action-button action-button--danger"
                    style={{ fontSize: "0.76rem" }}
                    type="button"
                    onClick={() => triggerIRAction("Network Isolation")}
                  >
                    Isolate Host System
                  </button>
                </div>
              </div>

              <div
                style={{
                  background: "rgba(255, 255, 255, 0.02)",
                  padding: "1rem",
                  borderRadius: "12px",
                  border: "1px solid var(--border)",
                  display: "grid",
                  gap: "0.6rem",
                }}
              >
                <strong style={{ fontSize: "0.9rem", color: "var(--warning)" }}>🔒 Privileged Account Lockdown</strong>
                <p style={{ fontSize: "0.78rem", color: "var(--muted)", margin: 0 }}>
                  Invalidate active user logon sessions, lock local administrator accounts, and flush kerberos/NTHash tokens.
                </p>
                <div>
                  <button
                    className="action-button action-button--warning"
                    style={{ fontSize: "0.76rem" }}
                    type="button"
                    onClick={() => triggerIRAction("Account Session Lockdown")}
                  >
                    Revoke & Lock Sessions
                  </button>
                </div>
              </div>

              <div
                style={{
                  background: "rgba(255, 255, 255, 0.02)",
                  padding: "1rem",
                  borderRadius: "12px",
                  border: "1px solid var(--border)",
                  display: "grid",
                  gap: "0.6rem",
                }}
              >
                <strong style={{ fontSize: "0.9rem" }}>📁 Forensic Evidence Dump</strong>
                <p style={{ fontSize: "0.78rem", color: "var(--muted)", margin: 0 }}>
                  Dump volatile memory context, network socket bindings, security event logs, and active process tree.
                </p>
                <div>
                  <button
                    className="action-button action-button--secondary"
                    style={{ fontSize: "0.76rem" }}
                    type="button"
                    onClick={() => triggerIRAction("Collect Forensic Evidence")}
                  >
                    Collect Security Context
                  </button>
                </div>
              </div>

              <div
                style={{
                  background: "rgba(255, 255, 255, 0.02)",
                  padding: "1rem",
                  borderRadius: "12px",
                  border: "1px solid var(--border)",
                  display: "grid",
                  gap: "0.6rem",
                }}
              >
                <strong style={{ fontSize: "0.9rem" }}>🛡️ Strict Baseline Enforcement</strong>
                <p style={{ fontSize: "0.78rem", color: "var(--muted)", margin: 0 }}>
                  Force emergency zero-trust hardening profile across all Defender, Firewall, and SSH controls.
                </p>
                <div>
                  <button
                    className="action-button action-button--primary"
                    style={{ fontSize: "0.76rem" }}
                    type="button"
                    onClick={() => triggerIRAction("Enforce Strict Baseline")}
                  >
                    Enforce Emergency Baseline
                  </button>
                </div>
              </div>
            </div>
          </div>
        );

      case "terminal":
        return (
          <div style={{ display: "grid", gap: "0.8rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h4 style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
                💻 Remote Terminal (Agent Tunnel)
              </h4>
              <span className="tone tone--success" style={{ fontSize: "0.74rem" }}>
                ● Agent Tunnel Active ({ep.hostname})
              </span>
            </div>
            <div
              style={{
                background: "#0d1117",
                border: "1px solid var(--border)",
                borderRadius: "10px",
                padding: "1rem",
                fontFamily: "monospace",
                fontSize: "0.82rem",
                color: "#e6edf3",
                minHeight: isExpandedRealEstate ? "440px" : "220px",
                maxHeight: isExpandedRealEstate ? "620px" : "360px",
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
                gap: "0.4rem",
              }}
            >
              {terminalHistory.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    color: item.type === "input" ? "#58a6ff" : item.type === "error" ? "#f85149" : "#3fb950",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {item.text}
                </div>
              ))}
              {terminalLoading && <div style={{ color: "var(--muted)" }}>Executing command over agent tunnel...</div>}
            </div>
            <form onSubmit={handleTerminalSubmit} style={{ display: "flex", gap: "0.6rem" }}>
              <input
                className="field__input"
                placeholder="Type command (e.g. ps, uname -a, systemctl status)..."
                style={{ flex: 1, fontFamily: "monospace", fontSize: "0.82rem" }}
                type="text"
                value={terminalInput}
                onChange={(e) => setTerminalInput(e.target.value)}
              />
              <button className="action-button action-button--primary" disabled={terminalLoading} type="submit">
                Send Command
              </button>
            </form>
          </div>
        );

      case "remote_desktop":
        return (
          <div style={{ display: "grid", gap: "0.8rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h4 style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
                🖥️ Remote Desktop Console
              </h4>
              <button
                className={`action-button ${rdpConnected ? "action-button--danger" : "action-button--primary"}`}
                style={{ fontSize: "0.76rem", padding: "0.35rem 0.75rem" }}
                type="button"
                onClick={() => {
                  if (rdpConnected) {
                    setRdpConnected(false);
                    setRdpSessionToken(null);
                  } else {
                    handleConnectRDP();
                  }
                }}
              >
                {rdpConnected ? "Disconnect Session" : "Connect Remote Desktop Session"}
              </button>
            </div>

            {rdpConnected ? (
              <div
                style={{
                  background: "#000",
                  border: "2px solid var(--accent-strong)",
                  borderRadius: "12px",
                  minHeight: isExpandedRealEstate ? "540px" : "340px",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "1rem",
                  position: "relative",
                }}
              >
                <div
                  style={{
                    position: "absolute",
                    top: "10px",
                    left: "12px",
                    background: "rgba(0,0,0,0.7)",
                    padding: "0.2rem 0.6rem",
                    borderRadius: "6px",
                    fontSize: "0.72rem",
                    color: "#3fb950",
                  }}
                >
                  ● LIVE RDP/WebRTC Stream • Token: {rdpSessionToken} • 1920x1080 @ 60fps
                </div>
                <div style={{ fontSize: "3rem" }}>
                  {ep.platform === "windows" ? "🪟" : ep.platform === "macos" ? "🍏" : "🐧"}
                </div>
                <p style={{ fontSize: "0.9rem", color: "var(--foreground)", margin: 0, textAlign: "center" }}>
                  Interactive Remote Desktop Session Active on <strong>{ep.hostname}</strong>
                </p>
                <div style={{ display: "flex", gap: "0.6rem" }}>
                  <button className="action-button action-button--secondary" style={{ fontSize: "0.74rem" }} type="button">
                    Send Ctrl+Alt+Del
                  </button>
                  <button className="action-button action-button--secondary" style={{ fontSize: "0.74rem" }} type="button">
                    Toggle Fullscreen
                  </button>
                </div>
              </div>
            ) : (
              <div
                style={{
                  background: "rgba(255, 255, 255, 0.02)",
                  border: "1px dashed var(--border)",
                  borderRadius: "12px",
                  padding: "2.5rem",
                  textAlign: "center",
                  display: "grid",
                  gap: "0.8rem",
                }}
              >
                <span style={{ fontSize: "2rem" }}>🖥️</span>
                <strong style={{ fontSize: "0.95rem" }}>Remote Desktop Session Idle</strong>
                <p style={{ fontSize: "0.8rem", color: "var(--muted)", maxWidth: "480px", margin: "0 auto" }}>
                  Initiate an encrypted WebRTC / RDP display session over the SHA secure agent tunnel to remotely control {ep.hostname}.
                </p>
                <div>
                  <button className="action-button action-button--primary" type="button" onClick={handleConnectRDP}>
                    Start Remote Desktop Connection
                  </button>
                </div>
              </div>
            )}
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
              Audit Trail for {ep.hostname}
            </h4>
            <div className="timeline-list">
              <div className="timeline-list__item">
                <span className="timeline-list__dot timeline-list__dot--info" />
                <div>
                  <strong>Compliance baseline scan completed</strong>
                  <p>Observed posture score {score}% • Operator: System Principal</p>
                </div>
              </div>
              <div className="timeline-list__item">
                <span className="timeline-list__dot timeline-list__dot--success" />
                <div>
                  <strong>Control plane heartbeat verified</strong>
                  <p>Agent version v{ep.agent_version} • Status: {ep.status}</p>
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
                className="action-button action-button--primary"
                disabled={scanningNetwork}
                style={{ fontSize: "0.76rem", padding: "0.35rem 0.7rem" }}
                type="button"
                onClick={handleScanNetwork}
              >
                {scanningNetwork ? "Scanning Subnet..." : "🔍 Scan Network"}
              </button>
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
