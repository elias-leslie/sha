"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";

import {
  connectivityDisplay,
  connectivityTone,
  endpointScore,
  endpointStateLabel,
  endpointTone,
  formatDateTime,
  formatLocalInputValue,
  futureIso,
  getEndpoint,
  getFixtureEndpoint,
  platformDisplayName,
  recordPostureSnapshot,
  sendEndpointHeartbeat,
  type EndpointDetail,
  type PostureStatus,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader } from "./console-primitives";

type EndpointDetailConsoleProps = {
  endpointId: string;
  initialEndpoint?: EndpointDetail;
};

export default function EndpointDetailConsole({
  endpointId,
  initialEndpoint = getFixtureEndpoint(endpointId) ?? {
    endpoint_id: endpointId,
    hostname: endpointId,
    platform: "linux",
    platform_version: null,
    agent_version: "unknown",
    tenant_id: null,
    site_id: null,
    status: "pending",
    connectivity_status: null,
    last_seen_at: new Date().toISOString(),
    last_heartbeat_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_platform_profile: null,
    declared_capabilities: [],
    execution_hooks: null,
    latest_posture_summary: null,
    latest_results: [],
  },
}: EndpointDetailConsoleProps) {
  const [endpoint, setEndpoint] = useState(initialEndpoint);
  const [source, setSource] = useState<"fixture" | "live">("fixture");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [heartbeatPending, setHeartbeatPending] = useState(false);
  const [snapshotPending, setSnapshotPending] = useState(false);
  const [heartbeatForm, setHeartbeatForm] = useState({
    agent_version: initialEndpoint.agent_version,
    platform_version: initialEndpoint.platform_version ?? "",
    platform_profile: initialEndpoint.last_platform_profile ?? `${initialEndpoint.platform}_control_plane`,
    connectivity_status: (initialEndpoint.connectivity_status ?? "online") as "online" | "degraded",
    declared_capabilities: initialEndpoint.declared_capabilities.join(", "),
    execution_hooks: Object.entries(initialEndpoint.execution_hooks ?? { heartbeat: true, posture_snapshot: true })
      .filter(([, value]) => value)
      .map(([key]) => key)
      .join(", "),
  });
  const [snapshotForm, setSnapshotForm] = useState({
    observed_at: formatLocalInputValue(futureIso(-5)),
    platform_profile: initialEndpoint.last_platform_profile ?? `${initialEndpoint.platform}_control_plane`,
    control_key: `${initialEndpoint.platform}.manual.control_probe`,
    status: "pass" as PostureStatus,
    severity: "medium",
    current_value: "aligned",
    recommended_value: "aligned",
    evidence_summary: "Manual operator snapshot recorded from the control plane.",
    reboot_required: false,
  });

  async function refreshEndpoint() {
    const liveEndpoint = await getEndpoint(endpointId);
    setEndpoint(liveEndpoint);
    setSource("live");
  }

  useEffect(() => {
    let cancelled = false;
    getEndpoint(endpointId)
      .then((liveEndpoint) => {
        if (!cancelled) {
          setEndpoint(liveEndpoint);
          setSource("live");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSource("fixture");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [endpointId]);

  const executionHooks = useMemo(() => Object.entries(endpoint.execution_hooks ?? {}).filter(([, value]) => value), [endpoint.execution_hooks]);

  async function handleHeartbeat(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setHeartbeatPending(true);
    setFeedback(null);
    setError(null);

    try {
      const hooks = heartbeatForm.execution_hooks
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)
        .reduce<Record<string, boolean>>((result, hook) => ({ ...result, [hook]: true }), {});
      await sendEndpointHeartbeat(endpointId, {
        agent_version: heartbeatForm.agent_version,
        platform_version: heartbeatForm.platform_version || null,
        platform_profile: heartbeatForm.platform_profile,
        connectivity_status: heartbeatForm.connectivity_status,
        declared_capabilities: heartbeatForm.declared_capabilities
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean),
        execution_hooks: hooks,
      });
      await refreshEndpoint();
      setFeedback("Heartbeat accepted.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to send heartbeat.");
    } finally {
      setHeartbeatPending(false);
    }
  }

  async function handleSnapshot(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSnapshotPending(true);
    setFeedback(null);
    setError(null);

    try {
      await recordPostureSnapshot({
        endpoint_id: endpointId,
        observed_at: new Date(snapshotForm.observed_at).toISOString(),
        platform_profile: snapshotForm.platform_profile,
        results: [
          {
            control_key: snapshotForm.control_key,
            status: snapshotForm.status,
            current_value: snapshotForm.current_value || null,
            recommended_value: snapshotForm.recommended_value || null,
            severity: snapshotForm.severity || null,
            evidence_summary: snapshotForm.evidence_summary,
            reboot_required: snapshotForm.reboot_required,
          },
        ],
      });
      await refreshEndpoint();
      setFeedback("Posture snapshot recorded.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to record posture snapshot.");
    } finally {
      setSnapshotPending(false);
    }
  }

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Endpoint identity"
            title={`Endpoint ${endpoint.hostname}`}
            description="Live endpoint detail route with heartbeat and posture write surfaces wired to the backend APIs."
          />
          <div className="detail-grid">
            <div className="detail-card">
              <span>Endpoint id</span>
              <strong>{endpoint.endpoint_id}</strong>
            </div>
            <div className="detail-card">
              <span>Platform</span>
              <strong>{platformDisplayName(endpoint.platform)} {endpoint.platform_version ?? ""}</strong>
            </div>
            <div className="detail-card">
              <span>Containment</span>
              <strong>{endpointStateLabel(endpoint)} • score {endpointScore(endpoint) ?? "--"}</strong>
            </div>
            <div className="detail-card">
              <span>Signal</span>
              <strong>{connectivityDisplay(endpoint.connectivity_status)} • last seen {formatDateTime(endpoint.last_seen_at)}</strong>
            </div>
          </div>
          <div className="tag-row">
            <Badge tone={endpointTone(endpoint)}>{endpointStateLabel(endpoint)}</Badge>
            <Badge tone={connectivityTone(endpoint.connectivity_status)}>{connectivityDisplay(endpoint.connectivity_status)}</Badge>
            <Badge tone={source === "live" ? "success" : "warning"}>{source === "live" ? "Live endpoint" : "Fixture endpoint"}</Badge>
            {endpoint.last_platform_profile ? <Badge>{endpoint.last_platform_profile}</Badge> : null}
          </div>
          {feedback ? <p className="inline-feedback inline-feedback--success">{feedback}</p> : null}
          {error ? <p className="inline-feedback inline-feedback--danger">{error}</p> : null}
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Heartbeat rail"
            title="Send heartbeat"
            description="Use the same endpoint heartbeat contract the agent uses to refresh connectivity and capability state."
          />
          <form className="form-grid" onSubmit={handleHeartbeat}>
            <label className="field" htmlFor="heartbeat-agent-version">
              <span className="field__label">Agent version</span>
              <input
                className="field__control"
                id="heartbeat-agent-version"
                onChange={(event) => setHeartbeatForm((current) => ({ ...current, agent_version: event.target.value }))}
                value={heartbeatForm.agent_version}
              />
            </label>
            <label className="field" htmlFor="heartbeat-platform-version">
              <span className="field__label">Platform version</span>
              <input
                className="field__control"
                id="heartbeat-platform-version"
                onChange={(event) => setHeartbeatForm((current) => ({ ...current, platform_version: event.target.value }))}
                value={heartbeatForm.platform_version}
              />
            </label>
            <label className="field" htmlFor="heartbeat-platform-profile">
              <span className="field__label">Platform profile</span>
              <input
                className="field__control"
                id="heartbeat-platform-profile"
                onChange={(event) => setHeartbeatForm((current) => ({ ...current, platform_profile: event.target.value }))}
                value={heartbeatForm.platform_profile}
              />
            </label>
            <label className="field" htmlFor="heartbeat-connectivity-status">
              <span className="field__label">Connectivity</span>
              <select
                className="field__control"
                id="heartbeat-connectivity-status"
                onChange={(event) =>
                  setHeartbeatForm((current) => ({
                    ...current,
                    connectivity_status: event.target.value as "online" | "degraded",
                  }))
                }
                value={heartbeatForm.connectivity_status}
              >
                <option value="online">online</option>
                <option value="degraded">degraded</option>
              </select>
            </label>
            <label className="field field--span-2" htmlFor="heartbeat-declared-capabilities">
              <span className="field__label">Declared capabilities</span>
              <input
                className="field__control"
                id="heartbeat-declared-capabilities"
                onChange={(event) => setHeartbeatForm((current) => ({ ...current, declared_capabilities: event.target.value }))}
                value={heartbeatForm.declared_capabilities}
              />
            </label>
            <label className="field field--span-2" htmlFor="heartbeat-execution-hooks">
              <span className="field__label">Execution hooks</span>
              <input
                className="field__control"
                id="heartbeat-execution-hooks"
                onChange={(event) => setHeartbeatForm((current) => ({ ...current, execution_hooks: event.target.value }))}
                value={heartbeatForm.execution_hooks}
              />
            </label>
            <div className="form-actions">
              <button className="action-button action-button--primary" disabled={heartbeatPending} type="submit">
                {heartbeatPending ? "Sending…" : "Send heartbeat"}
              </button>
            </div>
          </form>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Posture intake"
            title="Record posture snapshot"
            description="Write a single control result into the latest posture lane and refresh the endpoint detail in place."
          />
          <form className="form-grid" onSubmit={handleSnapshot}>
            <label className="field" htmlFor="snapshot-observed-at">
              <span className="field__label">Observed at</span>
              <input
                className="field__control"
                id="snapshot-observed-at"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, observed_at: event.target.value }))}
                type="datetime-local"
                value={snapshotForm.observed_at}
              />
            </label>
            <label className="field" htmlFor="snapshot-platform-profile">
              <span className="field__label">Platform profile</span>
              <input
                className="field__control"
                id="snapshot-platform-profile"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, platform_profile: event.target.value }))}
                value={snapshotForm.platform_profile}
              />
            </label>
            <label className="field field--span-2" htmlFor="snapshot-control-key">
              <span className="field__label">Control key</span>
              <input
                className="field__control"
                id="snapshot-control-key"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, control_key: event.target.value }))}
                value={snapshotForm.control_key}
              />
            </label>
            <label className="field" htmlFor="snapshot-status">
              <span className="field__label">Status</span>
              <select
                className="field__control"
                id="snapshot-status"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, status: event.target.value as PostureStatus }))}
                value={snapshotForm.status}
              >
                <option value="pass">pass</option>
                <option value="warn">warn</option>
                <option value="fail">fail</option>
                <option value="error">error</option>
                <option value="not_applicable">not_applicable</option>
              </select>
            </label>
            <label className="field" htmlFor="snapshot-severity">
              <span className="field__label">Severity</span>
              <input
                className="field__control"
                id="snapshot-severity"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, severity: event.target.value }))}
                value={snapshotForm.severity}
              />
            </label>
            <label className="field" htmlFor="snapshot-current-value">
              <span className="field__label">Current value</span>
              <input
                className="field__control"
                id="snapshot-current-value"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, current_value: event.target.value }))}
                value={snapshotForm.current_value}
              />
            </label>
            <label className="field" htmlFor="snapshot-recommended-value">
              <span className="field__label">Recommended value</span>
              <input
                className="field__control"
                id="snapshot-recommended-value"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, recommended_value: event.target.value }))}
                value={snapshotForm.recommended_value}
              />
            </label>
            <label className="field field--span-2" htmlFor="snapshot-evidence-summary">
              <span className="field__label">Evidence summary</span>
              <textarea
                className="field__control field__control--textarea"
                id="snapshot-evidence-summary"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, evidence_summary: event.target.value }))}
                value={snapshotForm.evidence_summary}
              />
            </label>
            <label className="checkbox-field" htmlFor="snapshot-reboot-required">
              <input
                checked={snapshotForm.reboot_required}
                id="snapshot-reboot-required"
                onChange={(event) => setSnapshotForm((current) => ({ ...current, reboot_required: event.target.checked }))}
                type="checkbox"
              />
              <span>Reboot required</span>
            </label>
            <div className="form-actions">
              <button className="action-button action-button--secondary" disabled={snapshotPending} type="submit">
                {snapshotPending ? "Recording…" : "Record posture snapshot"}
              </button>
            </div>
          </form>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Capabilities"
            title="Declared endpoint surface"
            description="Execution hooks and declared capabilities from the latest heartbeat payload."
          />
          <div className="tag-row">
            {endpoint.declared_capabilities.length ? endpoint.declared_capabilities.map((capability) => <Badge key={capability}>{capability}</Badge>) : <Badge tone="warning">No declared capabilities</Badge>}
          </div>
          <div className="tag-row">
            {executionHooks.length ? executionHooks.map(([hook]) => <Badge key={hook} tone="success">{hook}</Badge>) : <Badge tone="info">No execution hooks</Badge>}
          </div>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Latest results"
            title="Control evidence"
            description="Most recent posture results captured for this endpoint."
          />
          {endpoint.latest_results.length ? (
            <div className="operator-list">
              {endpoint.latest_results.map((result) => (
                <div className="operator-list__item" key={result.control_key}>
                  <div>
                    <div className="operator-list__title-row">
                      <strong>{result.control_key}</strong>
                      <Badge tone={result.status === "pass" ? "success" : result.status === "warn" ? "warning" : result.status === "fail" || result.status === "error" ? "danger" : "info"}>{result.status}</Badge>
                    </div>
                    <p>{result.evidence_summary}</p>
                    <p>
                      current {result.current_value ?? "n/a"} • recommended {result.recommended_value ?? "n/a"} • severity {result.severity ?? "n/a"}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No posture evidence" body="Use the snapshot writer above to inject the first result for this endpoint." />
          )}
        </Panel>
      </section>
    </>
  );
}
