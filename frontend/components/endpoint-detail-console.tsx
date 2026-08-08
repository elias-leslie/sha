"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";

import {
  actionableControlsForEndpoint,
  connectivityDisplay,
  connectivityTone,
  declaresActionCapability,
  endpointScore,
  endpointStateLabel,
  endpointTone,
  formatDateTime,
  formatLocalInputValue,
  futureIso,
  approvalActionDisplay,
  createResponseAction,
  getEndpoint,
  getFixtureEndpoint,
  getFixtureApprovalGrants,
  getFixtureControlRegistry,
  getFixtureResponseActions,
  isDemoMode,
  listApprovalGrants,
  listControlRegistry,
  listEndpointResponseActions,
  platformDisplayName,
  QUARANTINE_CLIENT_ID,
  QUARANTINE_LOCATION_ID,
  recordPostureSnapshot,
  responseActionStatusDisplay,
  responseActionStatusTone,
  sendEndpointHeartbeat,
  troubleshootingScopeDisplay,
  type ApprovalAction,
  type ApprovalGrant,
  type ControlRegistryAction,
  type ControlRegistryItem,
  type EndpointDetail,
  type PostureStatus,
  type ResponseAction,
  type TroubleshootingScope,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader } from "./console-primitives";

type EndpointDetailConsoleProps = {
  endpointId: string;
  initialEndpoint?: EndpointDetail;
  initialControls?: ControlRegistryItem[];
  demoMode?: boolean;
};

const EXECUTION_HOOK_NAMES = [
  "captures_rollback_artifacts",
  "reports_execution_results",
  "supports_dry_run",
] as const;

const RESPONSE_ACTION_OPTIONS: ApprovalAction[] = [
  "collect_security_context",
  "collect_remediation_evidence",
  "inspect_control",
  "apply_control",
  "rollback_control",
  "request_elevated_troubleshooting",
];

const RESPONSE_ACTION_SCOPE_OPTIONS: TroubleshootingScope[] = [
  "security_logs",
  "service_status",
  "firewall_state",
  "identity_state",
  "process_inventory",
  "network_bindings",
];

function defaultHardeningControlId(endpoint: EndpointDetail, controls: readonly ControlRegistryItem[]) {
  return actionableControlsForEndpoint(
    controls,
    endpoint.platform,
    "apply_control",
    endpoint.declared_capabilities,
  )[0]?.control_id ?? "";
}

function buildHeartbeatForm(endpoint: EndpointDetail) {
  return {
    agent_version: endpoint.agent_version,
    platform_version: endpoint.platform_version ?? "",
    platform_profile: endpoint.last_platform_profile ?? `${endpoint.platform}_control_plane`,
    connectivity_status: (endpoint.connectivity_status ?? "online") as "online" | "degraded",
    declared_capabilities: endpoint.declared_capabilities.join(", "),
    execution_hooks: Object.entries(endpoint.execution_hooks ?? {})
      .filter(([, value]) => value)
      .map(([key]) => key)
      .join(", "),
  };
}

function buildSnapshotForm(endpoint: EndpointDetail) {
  return {
    observed_at: formatLocalInputValue(futureIso(-5)),
    platform_profile: endpoint.last_platform_profile ?? `${endpoint.platform}_control_plane`,
    control_key: `${endpoint.platform}.manual.control_probe`,
    status: "pass" as PostureStatus,
    severity: "medium",
    current_value: "aligned",
    recommended_value: "aligned",
    evidence_summary: "Manual operator snapshot recorded from the control plane.",
    reboot_required: false,
  };
}

function emptyEndpoint(endpointId: string): EndpointDetail {
  return {
    endpoint_id: endpointId,
    hostname: endpointId,
    platform: "linux",
    platform_version: null,
    agent_version: "unknown",
    client_id: QUARANTINE_CLIENT_ID,
    location_id: QUARANTINE_LOCATION_ID,
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
  };
}

export default function EndpointDetailConsole({
  endpointId,
  initialEndpoint: providedInitialEndpoint,
  initialControls,
  demoMode = isDemoMode(),
}: EndpointDetailConsoleProps) {
  const initialEndpoint = useMemo<EndpointDetail>(
    () => providedInitialEndpoint ?? (demoMode ? getFixtureEndpoint(endpointId) : undefined) ?? emptyEndpoint(endpointId),
    [demoMode, endpointId, providedInitialEndpoint],
  );

  const [endpoint, setEndpoint] = useState(initialEndpoint);
  const [source, setSource] = useState<"loading" | "demo" | "live" | "error">(
    demoMode ? "demo" : providedInitialEndpoint ? "live" : "loading",
  );
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [relatedError, setRelatedError] = useState<string | null>(null);
  const [grantsReady, setGrantsReady] = useState(demoMode);
  const [controlsReady, setControlsReady] = useState(demoMode || Boolean(initialControls));
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [heartbeatPending, setHeartbeatPending] = useState(false);
  const [snapshotPending, setSnapshotPending] = useState(false);
  const [responseActionPending, setResponseActionPending] = useState(false);
  const [grantClock, setGrantClock] = useState(() => Date.now());
  const [heartbeatDirty, setHeartbeatDirty] = useState(false);
  const [snapshotDirty, setSnapshotDirty] = useState(false);
  const [responseActions, setResponseActions] = useState<ResponseAction[]>(() =>
    demoMode ? getFixtureResponseActions(endpointId) : [],
  );
  const [approvalGrants, setApprovalGrants] = useState<ApprovalGrant[]>(() =>
    demoMode ? getFixtureApprovalGrants() : [],
  );
  const [controls, setControls] = useState<ControlRegistryItem[]>(() =>
    initialControls ?? (demoMode ? getFixtureControlRegistry() : []),
  );
  const [heartbeatForm, setHeartbeatForm] = useState(() => buildHeartbeatForm(initialEndpoint));
  const [snapshotForm, setSnapshotForm] = useState(() => buildSnapshotForm(initialEndpoint));
  const [responseActionForm, setResponseActionForm] = useState({
    approval_grant_id: "",
    action: "collect_security_context" as ApprovalAction,
    control_id: defaultHardeningControlId(initialEndpoint, controls),
    troubleshooting_scope: "process_inventory" as TroubleshootingScope,
    reason: "Queue approved bounded endpoint response action.",
  });

  const updateHeartbeatForm = (updater: (current: typeof heartbeatForm) => typeof heartbeatForm) => {
    setHeartbeatDirty(true);
    setHeartbeatForm(updater);
  };

  const updateSnapshotForm = (updater: (current: typeof snapshotForm) => typeof snapshotForm) => {
    setSnapshotDirty(true);
    setSnapshotForm(updater);
  };

  async function refreshEndpointIdentity() {
    const liveEndpoint = await getEndpoint(endpointId);
    setEndpoint(liveEndpoint);
    setIdentityError(null);
    setSource("live");
  }

  useEffect(() => {
    setEndpoint(initialEndpoint);
    setSource(demoMode ? "demo" : providedInitialEndpoint ? "live" : "loading");
    setIdentityError(null);
    setRelatedError(null);
    setGrantsReady(demoMode);
    setControlsReady(demoMode || Boolean(initialControls));
    setControls(initialControls ?? (demoMode ? getFixtureControlRegistry() : []));
    setHeartbeatDirty(false);
    setSnapshotDirty(false);
    if (!demoMode) {
      setResponseActions([]);
      setApprovalGrants([]);
    }
    setHeartbeatForm(buildHeartbeatForm(initialEndpoint));
    setSnapshotForm(buildSnapshotForm(initialEndpoint));
    setResponseActionForm((current) => ({ ...current, approval_grant_id: "" }));
  }, [demoMode, endpointId, initialControls, initialEndpoint, providedInitialEndpoint]);

  useEffect(() => {
    if (demoMode) {
      if (!getFixtureEndpoint(endpointId)) {
        setSource("error");
        setIdentityError(`Demo endpoint ${endpointId} was not found.`);
      }
      return;
    }

    let cancelled = false;
    if (!providedInitialEndpoint) {
      setSource("loading");
    }

    const identityRequest = getEndpoint(endpointId)
      .then((liveEndpoint) => {
        if (!cancelled) {
          setEndpoint(liveEndpoint);
          setSource("live");
          setIdentityError(null);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setSource("error");
          setIdentityError(caught instanceof Error ? caught.message : `Endpoint ${endpointId} was not found.`);
        }
      });
    const grantsRequest = listApprovalGrants()
      .then((grants) => {
        if (!cancelled) {
          setApprovalGrants(grants);
          setGrantsReady(true);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setGrantsReady(false);
          setRelatedError((current) =>
            [current, caught instanceof Error ? caught.message : "Unable to load endpoint approval grants."]
              .filter(Boolean)
              .join(" "),
          );
        }
      });
    const controlsRequest = listControlRegistry()
      .then((registry) => {
        if (!cancelled) {
          setControls(registry);
          setControlsReady(true);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setControlsReady(Boolean(initialControls));
          setRelatedError((current) =>
            [current, caught instanceof Error ? caught.message : "Unable to load the control registry."]
              .filter(Boolean)
              .join(" "),
          );
        }
      });
    const actionsRequest = listEndpointResponseActions(endpointId, true)
      .then((actions) => {
        if (!cancelled) {
          setResponseActions(actions);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setRelatedError((current) =>
            [current, caught instanceof Error ? caught.message : "Unable to load endpoint action history."]
              .filter(Boolean)
              .join(" "),
          );
        }
      });
    void Promise.allSettled([identityRequest, grantsRequest, controlsRequest, actionsRequest]);

    return () => {
      cancelled = true;
    };
  }, [demoMode, endpointId, initialControls, providedInitialEndpoint]);

  useEffect(() => {
    if (!heartbeatDirty) {
      setHeartbeatForm(buildHeartbeatForm(endpoint));
    }
    if (!snapshotDirty) {
      setSnapshotForm(buildSnapshotForm(endpoint));
    }
  }, [endpoint, heartbeatDirty, snapshotDirty]);

  const availableResponseActions = useMemo(
    () =>
      RESPONSE_ACTION_OPTIONS.filter((action) => {
        if (action === "apply_control" || action === "rollback_control") {
          return actionableControlsForEndpoint(
            controls,
            endpoint.platform,
            action,
            endpoint.declared_capabilities,
          ).length > 0;
        }
        return declaresActionCapability(endpoint.declared_capabilities, action);
      }),
    [controls, endpoint.declared_capabilities, endpoint.platform],
  );
  const actionableControls = useMemo(
    () =>
      responseActionForm.action === "apply_control" || responseActionForm.action === "rollback_control"
        ? actionableControlsForEndpoint(
            controls,
            endpoint.platform,
            responseActionForm.action as ControlRegistryAction,
            endpoint.declared_capabilities,
          )
        : [],
    [controls, endpoint.declared_capabilities, endpoint.platform, responseActionForm.action],
  );
  const executionHooks = useMemo(() => Object.entries(endpoint.execution_hooks ?? {}).filter(([, value]) => value), [endpoint.execution_hooks]);

  useEffect(() => {
    setResponseActionForm((current) => {
      const action = availableResponseActions.includes(current.action) ? current.action : availableResponseActions[0];
      if (!action) {
        return current;
      }
      return action === current.action ? current : { ...current, action };
    });
  }, [availableResponseActions]);

  useEffect(() => {
    setResponseActionForm((current) =>
      actionableControls.some((control) => control.control_id === current.control_id)
        ? current
        : { ...current, control_id: actionableControls[0]?.control_id ?? "" },
    );
  }, [actionableControls]);

  const needsResponseActionControl = responseActionForm.action === "apply_control" || responseActionForm.action === "rollback_control";
  const needsResponseActionScope = responseActionForm.action !== "collect_remediation_evidence" && !needsResponseActionControl;
  useEffect(() => {
    const now = Date.now();
    setGrantClock(now);
    const nextExpiry = approvalGrants
      .map((grant) => new Date(grant.expires_at).getTime())
      .filter((expiresAt) => expiresAt > now)
      .sort((left, right) => left - right)[0];
    if (!nextExpiry) {
      return;
    }
    const timer = window.setTimeout(() => setGrantClock(Date.now()), Math.max(0, nextExpiry - now + 1));
    return () => window.clearTimeout(timer);
  }, [approvalGrants]);

  const eligibleApprovalGrants = useMemo(
    () =>
      approvalGrants.filter(
        (grant) =>
          grant.status === "approved" &&
          new Date(grant.expires_at).getTime() > grantClock &&
          grant.endpoint_ids.includes(endpointId) &&
          declaresActionCapability(
            endpoint.declared_capabilities,
            responseActionForm.action,
            needsResponseActionControl ? responseActionForm.control_id : null,
          ) &&
          grant.allowed_actions.includes(responseActionForm.action) &&
          (!needsResponseActionControl || grant.control_ids.includes(responseActionForm.control_id)) &&
          (!needsResponseActionScope || grant.troubleshooting_scopes.includes(responseActionForm.troubleshooting_scope)),
      ),
    [
      approvalGrants,
      endpoint.declared_capabilities,
      endpointId,
      grantClock,
      needsResponseActionControl,
      needsResponseActionScope,
      responseActionForm.action,
      responseActionForm.control_id,
      responseActionForm.troubleshooting_scope,
    ],
  );

  const effectiveApprovalGrantId = eligibleApprovalGrants.some(
    (grant) => grant.approval_grant_id === responseActionForm.approval_grant_id,
  )
    ? responseActionForm.approval_grant_id
    : eligibleApprovalGrants.length === 1
      ? eligibleApprovalGrants[0].approval_grant_id
      : "";

  async function handleHeartbeat(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (source !== "live") {
      return;
    }
    setHeartbeatPending(true);
    setFeedback(null);
    setError(null);

    try {
      const enabledHooks = heartbeatForm.execution_hooks
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      const hooks = EXECUTION_HOOK_NAMES.reduce<Record<string, boolean>>(
        (result, hook) => ({ ...result, [hook]: enabledHooks.includes(hook) }),
        {},
      );
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
      await refreshEndpointIdentity();
      setHeartbeatDirty(false);
      setFeedback("Heartbeat accepted.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to send heartbeat.");
    } finally {
      setHeartbeatPending(false);
    }
  }

  async function handleSnapshot(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (source !== "live") {
      return;
    }
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
      await refreshEndpointIdentity();
      setSnapshotDirty(false);
      setFeedback("Posture snapshot recorded.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to record posture snapshot.");
    } finally {
      setSnapshotPending(false);
    }
  }

  async function handleCreateResponseAction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      source !== "live" ||
      !grantsReady ||
      !effectiveApprovalGrantId ||
      (needsResponseActionControl && (!controlsReady || !responseActionForm.control_id))
    ) {
      return;
    }
    setResponseActionPending(true);
    setFeedback(null);
    setError(null);

    try {
      const created = await createResponseAction({
        endpoint_id: endpointId,
        approval_grant_id: effectiveApprovalGrantId,
        action: responseActionForm.action,
        control_id: needsResponseActionControl ? responseActionForm.control_id : null,
        troubleshooting_scope: needsResponseActionScope ? responseActionForm.troubleshooting_scope : null,
        idempotency_key: crypto.randomUUID(),
        reason: responseActionForm.reason,
      });
      setResponseActions((current) => [...current.filter((item) => item.response_action_id !== created.response_action_id), created]);
      setSource("live");
      setFeedback(`Queued response action ${created.response_action_id}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to queue response action.");
    } finally {
      setResponseActionPending(false);
    }
  }

  if (source === "loading") {
    return <EmptyState title={`Loading endpoint ${endpointId}`} body="Waiting for live endpoint identity." />;
  }

  if (source === "error") {
    return (
      <EmptyState
        title={`Endpoint ${endpointId} unavailable`}
        body={`Live endpoint identity could not be loaded: ${identityError ?? "unknown endpoint"}`}
      />
    );
  }

  if (source === "demo") {
    return (
      <Panel>
        <SectionHeader
          eyebrow="Demo endpoint identity"
          title={`Endpoint ${endpoint.hostname}`}
          description="Fixture-only endpoint preview. Heartbeat, posture, and response action surfaces are disabled in demo mode."
        />
        <div className="detail-grid">
          <div className="detail-card"><span>Endpoint id</span><strong>{endpoint.endpoint_id}</strong></div>
          <div className="detail-card"><span>Platform</span><strong>{platformDisplayName(endpoint.platform)} {endpoint.platform_version ?? ""}</strong></div>
          <div className="detail-card"><span>Containment</span><strong>{endpointStateLabel(endpoint)} • score {endpointScore(endpoint) ?? "--"}</strong></div>
          <div className="detail-card"><span>Signal</span><strong>{connectivityDisplay(endpoint.connectivity_status)} • last seen {formatDateTime(endpoint.last_seen_at)}</strong></div>
        </div>
        <Badge tone="warning">Demo fixture — mutations disabled</Badge>
      </Panel>
    );
  }

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="System Posture Detail"
            title={endpoint.hostname}
            description="Detailed system posture summary, heartbeat status, and posture inspection."
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
              <span>Posture State</span>
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
          {relatedError ? <p className="inline-feedback inline-feedback--danger" role="alert">Endpoint action resources load failed: {relatedError}</p> : null}
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Heartbeat Signal"
            title="Send heartbeat"
            description="Use the same endpoint heartbeat contract the agent uses to refresh connectivity and capability state."
          />
          <form className="form-grid" onSubmit={handleHeartbeat}>
            <label className="field" htmlFor="heartbeat-agent-version">
              <span className="field__label">Agent version</span>
              <input
                className="field__control"
                id="heartbeat-agent-version"
                onChange={(event) => updateHeartbeatForm((current) => ({ ...current, agent_version: event.target.value }))}
                value={heartbeatForm.agent_version}
              />
            </label>
            <label className="field" htmlFor="heartbeat-platform-version">
              <span className="field__label">Platform version</span>
              <input
                className="field__control"
                id="heartbeat-platform-version"
                onChange={(event) => updateHeartbeatForm((current) => ({ ...current, platform_version: event.target.value }))}
                value={heartbeatForm.platform_version}
              />
            </label>
            <label className="field" htmlFor="heartbeat-platform-profile">
              <span className="field__label">Platform profile</span>
              <input
                className="field__control"
                id="heartbeat-platform-profile"
                onChange={(event) => updateHeartbeatForm((current) => ({ ...current, platform_profile: event.target.value }))}
                value={heartbeatForm.platform_profile}
              />
            </label>
            <label className="field" htmlFor="heartbeat-connectivity-status">
              <span className="field__label">Connectivity</span>
              <select
                className="field__control"
                id="heartbeat-connectivity-status"
                onChange={(event) =>
                  updateHeartbeatForm((current) => ({
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
                onChange={(event) => updateHeartbeatForm((current) => ({ ...current, declared_capabilities: event.target.value }))}
                value={heartbeatForm.declared_capabilities}
              />
            </label>
            <label className="field field--span-2" htmlFor="heartbeat-execution-hooks">
              <span className="field__label">Execution hooks</span>
              <input
                className="field__control"
                id="heartbeat-execution-hooks"
                onChange={(event) => updateHeartbeatForm((current) => ({ ...current, execution_hooks: event.target.value }))}
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
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, observed_at: event.target.value }))}
                type="datetime-local"
                value={snapshotForm.observed_at}
              />
            </label>
            <label className="field" htmlFor="snapshot-platform-profile">
              <span className="field__label">Platform profile</span>
              <input
                className="field__control"
                id="snapshot-platform-profile"
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, platform_profile: event.target.value }))}
                value={snapshotForm.platform_profile}
              />
            </label>
            <label className="field field--span-2" htmlFor="snapshot-control-key">
              <span className="field__label">Control key</span>
              <input
                className="field__control"
                id="snapshot-control-key"
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, control_key: event.target.value }))}
                value={snapshotForm.control_key}
              />
            </label>
            <label className="field" htmlFor="snapshot-status">
              <span className="field__label">Status</span>
              <select
                className="field__control"
                id="snapshot-status"
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, status: event.target.value as PostureStatus }))}
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
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, severity: event.target.value }))}
                value={snapshotForm.severity}
              />
            </label>
            <label className="field" htmlFor="snapshot-current-value">
              <span className="field__label">Current value</span>
              <input
                className="field__control"
                id="snapshot-current-value"
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, current_value: event.target.value }))}
                value={snapshotForm.current_value}
              />
            </label>
            <label className="field" htmlFor="snapshot-recommended-value">
              <span className="field__label">Recommended value</span>
              <input
                className="field__control"
                id="snapshot-recommended-value"
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, recommended_value: event.target.value }))}
                value={snapshotForm.recommended_value}
              />
            </label>
            <label className="field field--span-2" htmlFor="snapshot-evidence-summary">
              <span className="field__label">Evidence summary</span>
              <textarea
                className="field__control field__control--textarea"
                id="snapshot-evidence-summary"
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, evidence_summary: event.target.value }))}
                value={snapshotForm.evidence_summary}
              />
            </label>
            <label className="checkbox-field" htmlFor="snapshot-reboot-required">
              <input
                checked={snapshotForm.reboot_required}
                id="snapshot-reboot-required"
                onChange={(event) => updateSnapshotForm((current) => ({ ...current, reboot_required: event.target.checked }))}
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
            eyebrow="Response actions"
            title="Approved work trail"
            description="Queued and completed typed actions for incident response, hardening, and rollback."
          />
          <form className="form-grid" onSubmit={handleCreateResponseAction}>
            <label className="field field--span-2" htmlFor="response-action-grant">
              <span className="field__label">Approval grant</span>
              <select
                className="field__control"
                disabled={!eligibleApprovalGrants.length}
                id="response-action-grant"
                onChange={(event) => setResponseActionForm((current) => ({ ...current, approval_grant_id: event.target.value }))}
                required
                value={effectiveApprovalGrantId}
              >
                {!eligibleApprovalGrants.length ? (
                  <option value="">No eligible active grant for this action and scope</option>
                ) : eligibleApprovalGrants.length > 1 ? (
                  <>
                    <option value="">Select an eligible grant</option>
                    {eligibleApprovalGrants.map((grant) => (
                      <option key={grant.approval_grant_id} value={grant.approval_grant_id}>
                        {grant.approval_grant_id} — expires {formatDateTime(grant.expires_at)}
                      </option>
                    ))}
                  </>
                ) : (
                  <option value={eligibleApprovalGrants[0].approval_grant_id}>
                    {eligibleApprovalGrants[0].approval_grant_id} — expires {formatDateTime(eligibleApprovalGrants[0].expires_at)}
                  </option>
                )}
              </select>
            </label>
            <label className="field" htmlFor="response-action-kind">
              <span className="field__label">Action</span>
              <select
                className="field__control"
                disabled={!availableResponseActions.length}
                id="response-action-kind"
                onChange={(event) =>
                  setResponseActionForm((current) => ({ ...current, action: event.target.value as ApprovalAction }))
                }
                value={responseActionForm.action}
              >
                {!availableResponseActions.length ? <option value="">No declared response actions</option> : null}
                {availableResponseActions.map((action) => (
                  <option key={action} value={action}>
                    {approvalActionDisplay(action)}
                  </option>
                ))}
              </select>
            </label>
            {responseActionForm.action === "apply_control" || responseActionForm.action === "rollback_control" ? (
              <label className="field" htmlFor="response-action-control">
                <span className="field__label">Control id</span>
                <select
                  className="field__control"
                  disabled={!actionableControls.length}
                  id="response-action-control"
                  onChange={(event) => setResponseActionForm((current) => ({ ...current, control_id: event.target.value }))}
                  required
                  value={responseActionForm.control_id}
                >
                  {actionableControls.length ? (
                    actionableControls.map((control) => (
                      <option key={control.control_id} value={control.control_id}>
                        {control.title}
                      </option>
                    ))
                  ) : (
                    <option value="">No mutable controls for {platformDisplayName(endpoint.platform)}</option>
                  )}
                </select>
              </label>
            ) : responseActionForm.action === "collect_remediation_evidence" ? null : (
              <label className="field" htmlFor="response-action-scope">
                <span className="field__label">Troubleshooting scope</span>
                <select
                  className="field__control"
                  id="response-action-scope"
                  onChange={(event) =>
                    setResponseActionForm((current) => ({
                      ...current,
                      troubleshooting_scope: event.target.value as TroubleshootingScope,
                    }))
                  }
                  value={responseActionForm.troubleshooting_scope}
                >
                  {RESPONSE_ACTION_SCOPE_OPTIONS.map((scope) => (
                    <option key={scope} value={scope}>
                      {troubleshootingScopeDisplay(scope)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <p className="inline-feedback field--span-2">
              Action attribution comes from the authenticated API principal.
            </p>
            <label className="field field--span-2" htmlFor="response-action-reason">
              <span className="field__label">Reason</span>
              <textarea
                className="field__control field__control--textarea"
                id="response-action-reason"
                onChange={(event) => setResponseActionForm((current) => ({ ...current, reason: event.target.value }))}
                value={responseActionForm.reason}
              />
            </label>
            <div className="form-actions">
              <button
                className="action-button action-button--primary"
                disabled={
                  responseActionPending ||
                  !grantsReady ||
                  !effectiveApprovalGrantId ||
                  !availableResponseActions.length ||
                  (needsResponseActionControl && (!controlsReady || !responseActionForm.control_id))
                }
                type="submit"
              >
                {responseActionPending ? "Queueing…" : "Queue response action"}
              </button>
            </div>
          </form>
          {responseActions.length ? (
            <div className="operator-list">
              {responseActions.map((action) => (
                <div className="operator-list__item" key={action.response_action_id}>
                  <div>
                    <div className="operator-list__title-row">
                      <strong>{approvalActionDisplay(action.action)}</strong>
                      <Badge tone={responseActionStatusTone(action.status)}>{responseActionStatusDisplay(action.status)}</Badge>
                    </div>
                    <p>{action.reason}</p>
                    <p>
                      {action.control_id ?? (action.troubleshooting_scope ? troubleshootingScopeDisplay(action.troubleshooting_scope) : "No scope")} • requested by {action.requested_by} • {formatDateTime(action.created_at)}
                    </p>
                    {action.status === "leased" ? (
                      <p>
                        Attempt {action.attempt_count} • claimed {formatDateTime(action.leased_at)} • lease expires {formatDateTime(action.lease_expires_at)}
                      </p>
                    ) : null}
                    {action.result_summary ? <p>{action.result_summary}</p> : null}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No response actions" body="Approval-backed hardening and incident-response actions will appear here." />
          )}
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
