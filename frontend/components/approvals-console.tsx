"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";

import {
  actionableControlsForEndpoint,
  approvalActionDisplay,
  approvalDecisionSummary,
  approvalRequestKindDisplay,
  approvalRiskDisplay,
  approvalRiskTone,
  approvalStatusDisplay,
  approvalStatusTone,
  createApprovalGrant,
  createApprovalRequest,
  decideApprovalRequest,
  endpointLabel,
  endpointListDisplay,
  formatDateTime,
  futureIso,
  futureLocalInput,
  getFixtureControlRegistry,
  getFixtureApprovalGrants,
  getFixtureApprovalRequests,
  getFixtureEndpoints,
  isDemoMode,
  listApprovalGrants,
  listApprovalRequests,
  listControlRegistry,
  listEndpoints,
  localInputToIso,
  titleCaseKey,
  troubleshootingScopeDisplay,
  type ApprovalAction,
  type ApprovalGrant,
  type ApprovalRequest,
  type ControlRegistryItem,
  type EndpointInventoryItem,
  type TroubleshootingScope,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";

type ApprovalsConsoleProps = {
  initialRequests?: ApprovalRequest[];
  initialGrants?: ApprovalGrant[];
  initialEndpoints?: EndpointInventoryItem[];
  initialControls?: ControlRegistryItem[];
  demoMode?: boolean;
};

const TROUBLESHOOTING_SCOPE_OPTIONS: TroubleshootingScope[] = [
  "security_logs",
  "service_status",
  "firewall_state",
  "identity_state",
  "process_inventory",
  "network_bindings",
];

function firstHardeningControlForEndpoint(
  endpoint: EndpointInventoryItem | undefined,
  controls: readonly ControlRegistryItem[],
) {
  return actionableControlsForEndpoint(
    controls,
    endpoint?.platform,
    "apply_control",
    endpoint?.declared_capabilities ?? [],
  )[0]?.control_id ?? "";
}

export default function ApprovalsConsole({
  initialRequests,
  initialGrants,
  initialEndpoints,
  initialControls,
  demoMode = isDemoMode(),
}: ApprovalsConsoleProps) {
  const [requests, setRequests] = useState(() => initialRequests ?? (demoMode ? getFixtureApprovalRequests() : []));
  const [grants, setGrants] = useState(() => initialGrants ?? (demoMode ? getFixtureApprovalGrants() : []));
  const [endpoints, setEndpoints] = useState(() => initialEndpoints ?? (demoMode ? getFixtureEndpoints() : []));
  const [controls, setControls] = useState(() =>
    initialControls ?? (demoMode ? getFixtureControlRegistry() : []),
  );
  const [resourceState, setResourceState] = useState(() => ({
    requests: demoMode || Boolean(initialRequests),
    grants: demoMode || Boolean(initialGrants),
    endpoints: demoMode || Boolean(initialEndpoints),
    controls: demoMode || Boolean(initialControls),
    loading: !demoMode,
  }));
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(
    () => requests.find((item) => item.status === "pending")?.approval_request_id ?? null,
  );
  const [decisionComment, setDecisionComment] = useState("Approved for the maintenance window.");
  const [decisionExpiry, setDecisionExpiry] = useState(futureLocalInput(45));
  const [decisionPending, setDecisionPending] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [requestPending, setRequestPending] = useState(false);
  const [grantPending, setGrantPending] = useState(false);
  const [requestForm, setRequestForm] = useState(() => {
    const endpointId = endpoints.length === 1 ? endpoints[0].endpoint_id : "";
    return {
      endpoint_id: endpointId,
      request_kind: "hardening_change" as ApprovalRequest["request_kind"],
      control_id: firstHardeningControlForEndpoint(
        endpoints.find((item) => item.endpoint_id === endpointId),
        controls,
      ),
      reason: "Approve guarded hardening rollout",
      risk: "high" as ApprovalRequest["risk"],
      ttl: 60,
      troubleshooting_scopes: ["security_logs"] as TroubleshootingScope[],
    };
  });
  const [grantForm, setGrantForm] = useState(() => ({
    endpoint_id: endpoints.length === 1 ? endpoints[0].endpoint_id : "",
    reason: "Temporary troubleshooting grant",
    expires_at: futureLocalInput(90),
    troubleshooting_scopes: ["security_logs"] as TroubleshootingScope[],
  }));

  useEffect(() => {
    if (demoMode) {
      setRequests(initialRequests ?? getFixtureApprovalRequests());
      setGrants(initialGrants ?? getFixtureApprovalGrants());
      setEndpoints(initialEndpoints ?? getFixtureEndpoints());
      setControls(initialControls ?? getFixtureControlRegistry());
      setResourceState({ requests: true, grants: true, endpoints: true, controls: true, loading: false });
      setLoadError(null);
      return;
    }

    let cancelled = false;
    setResourceState((current) => ({ ...current, loading: true }));
    setLoadError(null);
    Promise.allSettled([listApprovalRequests(), listApprovalGrants(), listEndpoints(), listControlRegistry()]).then(
      ([requestResult, grantResult, endpointResult, controlResult]) => {
        if (cancelled) {
          return;
        }
        if (requestResult.status === "fulfilled") {
          setRequests(requestResult.value);
        }
        if (grantResult.status === "fulfilled") {
          setGrants(grantResult.value);
        }
        if (endpointResult.status === "fulfilled") {
          setEndpoints(endpointResult.value);
        }
        if (controlResult.status === "fulfilled") {
          setControls(controlResult.value);
        }
        const failures = [requestResult, grantResult, endpointResult, controlResult].filter(
          (result): result is PromiseRejectedResult => result.status === "rejected",
        );
        setResourceState({
          requests: requestResult.status === "fulfilled" || initialRequests !== undefined,
          grants: grantResult.status === "fulfilled" || initialGrants !== undefined,
          endpoints: endpointResult.status === "fulfilled" || initialEndpoints !== undefined,
          controls: controlResult.status === "fulfilled" || initialControls !== undefined,
          loading: false,
        });
        setLoadError(
          failures.length
            ? failures
                .map((result) => (result.reason instanceof Error ? result.reason.message : "Unable to load an approval resource."))
                .join(" ")
            : null,
        );
      },
    );

    return () => {
      cancelled = true;
    };
  }, [demoMode, initialControls, initialEndpoints, initialGrants, initialRequests]);

  useEffect(() => {
    const chooseEndpoint = (current: string) => {
      if (endpoints.some((endpoint) => endpoint.endpoint_id === current)) {
        return current;
      }
      return endpoints.length === 1 ? endpoints[0].endpoint_id : "";
    };
    setRequestForm((current) => {
      const endpointId = chooseEndpoint(current.endpoint_id);
      return {
        ...current,
        endpoint_id: endpointId,
        control_id:
          endpointId === current.endpoint_id
            ? current.control_id
            : firstHardeningControlForEndpoint(
                endpoints.find((endpoint) => endpoint.endpoint_id === endpointId),
                controls,
              ),
      };
    });
    setGrantForm((current) => ({ ...current, endpoint_id: chooseEndpoint(current.endpoint_id) }));
  }, [controls, endpoints]);

  const pendingRequests = useMemo(() => requests.filter((request) => request.status === "pending"), [requests]);
  const activeGrants = useMemo(() => grants.filter((grant) => grant.status === "approved"), [grants]);
  const auditHistory = useMemo(() => requests.filter((request) => request.status !== "pending"), [requests]);
  const requestEndpoint = useMemo(
    () => endpoints.find((endpoint) => endpoint.endpoint_id === requestForm.endpoint_id),
    [endpoints, requestForm.endpoint_id],
  );
  const actionableControls = useMemo(
    () =>
      actionableControlsForEndpoint(
        controls,
        requestEndpoint?.platform,
        "apply_control",
        requestEndpoint?.declared_capabilities ?? [],
      ),
    [controls, requestEndpoint?.declared_capabilities, requestEndpoint?.platform],
  );
  const selectedRequest = useMemo(() => {
    return requests.find((request) => request.approval_request_id === selectedId) ?? pendingRequests[0] ?? requests[0] ?? null;
  }, [pendingRequests, requests, selectedId]);

  useEffect(() => {
    if (requestForm.request_kind !== "hardening_change") {
      return;
    }
    if (actionableControls.some((control) => control.control_id === requestForm.control_id)) {
      return;
    }
    setRequestForm((current) => ({ ...current, control_id: actionableControls[0]?.control_id ?? "" }));
  }, [actionableControls, requestForm.control_id, requestForm.request_kind]);

  useEffect(() => {
    if (selectedRequest && selectedId !== selectedRequest.approval_request_id) {
      setSelectedId(selectedRequest.approval_request_id);
      setDecisionExpiry(futureLocalInput(selectedRequest.requested_ttl_minutes));
    }
  }, [selectedId, selectedRequest]);

  async function refreshApprovalData() {
    const [requestResult, grantResult] = await Promise.allSettled([listApprovalRequests(), listApprovalGrants()]);
    if (requestResult.status === "fulfilled") {
      setRequests(requestResult.value);
    }
    if (grantResult.status === "fulfilled") {
      setGrants(grantResult.value);
    }
    setResourceState((current) => ({
      ...current,
      requests: requestResult.status === "fulfilled",
      grants: grantResult.status === "fulfilled",
    }));
    const failures = [requestResult, grantResult].filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    setLoadError(
      failures.length
        ? failures
            .map((result) => (result.reason instanceof Error ? result.reason.message : "Unable to refresh approval data."))
            .join(" ")
        : null,
    );
  }

  async function submitDecision(decision: "approve" | "deny" | "revoke") {
    if (!selectedRequest || !resourceState.requests || demoMode) {
      return;
    }

    setDecisionPending(true);
    setFeedback(null);
    setError(null);

    try {
      const updated = await decideApprovalRequest(selectedRequest.approval_request_id, {
        decision,
        decision_comment: decisionComment,
        expires_at: decision === "approve" ? localInputToIso(decisionExpiry) : null,
      });
      setRequests((current) =>
        current.map((request) =>
          request.approval_request_id === updated.approval_request_id ? updated : request,
        ),
      );
      setFeedback(
        `${approvalStatusDisplay(updated.status)}${updated.decision_by ? ` by ${updated.decision_by}` : ""}`,
      );
      await refreshApprovalData();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to submit decision.");
      await refreshApprovalData();
    } finally {
      setDecisionPending(false);
    }
  }

  async function handleCreateRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      !resourceState.requests ||
      !resourceState.endpoints ||
      demoMode ||
      !requestForm.endpoint_id ||
      (requestForm.request_kind === "hardening_change" && (!resourceState.controls || !requestForm.control_id))
    ) {
      return;
    }
    setRequestPending(true);
    setFeedback(null);
    setError(null);

    try {
      const payload =
        requestForm.request_kind === "hardening_change"
          ? {
              endpoint_ids: [requestForm.endpoint_id],
              request_kind: requestForm.request_kind,
              requested_actions: ["apply_control"] as ApprovalAction[],
              control_ids: [requestForm.control_id],
              troubleshooting_scopes: [],
              requested_ttl_minutes: requestForm.ttl,
              reason: requestForm.reason,
              risk: requestForm.risk,
            }
          : {
              endpoint_ids: [requestForm.endpoint_id],
              request_kind: requestForm.request_kind,
              requested_actions: [
                "request_elevated_troubleshooting",
                "inspect_control",
                "collect_security_context",
              ] as ApprovalAction[],
              control_ids: [],
              troubleshooting_scopes: requestForm.troubleshooting_scopes,
              requested_ttl_minutes: requestForm.ttl,
              reason: requestForm.reason,
              risk: requestForm.risk,
            };
      const created = await createApprovalRequest(payload);
      setRequests((current) => [created, ...current]);
      setSelectedId(created.approval_request_id);
      setResourceState((current) => ({ ...current, requests: true }));
      setFeedback(`Queued request ${created.approval_request_id}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create approval request.");
    } finally {
      setRequestPending(false);
    }
  }

  async function handleCreateGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!resourceState.grants || !resourceState.endpoints || demoMode || !grantForm.endpoint_id) {
      return;
    }
    setGrantPending(true);
    setFeedback(null);
    setError(null);

    try {
      const created = await createApprovalGrant({
        endpoint_ids: [grantForm.endpoint_id],
        allowed_actions: ["request_elevated_troubleshooting", "inspect_control", "collect_security_context"],
        control_ids: [],
        troubleshooting_scopes: grantForm.troubleshooting_scopes,
        reason: grantForm.reason,
        expires_at: localInputToIso(grantForm.expires_at) ?? futureIso(60),
      });
      setGrants((current) => [created, ...current]);
      setResourceState((current) => ({ ...current, grants: true }));
      setFeedback(`Opened manual grant ${created.approval_grant_id}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create approval grant.");
    } finally {
      setGrantPending(false);
    }
  }

  const anyResourceReady =
    resourceState.requests || resourceState.grants || resourceState.endpoints || resourceState.controls;
  const source = demoMode
    ? "demo"
    : resourceState.loading
      ? "loading"
      : loadError
        ? anyResourceReady
          ? "partial"
          : "error"
        : resourceState.requests && resourceState.grants && resourceState.endpoints && resourceState.controls
          ? "live"
          : anyResourceReady
            ? "partial"
            : "error";
  const canDecide = resourceState.requests && !demoMode;
  const canCreateRequest =
    resourceState.requests &&
    resourceState.endpoints &&
    !demoMode &&
    (requestForm.request_kind !== "hardening_change" || (resourceState.controls && Boolean(requestForm.control_id)));
  const canCreateGrant = resourceState.grants && resourceState.endpoints && !demoMode;

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Governance"
            title="Approval Review Console"
            description="Configuration changes and elevated troubleshooting require operator approval before execution."
          />
          {loadError ? <p className="inline-feedback inline-feedback--danger" role="alert">Approval resources load failed: {loadError}</p> : null}
          <div className="stat-grid">
            <StatCard label="Pending" value={pendingRequests.length} meta="Awaiting decision" tone="warning" />
            <StatCard label="Active grants" value={activeGrants.length} meta="Active grants in force" tone="success" />
            <StatCard label="Recorded history" value={auditHistory.length} meta="Closed approval outcomes" tone="info" />
            <StatCard label="Data source" value={source === "live" ? "Live" : source === "demo" ? "Demo" : source === "loading" ? "Loading" : source === "partial" ? "Partial" : "Error"} meta="Backend link state" tone={source === "live" ? "success" : source === "error" ? "danger" : "warning"} />
          </div>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Pending queue"
            title="Approval requests"
            description="Select a request to inspect scope, control IDs, and endpoint blast radius."
          />
          {pendingRequests.length ? (
            <div className="queue-list">
              {pendingRequests.map((request) => (
                <button
                  className="queue-list__item"
                  data-active={selectedRequest?.approval_request_id === request.approval_request_id ? "true" : "false"}
                  key={request.approval_request_id}
                  onClick={() => {
                    setSelectedId(request.approval_request_id);
                    setDecisionExpiry(futureLocalInput(request.requested_ttl_minutes));
                  }}
                  type="button"
                >
                  <div className="operator-list__title-row">
                    <strong>{request.reason}</strong>
                    <Badge tone={approvalRiskTone(request.risk)}>Risk {approvalRiskDisplay(request.risk)}</Badge>
                  </div>
                  <p>
                    {approvalRequestKindDisplay(request.request_kind)} • {endpointListDisplay(request.endpoint_ids, endpoints)} • {formatDateTime(request.created_at)}
                  </p>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState title="No pending requests" body="The approval queue is empty. Create a request below when a control change needs human review." />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Decision console"
            title={selectedRequest ? selectedRequest.reason : "No request selected"}
            description={selectedRequest ? "Single review surface for the currently selected approval request." : "Select a pending request to unlock the decision rail."}
          />
          {selectedRequest ? (
            <div className="stack-gap">
              <div className="detail-grid">
                <div className="detail-card">
                  <span>Kind</span>
                  <strong>{approvalRequestKindDisplay(selectedRequest.request_kind)}</strong>
                </div>
                <div className="detail-card">
                  <span>Status</span>
                  <strong>{approvalDecisionSummary(selectedRequest)}</strong>
                </div>
                <div className="detail-card">
                  <span>Endpoints</span>
                  <strong>{endpointListDisplay(selectedRequest.endpoint_ids, endpoints)}</strong>
                </div>
                <div className="detail-card">
                  <span>Scope</span>
                  <strong>
                    {selectedRequest.control_ids.length
                      ? selectedRequest.control_ids.join(", ")
                      : selectedRequest.troubleshooting_scopes.map(troubleshootingScopeDisplay).join(", ")}
                  </strong>
                </div>
              </div>

              <div className="tag-row">
                {selectedRequest.requested_actions.map((action) => (
                  <Badge key={action}>{approvalActionDisplay(action)}</Badge>
                ))}
                {selectedRequest.control_ids.map((controlId) => (
                  <Badge key={controlId} tone="warning">
                    {controlId}
                  </Badge>
                ))}
              </div>

              <form className="form-grid" onSubmit={(event) => event.preventDefault()}>
                <p className="inline-feedback field--span-2">
                  Action logged to administrator audit trail.
                </p>
                <label className="field field--span-2" htmlFor="decision-comment">
                  <span className="field__label">Decision comment</span>
                  <textarea
                    className="field__control field__control--textarea"
                    id="decision-comment"
                    onChange={(event) => setDecisionComment(event.target.value)}
                    required
                    value={decisionComment}
                  />
                </label>
                <label className="field" htmlFor="decision-expiry">
                  <span className="field__label">Approve until</span>
                  <input
                    className="field__control"
                    id="decision-expiry"
                    onChange={(event) => setDecisionExpiry(event.target.value)}
                    type="datetime-local"
                    value={decisionExpiry}
                  />
                </label>
                <div className="form-actions">
                  {selectedRequest.status === "pending" ? (
                    <>
                      <button className="action-button action-button--primary" disabled={decisionPending || !canDecide} onClick={() => submitDecision("approve")} type="button">
                        Approve request
                      </button>
                      <button className="action-button action-button--secondary" disabled={decisionPending || !canDecide} onClick={() => submitDecision("deny")} type="button">
                        Deny request
                      </button>
                    </>
                  ) : null}
                  {selectedRequest.status === "approved" ? (
                    <button className="action-button action-button--ghost" disabled={decisionPending || !canDecide} onClick={() => submitDecision("revoke")} type="button">
                      Revoke request
                    </button>
                  ) : null}
                  {feedback ? <span className="inline-feedback inline-feedback--success">{feedback}</span> : null}
                  {error ? <span className="inline-feedback inline-feedback--danger">{error}</span> : null}
                </div>
              </form>
            </div>
          ) : (
            <EmptyState title="No selection" body="Choose a pending request from the queue to open the decision console." />
          )}
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Request authoring"
            title="Open a new approval request"
            description="Convert a risky control change or troubleshooting need into a bounded review item."
          />
          <form className="form-grid" onSubmit={handleCreateRequest}>
            <label className="field" htmlFor="request-endpoint">
              <span className="field__label">Target endpoint</span>
              <select
                className="field__control"
                id="request-endpoint"
                onChange={(event) => setRequestForm((current) => ({ ...current, endpoint_id: event.target.value }))}
                required
                value={requestForm.endpoint_id}
              >
                {endpoints.length !== 1 ? <option value="">Select an endpoint</option> : null}
                {endpoints.map((endpoint) => (
                  <option key={endpoint.endpoint_id} value={endpoint.endpoint_id}>
                    {endpoint.hostname}
                  </option>
                ))}
              </select>
            </label>
            <label className="field" htmlFor="request-kind">
              <span className="field__label">Request kind</span>
              <select
                className="field__control"
                id="request-kind"
                onChange={(event) =>
                  setRequestForm((current) => ({
                    ...current,
                    request_kind: event.target.value as ApprovalRequest["request_kind"],
                  }))
                }
                value={requestForm.request_kind}
              >
                <option value="hardening_change">Hardening change</option>
                <option value="elevated_troubleshooting">Elevated troubleshooting</option>
              </select>
            </label>
            {requestForm.request_kind === "hardening_change" ? (
              <label className="field field--span-2" htmlFor="request-control-id">
                <span className="field__label">Control id</span>
                <select
                  className="field__control"
                  disabled={!actionableControls.length}
                  id="request-control-id"
                  onChange={(event) => setRequestForm((current) => ({ ...current, control_id: event.target.value }))}
                  required
                  value={requestForm.control_id}
                >
                  {actionableControls.length ? (
                    actionableControls.map((control) => (
                      <option key={control.control_id} value={control.control_id}>
                        {control.title}
                      </option>
                    ))
                  ) : (
                    <option value="">No mutable controls for this platform</option>
                  )}
                </select>
              </label>
            ) : (
              <label className="field field--span-2" htmlFor="request-troubleshooting">
                <span className="field__label">Troubleshooting scopes</span>
                <select
                  className="field__control"
                  id="request-troubleshooting"
                  multiple
                  onChange={(event) =>
                    setRequestForm((current) => ({
                      ...current,
                      troubleshooting_scopes: Array.from(event.target.selectedOptions).map(
                        (option) => option.value as TroubleshootingScope,
                      ),
                    }))
                  }
                  value={requestForm.troubleshooting_scopes}
                >
                  {TROUBLESHOOTING_SCOPE_OPTIONS.map((scope) => (
                    <option key={scope} value={scope}>
                      {troubleshootingScopeDisplay(scope)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label className="field field--span-2" htmlFor="request-reason">
              <span className="field__label">Reason</span>
              <textarea
                className="field__control field__control--textarea"
                id="request-reason"
                onChange={(event) => setRequestForm((current) => ({ ...current, reason: event.target.value }))}
                value={requestForm.reason}
              />
            </label>
            <p className="inline-feedback field--span-2">
              Action logged to administrator audit trail.
            </p>
            <label className="field" htmlFor="request-risk">
              <span className="field__label">Risk</span>
              <select
                className="field__control"
                id="request-risk"
                onChange={(event) => setRequestForm((current) => ({ ...current, risk: event.target.value as ApprovalRequest["risk"] }))}
                value={requestForm.risk}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            <label className="field" htmlFor="request-ttl">
              <span className="field__label">TTL minutes</span>
              <input
                className="field__control"
                id="request-ttl"
                min={15}
                max={240}
                onChange={(event) => setRequestForm((current) => ({ ...current, ttl: Number(event.target.value) }))}
                type="number"
                value={requestForm.ttl}
              />
            </label>
            <div className="form-actions">
              <button className="action-button action-button--primary" disabled={requestPending || !canCreateRequest || !requestForm.endpoint_id || (requestForm.request_kind === "hardening_change" && !requestForm.control_id)} type="submit">
                {requestPending ? "Queueing…" : "Create approval request"}
              </button>
            </div>
          </form>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Manual Grant"
            title="Issue a manual grant"
            description="Issue a temporary troubleshooting grant for endpoint diagnostic access."
          />
          <form className="form-grid" onSubmit={handleCreateGrant}>
            <label className="field" htmlFor="grant-endpoint">
              <span className="field__label">Endpoint</span>
              <select
                className="field__control"
                id="grant-endpoint"
                onChange={(event) => setGrantForm((current) => ({ ...current, endpoint_id: event.target.value }))}
                required
                value={grantForm.endpoint_id}
              >
                {endpoints.length !== 1 ? <option value="">Select an endpoint</option> : null}
                {endpoints.map((endpoint) => (
                  <option key={endpoint.endpoint_id} value={endpoint.endpoint_id}>
                    {endpoint.hostname}
                  </option>
                ))}
              </select>
            </label>
            <p className="inline-feedback field--span-2">
              Action logged to administrator audit trail.
            </p>
            <label className="field" htmlFor="grant-expiry">
              <span className="field__label">Grant expires at</span>
              <input
                className="field__control"
                id="grant-expiry"
                onChange={(event) => setGrantForm((current) => ({ ...current, expires_at: event.target.value }))}
                type="datetime-local"
                value={grantForm.expires_at}
              />
            </label>
            <label className="field field--span-2" htmlFor="grant-reason">
              <span className="field__label">Reason</span>
              <textarea
                className="field__control field__control--textarea"
                id="grant-reason"
                onChange={(event) => setGrantForm((current) => ({ ...current, reason: event.target.value }))}
                value={grantForm.reason}
              />
            </label>
            <label className="field field--span-2" htmlFor="grant-scopes">
              <span className="field__label">Troubleshooting scopes</span>
              <select
                className="field__control"
                id="grant-scopes"
                multiple
                onChange={(event) =>
                  setGrantForm((current) => ({
                    ...current,
                    troubleshooting_scopes: Array.from(event.target.selectedOptions).map(
                      (option) => option.value as TroubleshootingScope,
                    ),
                  }))
                }
                value={grantForm.troubleshooting_scopes}
              >
                {TROUBLESHOOTING_SCOPE_OPTIONS.map((scope) => (
                  <option key={scope} value={scope}>
                    {troubleshootingScopeDisplay(scope)}
                  </option>
                ))}
              </select>
            </label>
            <div className="form-actions">
              <button className="action-button action-button--secondary" disabled={grantPending || !canCreateGrant || !grantForm.endpoint_id} type="submit">
                {grantPending ? "Issuing…" : "Issue manual grant"}
              </button>
            </div>
          </form>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Approved windows"
            title="Active grants"
            description="Currently approved troubleshooting or rollout windows."
          />
          {activeGrants.length ? (
            <div className="operator-list">
              {activeGrants.map((grant) => (
                <div className="operator-list__item" key={grant.approval_grant_id}>
                  <div>
                    <div className="operator-list__title-row">
                      <strong>{grant.reason}</strong>
                      <Badge tone={approvalStatusTone(grant.status)}>{approvalStatusDisplay(grant.status)}</Badge>
                    </div>
                    <p>
                      {endpointListDisplay(grant.endpoint_ids, endpoints)} • approved by {grant.approved_by} • expires {formatDateTime(grant.expires_at)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No active grants" body="Manual and request-driven grants will appear here as soon as the backend issues them." />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Audit history"
            title="Decision trail"
            description="Closed approvals preserve who acted, when, and why."
          />
          <div className="timeline-list">
            {auditHistory.map((request) => {
              const latestEvent = request.audit_events[request.audit_events.length - 1];
              return (
                <div className="timeline-list__item" key={request.approval_request_id}>
                  <span className={`timeline-list__dot timeline-list__dot--${approvalStatusTone(request.status)}`} />
                  <div>
                    <strong>{request.reason}</strong>
                    <p>
                      {latestEvent.event_type} by {latestEvent.actor} • {formatDateTime(latestEvent.created_at)}
                    </p>
                    <p>{latestEvent.comment}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      </section>
    </>
  );
}
