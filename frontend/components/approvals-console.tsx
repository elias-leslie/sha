"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";

import {
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
  formatLocalInputValue,
  futureIso,
  getFixtureApprovalGrants,
  getFixtureApprovalRequests,
  getFixtureEndpoints,
  listApprovalGrants,
  listApprovalRequests,
  listEndpoints,
  localInputToIso,
  titleCaseKey,
  troubleshootingScopeDisplay,
  type ApprovalAction,
  type ApprovalGrant,
  type ApprovalRequest,
  type EndpointInventoryItem,
  type TroubleshootingScope,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";

type ApprovalsConsoleProps = {
  initialRequests?: ApprovalRequest[];
  initialGrants?: ApprovalGrant[];
  initialEndpoints?: EndpointInventoryItem[];
};

const TROUBLESHOOTING_SCOPE_OPTIONS: TroubleshootingScope[] = [
  "security_logs",
  "service_status",
  "firewall_state",
  "identity_state",
  "process_inventory",
  "network_bindings",
];

export default function ApprovalsConsole({
  initialRequests = getFixtureApprovalRequests(),
  initialGrants = getFixtureApprovalGrants(),
  initialEndpoints = getFixtureEndpoints(),
}: ApprovalsConsoleProps) {
  const [requests, setRequests] = useState(initialRequests);
  const [grants, setGrants] = useState(initialGrants);
  const [endpoints, setEndpoints] = useState(initialEndpoints);
  const [source, setSource] = useState<"fixture" | "live">("fixture");
  const [selectedId, setSelectedId] = useState<string | null>(initialRequests.find((item) => item.status === "pending")?.approval_request_id ?? null);
  const [decisionOperator, setDecisionOperator] = useState("secops-alpha");
  const [decisionComment, setDecisionComment] = useState("Approved for the maintenance window.");
  const [decisionExpiry, setDecisionExpiry] = useState(formatLocalInputValue(futureIso(45)));
  const [decisionPending, setDecisionPending] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [requestPending, setRequestPending] = useState(false);
  const [grantPending, setGrantPending] = useState(false);
  const [requestForm, setRequestForm] = useState({
    endpoint_id: initialEndpoints[0]?.endpoint_id ?? "",
    request_kind: "hardening_change" as ApprovalRequest["request_kind"],
    control_id: "control.windows.rdp-network-level-authentication",
    reason: "Approve guarded hardening rollout",
    requested_by: "ops-console",
    risk: "high" as ApprovalRequest["risk"],
    ttl: 60,
    troubleshooting_scopes: ["security_logs"] as TroubleshootingScope[],
  });
  const [grantForm, setGrantForm] = useState({
    endpoint_id: initialEndpoints[0]?.endpoint_id ?? "",
    approved_by: "secops-alpha",
    requested_by: "ops-console",
    reason: "Temporary bounded troubleshooting window",
    expires_at: formatLocalInputValue(futureIso(90)),
    troubleshooting_scopes: ["security_logs"] as TroubleshootingScope[],
  });

  useEffect(() => {
    let cancelled = false;

    Promise.all([listApprovalRequests(), listApprovalGrants(), listEndpoints()])
      .then(([liveRequests, liveGrants, liveEndpoints]) => {
        if (cancelled) {
          return;
        }
        setRequests(liveRequests);
        setGrants(liveGrants);
        setEndpoints(liveEndpoints);
        setSource("live");
      })
      .catch(() => {
        if (!cancelled) {
          setSource("fixture");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const pendingRequests = useMemo(() => requests.filter((request) => request.status === "pending"), [requests]);
  const activeGrants = useMemo(() => grants.filter((grant) => grant.status === "approved"), [grants]);
  const auditHistory = useMemo(() => requests.filter((request) => request.status !== "pending"), [requests]);
  const selectedRequest = useMemo(() => {
    return requests.find((request) => request.approval_request_id === selectedId) ?? pendingRequests[0] ?? requests[0] ?? null;
  }, [pendingRequests, requests, selectedId]);

  useEffect(() => {
    if (selectedRequest && selectedId !== selectedRequest.approval_request_id) {
      setSelectedId(selectedRequest.approval_request_id);
      setDecisionExpiry(formatLocalInputValue(futureIso(selectedRequest.requested_ttl_minutes)));
    }
  }, [selectedId, selectedRequest]);

  async function refreshGrants() {
    try {
      const liveGrants = await listApprovalGrants();
      setGrants(liveGrants);
      setSource("live");
    } catch {
      // preserve current grant snapshot if refresh fails
    }
  }

  async function submitDecision(decision: "approve" | "deny" | "revoke") {
    if (!selectedRequest) {
      return;
    }

    setDecisionPending(true);
    setFeedback(null);
    setError(null);

    try {
      const updated = await decideApprovalRequest(selectedRequest.approval_request_id, {
        decision,
        decided_by: decisionOperator,
        decision_comment: decisionComment,
        expires_at: decision === "approve" ? localInputToIso(decisionExpiry) : null,
      });
      setRequests((current) =>
        current.map((request) =>
          request.approval_request_id === updated.approval_request_id ? updated : request,
        ),
      );
      setSource("live");
      setFeedback(`${approvalStatusDisplay(updated.status)} by ${updated.decision_by ?? decisionOperator}`);
      await refreshGrants();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to submit decision.");
    } finally {
      setDecisionPending(false);
    }
  }

  async function handleCreateRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
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
              requested_by: requestForm.requested_by,
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
              requested_by: requestForm.requested_by,
              reason: requestForm.reason,
              risk: requestForm.risk,
            };
      const created = await createApprovalRequest(payload);
      setRequests((current) => [created, ...current]);
      setSelectedId(created.approval_request_id);
      setSource("live");
      setFeedback(`Queued request ${created.approval_request_id}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create approval request.");
    } finally {
      setRequestPending(false);
    }
  }

  async function handleCreateGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setGrantPending(true);
    setFeedback(null);
    setError(null);

    try {
      const created = await createApprovalGrant({
        endpoint_ids: [grantForm.endpoint_id],
        allowed_actions: ["request_elevated_troubleshooting", "inspect_control", "collect_security_context"],
        control_ids: [],
        troubleshooting_scopes: grantForm.troubleshooting_scopes,
        requested_by: grantForm.requested_by,
        approved_by: grantForm.approved_by,
        reason: grantForm.reason,
        expires_at: localInputToIso(grantForm.expires_at) ?? futureIso(60),
      });
      setGrants((current) => [created, ...current]);
      setSource("live");
      setFeedback(`Opened manual grant ${created.approval_grant_id}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create approval grant.");
    } finally {
      setGrantPending(false);
    }
  }

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Governance"
            title="Human decision surface"
            description="Risk-bearing changes stay blocked until an operator approves, denies, or revokes the request."
          />
          <div className="stat-grid">
            <StatCard label="Pending" value={pendingRequests.length} meta="Awaiting decision" tone="warning" />
            <StatCard label="Active grants" value={activeGrants.length} meta="Approved windows in force" tone="success" />
            <StatCard label="Recorded history" value={auditHistory.length} meta="Closed approval outcomes" tone="info" />
            <StatCard label="Data source" value={source === "live" ? "Live" : "Fixture"} meta="Backend link state" tone={source === "live" ? "success" : "warning"} />
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
                    setDecisionExpiry(formatLocalInputValue(futureIso(request.requested_ttl_minutes)));
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
                <label className="field" htmlFor="decision-operator">
                  <span className="field__label">Decision operator</span>
                  <input
                    className="field__control"
                    id="decision-operator"
                    onChange={(event) => setDecisionOperator(event.target.value)}
                    required
                    value={decisionOperator}
                  />
                </label>
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
                  <button className="action-button action-button--primary" disabled={decisionPending} onClick={() => submitDecision("approve")} type="button">
                    Approve request
                  </button>
                  <button className="action-button action-button--secondary" disabled={decisionPending} onClick={() => submitDecision("deny")} type="button">
                    Deny request
                  </button>
                  {selectedRequest.status === "approved" ? (
                    <button className="action-button action-button--ghost" disabled={decisionPending} onClick={() => submitDecision("revoke")} type="button">
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
                value={requestForm.endpoint_id}
              >
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
                <input
                  className="field__control"
                  id="request-control-id"
                  onChange={(event) => setRequestForm((current) => ({ ...current, control_id: event.target.value }))}
                  value={requestForm.control_id}
                />
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
            <label className="field" htmlFor="request-by">
              <span className="field__label">Requested by</span>
              <input
                className="field__control"
                id="request-by"
                onChange={(event) => setRequestForm((current) => ({ ...current, requested_by: event.target.value }))}
                value={requestForm.requested_by}
              />
            </label>
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
              <button className="action-button action-button--primary" disabled={requestPending} type="submit">
                {requestPending ? "Queueing…" : "Create approval request"}
              </button>
            </div>
          </form>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Emergency lane"
            title="Issue a manual grant"
            description="When operations needs bounded read access fast, mint a time-boxed troubleshooting grant."
          />
          <form className="form-grid" onSubmit={handleCreateGrant}>
            <label className="field" htmlFor="grant-endpoint">
              <span className="field__label">Endpoint</span>
              <select
                className="field__control"
                id="grant-endpoint"
                onChange={(event) => setGrantForm((current) => ({ ...current, endpoint_id: event.target.value }))}
                value={grantForm.endpoint_id}
              >
                {endpoints.map((endpoint) => (
                  <option key={endpoint.endpoint_id} value={endpoint.endpoint_id}>
                    {endpoint.hostname}
                  </option>
                ))}
              </select>
            </label>
            <label className="field" htmlFor="grant-approved-by">
              <span className="field__label">Approved by</span>
              <input
                className="field__control"
                id="grant-approved-by"
                onChange={(event) => setGrantForm((current) => ({ ...current, approved_by: event.target.value }))}
                value={grantForm.approved_by}
              />
            </label>
            <label className="field" htmlFor="grant-requested-by">
              <span className="field__label">Requested by</span>
              <input
                className="field__control"
                id="grant-requested-by"
                onChange={(event) => setGrantForm((current) => ({ ...current, requested_by: event.target.value }))}
                value={grantForm.requested_by}
              />
            </label>
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
              <button className="action-button action-button--secondary" disabled={grantPending} type="submit">
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
