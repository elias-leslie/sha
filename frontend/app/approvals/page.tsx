import NavShell from "../../components/nav-shell";
import {
  approvalActionDisplay,
  approvalRequestKindDisplay,
  approvalRiskDisplay,
  approvalRiskTone,
  approvalStatusDisplay,
  approvalStatusTone,
  describeApprovalGrant,
  describeApprovalRequest,
  endpointListDisplay,
  getApprovalGrants,
  getApprovalRequests,
  troubleshootingScopeDisplay,
} from "../../lib/api";

function MetricCard({
  label,
  value,
  meta,
}: {
  label: string;
  value: number | string;
  meta: string;
}) {
  return (
    <article className="metric">
      <div className="metric__label">{label}</div>
      <div className="metric__value">{value}</div>
      <div className="metric__meta">{meta}</div>
    </article>
  );
}

function DetailList({ title, values }: { title: string; values: readonly string[] }) {
  if (!values.length) {
    return null;
  }

  return (
    <div className="stack">
      <div className="eyebrow">{title}</div>
      <div className="list-item__title">
        {values.map((value) => (
          <span className="pill" key={`${title}-${value}`}>
            {value}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function ApprovalsPage() {
  const requests = getApprovalRequests();
  const grants = getApprovalGrants();
  const pendingRequests = requests.filter((request) => request.status === "pending");
  const auditHistory = requests.filter((request) => request.status !== "pending");
  const activeGrants = grants.filter((grant) => grant.status === "approved");
  const criticalRequests = pendingRequests.filter((request) => request.risk === "critical").length;

  return (
    <NavShell
      title="Approval queue"
      description="Bounded operator review for disruptive hardening changes and temporary elevated troubleshooting scopes."
    >
      <section className="panel stack">
        <div>
          <p className="eyebrow">Governance</p>
          <h2>Review state</h2>
        </div>
        <div className="summary-grid">
          <MetricCard label="Pending" value={pendingRequests.length} meta="Requests awaiting a human decision" />
          <MetricCard label="Active grants" value={activeGrants.length} meta="Time-boxed approvals currently in force" />
          <MetricCard label="Critical" value={criticalRequests} meta="Requests that need careful operator review" />
        </div>
      </section>

      <section className="panel stack">
        <div>
          <p className="eyebrow">Requests</p>
          <h2>Pending requests</h2>
        </div>
        <div className="list">
          {pendingRequests.map((request) => (
            <div className="list-item" key={request.approval_request_id}>
              <div className="list-item__body stack">
                <div className="list-item__title">
                  <span>{describeApprovalRequest(request)}</span>
                  <span className={`pill pill--${approvalStatusTone(request.status)}`}>
                    {approvalStatusDisplay(request.status)}
                  </span>
                  <span className={`pill pill--${approvalRiskTone(request.risk)}`}>
                    Risk {approvalRiskDisplay(request.risk)}
                  </span>
                </div>
                <p className="muted">
                  {approvalRequestKindDisplay(request.request_kind)} · Requested by {request.requested_by} · Endpoints {endpointListDisplay(request.endpoint_ids)}
                </p>
                <DetailList title="Actions" values={request.requested_actions.map(approvalActionDisplay)} />
                <DetailList title="Controls" values={request.control_ids} />
                <DetailList
                  title="Troubleshooting scopes"
                  values={request.troubleshooting_scopes.map(troubleshootingScopeDisplay)}
                />
                <p className="muted">Requested TTL {request.requested_ttl_minutes} minutes.</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="subgrid">
        <article className="panel stack">
          <div>
            <p className="eyebrow">Grants</p>
            <h2>Active grants</h2>
          </div>
          <div className="list">
            {activeGrants.map((grant) => (
              <div className="list-item" key={grant.approval_grant_id}>
                <div className="list-item__body stack">
                  <div className="list-item__title">
                    <span>{describeApprovalGrant(grant)}</span>
                    <span className={`pill pill--${approvalStatusTone(grant.status)}`}>
                      {approvalStatusDisplay(grant.status)}
                    </span>
                  </div>
                  <p className="muted">
                    Approved by {grant.approved_by} · Expires {grant.expires_at} · Endpoints {endpointListDisplay(grant.endpoint_ids)}
                  </p>
                  <DetailList title="Actions" values={grant.allowed_actions.map(approvalActionDisplay)} />
                  <DetailList title="Controls" values={grant.control_ids} />
                  <DetailList
                    title="Troubleshooting scopes"
                    values={grant.troubleshooting_scopes.map(troubleshootingScopeDisplay)}
                  />
                </div>
              </div>
            ))}
          </div>
        </article>

        <article className="panel callout">
          <p className="callout__title">SHAna boundary</p>
          <p>
            No arbitrary shell access. SHAna can request hardening changes or bounded troubleshooting scopes only,
            and every broader read path still needs explicit human approval plus expiry.
          </p>
        </article>
      </section>

      <section className="panel stack">
        <div>
          <p className="eyebrow">History</p>
          <h2>Audit trail</h2>
        </div>
        <div className="list">
          {auditHistory.map((request) => {
            const latestEvent = request.audit_events[request.audit_events.length - 1];
            return (
              <div className="list-item" key={request.approval_request_id}>
                <div className="list-item__body stack">
                  <div className="list-item__title">
                    <span>{describeApprovalRequest(request)}</span>
                    <span className={`pill pill--${approvalStatusTone(request.status)}`}>
                      {approvalStatusDisplay(request.status)}
                    </span>
                  </div>
                  <p className="muted">
                    Latest event {latestEvent.event_type} by {latestEvent.actor} · {latestEvent.created_at}
                  </p>
                  <p className="muted">{latestEvent.comment}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </NavShell>
  );
}
