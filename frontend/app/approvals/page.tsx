import NavShell from "../../components/nav-shell";
import { approvalStatusDisplay, approvalStatusTone, getApprovalRequests } from "../../lib/api";

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

function riskTone(risk: "low" | "medium" | "high") {
  if (risk === "high") {
    return "danger" as const;
  }

  if (risk === "medium") {
    return "warning" as const;
  }

  return "info" as const;
}

export default function ApprovalsPage() {
  const requests = getApprovalRequests();
  const pendingCount = requests.filter((request) => request.status === "pending").length;
  const highRiskCount = requests.filter((request) => request.risk === "high").length;

  return (
    <NavShell
      title="Approval queue"
      description="Human review remains in the loop for risky changes, package generation, and future rollout gates."
    >
      <section className="panel stack">
        <div>
          <p className="eyebrow">Governance</p>
          <h2>Review state</h2>
        </div>
        <div className="summary-grid">
          <MetricCard label="Pending" value={pendingCount} meta="Awaiting a decision from the operator" />
          <MetricCard label="High risk" value={highRiskCount} meta="Requests that warrant extra review" />
        </div>
      </section>

      <section className="panel stack">
        <div>
          <p className="eyebrow">Requests</p>
          <h2>Queued approvals</h2>
        </div>
        <div className="list">
          {requests.map((request) => (
            <div className="list-item" key={request.id}>
              <div className="list-item__body">
                <div className="list-item__title">
                  <span>{request.target}</span>
                  <span className={`pill pill--${approvalStatusTone(request.status)}`}>
                    {approvalStatusDisplay(request.status)}
                  </span>
                  <span className={`pill pill--${riskTone(request.risk)}`}>Risk {request.risk}</span>
                </div>
                <p className="muted">Requested by {request.requestedBy}</p>
              </div>
              <div className="muted">{request.reason}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="subgrid">
        <article className="panel callout">
          <p className="callout__title">Approval flow placeholder</p>
          <p>
            This slice leaves room for decisions, comments, and audit history without bringing any live backend
            dependency into the build.
          </p>
        </article>

        <article className="panel stack">
          <div>
            <p className="eyebrow">Next step</p>
            <h2>Ready for operator controls</h2>
          </div>
          <p className="muted">
            Future work can wire the queue to notifications, change requests, and package signing ceremonies.
          </p>
        </article>
      </section>
    </NavShell>
  );
}
