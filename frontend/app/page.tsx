import NavShell from "../components/nav-shell";
import {
  approvalStatusDisplay,
  approvalStatusTone,
  describeApprovalRequest,
  endpointStateDisplay,
  endpointStateTone,
  getApprovalRequests,
  getFleetEndpoints,
  getFleetSummary,
  getInstallerProfiles,
  platformDisplayName,
} from "../lib/api";

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

function RouteCard({ href, title, description }: { href: string; title: string; description: string }) {
  return (
    <a className="link-card" href={href}>
      <div className="link-card__title">{title}</div>
      <p className="link-card__text">{description}</p>
    </a>
  );
}

export default function HomePage() {
  const summary = getFleetSummary();
  const endpoints = getFleetEndpoints();
  const approvals = getApprovalRequests().filter((request) => request.status === "pending");
  const installerProfiles = getInstallerProfiles();

  return (
    <NavShell
      title="SHA operator workspace"
      description="This lane establishes the SHA dashboard shell with local fixtures, safe autonomy guardrails, and room for backend wiring."
    >
      <section className="subgrid">
        <article className="panel stack">
          <div>
            <p className="eyebrow">Fleet snapshot</p>
            <h2>Fixture-backed visibility</h2>
          </div>
          <div className="summary-grid">
            <MetricCard label="Endpoints" value={summary.totalEndpoints} meta="Available in the lane" />
            <MetricCard label="Healthy" value={summary.healthyEndpoints} meta="Endpoints within target posture" />
            <MetricCard label="Needs attention" value={summary.needsAttentionEndpoints} meta="Awaiting remediation or approval" />
            <MetricCard label="Average score" value={summary.averageScore} meta="Local hardening average" />
          </div>
        </article>

        <article className="panel stack">
          <div>
            <p className="eyebrow">Navigation</p>
            <h2>Shell entry points</h2>
          </div>
          <div className="stack">
            <RouteCard href="/fleet" title="Fleet" description="Endpoint posture, scores, and check-in timing." />
            <RouteCard href="/controls" title="Controls" description="Policy lanes for future enforcement and rollout." />
            <RouteCard href="/approvals" title="Approvals" description="Human review queue for risk-bearing actions." />
            <RouteCard href="/installers" title="Installers" description="Windows and Linux profile selection with package generation placeholders." />
          </div>
        </article>
      </section>

      <section className="subgrid">
        <article className="panel stack">
          <div>
            <p className="eyebrow">Fleet focus</p>
            <h2>Top local endpoints</h2>
          </div>
          <div className="list">
            {endpoints.map((endpoint) => (
              <div className="list-item" key={endpoint.id}>
                <div className="list-item__body">
                  <div className="list-item__title">
                    <span>{endpoint.hostname}</span>
                    <span className={`pill pill--${endpointStateTone(endpoint.state)}`}>
                      {endpointStateDisplay(endpoint.state)}
                    </span>
                  </div>
                  <p className="muted">
                    {platformDisplayName(endpoint.platform)} · {endpoint.note}
                  </p>
                </div>
                <div className="muted">Score {endpoint.hardeningScore}</div>
              </div>
            ))}
          </div>
        </article>

        <article className="panel stack">
          <div>
            <p className="eyebrow">Approvals</p>
            <h2>Pending review queue</h2>
          </div>
          <div className="list">
            {approvals.map((request) => (
              <div className="list-item" key={request.approval_request_id}>
                <div className="list-item__body">
                  <div className="list-item__title">
                    <span>{describeApprovalRequest(request)}</span>
                    <span className={`pill pill--${approvalStatusTone(request.status)}`}>
                      {approvalStatusDisplay(request.status)}
                    </span>
                  </div>
                  <p className="muted">
                    Requested by {request.requested_by} · Risk {request.risk}
                  </p>
                </div>
                <div className="muted">{request.reason}</div>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="subgrid">
        <article className="panel stack">
          <div>
            <p className="eyebrow">Installer lanes</p>
            <h2>Windows and Linux profiles</h2>
          </div>
          <div className="selection-grid">
            {installerProfiles.map((profile) => (
              <article className="profile-card" key={profile.id}>
                <div className="profile-card__meta">
                  <span className="pill pill--info">{platformDisplayName(profile.platform)}</span>
                  <span className="pill">{profile.packageName}</span>
                </div>
                <h3>{profile.displayName}</h3>
                <p>{profile.description}</p>
              </article>
            ))}
          </div>
        </article>

        <article className="panel callout">
          <p className="callout__title">Safety by design</p>
          <p>
            The dashboard shell keeps every view local for now, so the first frontend slice can ship with fixture-backed
            routing, stable data, and no backend dependency during build or test runs.
          </p>
          <a className="button-placeholder" href="/installers">
            Package generation placeholder
          </a>
        </article>
      </section>
    </NavShell>
  );
}
