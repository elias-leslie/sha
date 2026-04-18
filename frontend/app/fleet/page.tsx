import NavShell from "../../components/nav-shell";
import {
  endpointStateDisplay,
  endpointStateTone,
  getFleetEndpoints,
  getFleetSummary,
  platformDisplayName,
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

export default function FleetPage() {
  const summary = getFleetSummary();
  const endpoints = getFleetEndpoints();

  return (
    <NavShell
      title="Fleet overview"
      description="Track endpoint posture, hardening coverage, and check-in timing across the local SHA fixture set."
    >
      <section className="panel stack">
        <div>
          <p className="eyebrow">Fleet health</p>
          <h2>Signal at a glance</h2>
        </div>
        <div className="summary-grid">
          <MetricCard label="Endpoints" value={summary.totalEndpoints} meta="Local fleet fixture count" />
          <MetricCard label="Healthy" value={summary.healthyEndpoints} meta="Endpoints within target posture" />
          <MetricCard label="Degraded" value={summary.degradedEndpoints} meta="Needs tuning but still reachable" />
          <MetricCard label="Attention" value={summary.needsAttentionEndpoints} meta="Requires review before rollout" />
          <MetricCard label="Windows" value={summary.windowsEndpoints} meta="Ready for installer profile wiring" />
          <MetricCard label="Linux" value={summary.linuxEndpoints} meta="Ready for installer profile wiring" />
        </div>
      </section>

      <section className="panel stack">
        <div>
          <p className="eyebrow">Endpoints</p>
          <h2>Detailed posture list</h2>
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
                  <span className="pill pill--info">{platformDisplayName(endpoint.platform)}</span>
                </div>
                <p className="muted">Stable identifier: <code>{endpoint.id}</code></p>
                <p className="muted">Last check-in {endpoint.lastCheckIn}</p>
              </div>
              <div className="muted">Hardening score {endpoint.hardeningScore}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="subgrid">
        <article className="panel stack">
          <div>
            <p className="eyebrow">Readiness</p>
            <h2>What the backend will eventually feed</h2>
          </div>
          <p className="muted">
            This shell already has room for scorecards, endpoint drill-down, and installer orchestration without
            depending on live services during the initial build slice.
          </p>
        </article>

        <article className="panel callout">
          <p className="callout__title">Fleet layout placeholder</p>
          <p>
            When the control plane arrives, this page can surface alerts, rollout groups, and endpoint drill-downs
            without changing the navigation shell.
          </p>
        </article>
      </section>
    </NavShell>
  );
}
