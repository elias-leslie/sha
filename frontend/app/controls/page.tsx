import NavShell from "../../components/nav-shell";
import { controlStatusDisplay, controlStatusTone, getControlPolicies } from "../../lib/api";

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

export default function ControlsPage() {
  const policies = getControlPolicies();
  const activeCount = policies.filter((policy) => policy.status === "active").length;
  const reviewCount = policies.filter((policy) => policy.status === "review").length;
  const plannedCount = policies.filter((policy) => policy.status === "planned").length;

  return (
    <NavShell
      title="Control policies"
      description="Review the local SHA policy shell that will later map to endpoint enforcement and package rollout gates."
    >
      <section className="panel stack">
        <div>
          <p className="eyebrow">Policy deck</p>
          <h2>Current control-plane lane</h2>
        </div>
        <div className="summary-grid">
          <MetricCard label="Active" value={activeCount} meta="Policies already scoped for execution" />
          <MetricCard label="Review" value={reviewCount} meta="Policies waiting for human review" />
          <MetricCard label="Planned" value={plannedCount} meta="Policies reserved for later slices" />
        </div>
      </section>

      <section className="panel stack">
        <div>
          <p className="eyebrow">Controls</p>
          <h2>Policy shell inventory</h2>
        </div>
        <div className="selection-grid">
          {policies.map((policy) => (
            <article className="profile-card" key={policy.id}>
              <div className="profile-card__meta">
                <span className={`pill pill--${controlStatusTone(policy.status)}`}>
                  {controlStatusDisplay(policy.status)}
                </span>
                <span className="pill pill--info">{policy.scope}</span>
              </div>
              <h3>{policy.name}</h3>
              <p>{policy.description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="subgrid">
        <article className="panel callout">
          <p className="callout__title">Future enforcement lane</p>
          <p>
            This page is intentionally placeholder-only for now, but it already has space for control authoring,
            rollout staging, and policy execution history.
          </p>
        </article>

        <article className="panel stack">
          <div>
            <p className="eyebrow">Notes</p>
            <h2>Ready for backend wiring</h2>
          </div>
          <p className="muted">
            The control shell can absorb live schema data later without changing the route contract or the shared
            navigation.
          </p>
        </article>
      </section>
    </NavShell>
  );
}
