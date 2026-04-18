import { use } from "react";

import NavShell from "../../../components/nav-shell";
import {
  endpointStateDisplay,
  endpointStateTone,
  getEndpointById,
  getFleetEndpoints,
  platformDisplayName,
} from "../../../lib/api";

type EndpointParams = {
  endpointId: string;
};

function resolveEndpointParams(params: Promise<EndpointParams> | EndpointParams) {
  const candidate = params as unknown as { then?: unknown };
  if (typeof candidate.then === "function") {
    return use(params as Promise<EndpointParams>);
  }

  return params as unknown as EndpointParams;
}

export function generateStaticParams() {
  return getFleetEndpoints().map((endpoint) => ({ endpointId: endpoint.id }));
}

export default function EndpointDetailPage({
  params,
}: {
  params: Promise<EndpointParams> | EndpointParams;
}) {
  const { endpointId } = resolveEndpointParams(params);
  const endpoint = getEndpointById(endpointId) ?? {
    id: endpointId,
    hostname: endpointId,
    platform: "linux" as const,
    state: "needs-attention" as const,
    hardeningScore: 0,
    lastCheckIn: "No local fixture yet",
    controls: ["Pending fixture hookup"],
    note: "This lane keeps the detail shell local and ready for backend wiring.",
  };

  return (
    <NavShell
      title={`Endpoint ${endpointId}`}
      description={`Stable identifier: ${endpointId}. This detail view is backed by local fixtures so the frontend builds without the backend.`}
    >
      <section className="panel stack">
        <div>
          <p className="eyebrow">Endpoint summary</p>
          <h2>Route-param backed identity</h2>
        </div>
        <div className="definition-grid">
          <dl className="definition">
            <dt>Stable ID</dt>
            <dd><code>{endpoint.id}</code></dd>
          </dl>
          <dl className="definition">
            <dt>Hostname</dt>
            <dd>{endpoint.hostname}</dd>
          </dl>
          <dl className="definition">
            <dt>Platform</dt>
            <dd>{platformDisplayName(endpoint.platform)}</dd>
          </dl>
          <dl className="definition">
            <dt>State</dt>
            <dd className={`pill pill--${endpointStateTone(endpoint.state)}`}>{endpointStateDisplay(endpoint.state)}</dd>
          </dl>
          <dl className="definition">
            <dt>Last check-in</dt>
            <dd>{endpoint.lastCheckIn}</dd>
          </dl>
          <dl className="definition">
            <dt>Hardening score</dt>
            <dd>{endpoint.hardeningScore}</dd>
          </dl>
        </div>
      </section>

      <section className="subgrid">
        <article className="panel stack">
          <div>
            <p className="eyebrow">Hardening posture</p>
            <h2>Applied controls</h2>
          </div>
          <div className="list">
            {endpoint.controls.map((control) => (
              <div className="list-item" key={control}>
                <div className="list-item__body">
                  <div className="list-item__title">{control}</div>
                  <p className="muted">Placeholder for policy mapping, status, and rollout history.</p>
                </div>
                <span className="pill pill--info">Tracked</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel callout">
          <p className="callout__title">Detail shell placeholder</p>
          <p>{endpoint.note}</p>
          <p>
            Future versions can add approval links, remediation actions, and package lineage without changing the
            route contract.
          </p>
        </article>
      </section>
    </NavShell>
  );
}
