import { use } from "react";

import EndpointDetailConsole from "../../../components/endpoint-detail-console";
import NavShell from "../../../components/nav-shell";
import { getFixtureEndpoint, getFixtureEndpoints } from "../../../lib/api";

type EndpointParams = {
  endpointId: string;
};

function resolveEndpointParams(params: Promise<EndpointParams> | EndpointParams) {
  const candidate = params as unknown as { then?: unknown };
  if (typeof candidate.then === "function") {
    return use(params as Promise<EndpointParams>);
  }

  return params as EndpointParams;
}

export function generateStaticParams() {
  return getFixtureEndpoints().map((endpoint) => ({ endpointId: endpoint.endpoint_id }));
}

export default function EndpointDetailPage({
  params,
}: {
  params: Promise<EndpointParams> | EndpointParams;
}) {
  const { endpointId } = resolveEndpointParams(params);
  const endpoint = getFixtureEndpoint(endpointId);
  const title = endpoint ? `Endpoint ${endpoint.hostname}` : `Endpoint ${endpointId}`;

  return (
    <NavShell
      currentPath="/fleet"
      title={title}
      description="Endpoint drill-down with live heartbeat and posture write surfaces for operator validation and controlled testing."
    >
      <EndpointDetailConsole endpointId={endpointId} initialEndpoint={endpoint} />
    </NavShell>
  );
}
