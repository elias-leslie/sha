import { use } from "react";

import EndpointDetailConsole from "../../../components/endpoint-detail-console";
import EndpointShellTitle from "../../../components/endpoint-shell-title";
import NavShell from "../../../components/nav-shell";
import {
  getFixtureControlRegistry,
  getFixtureEndpoint,
  getFixtureEndpoints,
  isDemoMode,
} from "../../../lib/api";

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
  const demoMode = isDemoMode();
  const endpoint = demoMode ? getFixtureEndpoint(endpointId) : undefined;

  return (
    <NavShell
      currentPath="/fleet"
      scopeNotice="Endpoint-specific view. Client and location viewpoint filters do not apply; endpoint identity and server authorization govern this page."
      title={<EndpointShellTitle demoMode={demoMode} endpointId={endpointId} initialHostname={endpoint?.hostname} />}
      description="Endpoint drill-down with live heartbeat and posture write surfaces for operator validation and controlled testing."
    >
      <EndpointDetailConsole
        demoMode={demoMode}
        endpointId={endpointId}
        initialControls={demoMode ? getFixtureControlRegistry() : undefined}
        initialEndpoint={endpoint}
      />
    </NavShell>
  );
}
