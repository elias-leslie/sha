"use client";

import { useEffect, useState } from "react";

import { getEndpoint, getFixtureEndpoint, isDemoMode } from "../lib/api";

type EndpointShellTitleProps = {
  endpointId: string;
  initialHostname?: string;
  demoMode?: boolean;
};

export default function EndpointShellTitle({ endpointId, initialHostname, demoMode = isDemoMode() }: EndpointShellTitleProps) {
  const demoEndpoint = demoMode ? getFixtureEndpoint(endpointId) : undefined;
  const [hostname, setHostname] = useState(initialHostname ?? demoEndpoint?.hostname ?? null);
  const [failed, setFailed] = useState(demoMode && !demoEndpoint);

  useEffect(() => {
    let cancelled = false;
    const fixture = demoMode ? getFixtureEndpoint(endpointId) : undefined;
    setHostname(initialHostname ?? fixture?.hostname ?? null);
    setFailed(demoMode && !fixture);

    if (demoMode) {
      return;
    }

    getEndpoint(endpointId)
      .then((endpoint) => {
        if (!cancelled) {
          setHostname(endpoint.hostname);
          setFailed(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setHostname(null);
          setFailed(true);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [demoMode, endpointId, initialHostname]);

  return <>{failed ? "Endpoint unavailable" : hostname ? `Endpoint ${hostname}` : `Loading endpoint ${endpointId}`}</>;
}
