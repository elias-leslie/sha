"use client";

import { useEffect, useState } from "react";

import { getEndpoint } from "../lib/api";

type EndpointShellTitleProps = {
  endpointId: string;
  initialHostname?: string;
};

export default function EndpointShellTitle({ endpointId, initialHostname }: EndpointShellTitleProps) {
  const [hostname, setHostname] = useState(initialHostname ?? endpointId);

  useEffect(() => {
    let cancelled = false;

    setHostname(initialHostname ?? endpointId);
    getEndpoint(endpointId)
      .then((endpoint) => {
        if (!cancelled) {
          setHostname(endpoint.hostname);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setHostname(initialHostname ?? endpointId);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [endpointId, initialHostname]);

  return <>Endpoint {hostname}</>;
}
