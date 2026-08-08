"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import {
  connectivityDisplay,
  connectivityTone,
  enrollEndpoint,
  endpointScore,
  endpointStateLabel,
  endpointTone,
  fleetSummary,
  formatDateTime,
  getFixtureEndpoints,
  isDemoMode,
  listEndpoints,
  platformDisplayName,
  QUARANTINE_CLIENT_ID,
  type EndpointInventoryItem,
  type Platform,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";
import { useScope } from "./scope-context";

type FleetConsoleProps = {
  initialEndpoints?: EndpointInventoryItem[];
  demoMode?: boolean;
};

const FILTERS = [
  { key: "all", label: "All" },
  { key: "windows", label: "Windows" },
  { key: "linux", label: "Linux" },
  { key: "macos", label: "macOS" },
  { key: "attention", label: "Needs attention" },
] as const;

export default function FleetConsole({ initialEndpoints, demoMode = isDemoMode() }: FleetConsoleProps) {
  const {
    scope,
    href,
    ready: scopeReady,
    selectedClient,
    selectedLocation,
  } = useScope();
  const [endpoints, setEndpoints] = useState(() => initialEndpoints ?? (demoMode ? getFixtureEndpoints() : []));
  const [source, setSource] = useState<"loading" | "demo" | "live" | "error">(
    demoMode ? "demo" : initialEndpoints ? "live" : "loading",
  );
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["key"]>("all");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const activeScopeRef = useRef(scope);
  activeScopeRef.current = scope;
  const [enrollForm, setEnrollForm] = useState({
    hostname: "demo-lab-linux-01",
    agent_fingerprint: "demo-fingerprint-demo-lab-linux-01",
    platform: "linux" as Platform,
    platform_version: "Ubuntu 24.04 LTS",
    agent_version: "1.0.0",
    tenant_id: "",
    site_id: "",
  });
  const boundTenantAlias =
    selectedClient?.state === "active" && !selectedClient.is_system
      ? selectedClient.key
      : null;
  const boundLocationAlias =
    selectedLocation?.state === "active" && !selectedLocation.is_system
      ? selectedLocation.key
      : null;
  const compatibilityEnrollmentBound = Boolean(
    scopeReady &&
      scope.client_id &&
      scope.location_id &&
      selectedClient?.client_id === scope.client_id &&
      selectedLocation?.client_id === scope.client_id &&
      selectedLocation.location_id === scope.location_id &&
      boundTenantAlias &&
      boundLocationAlias,
  );

  useEffect(() => {
    setEnrollForm((current) => ({
      ...current,
      tenant_id: compatibilityEnrollmentBound ? (boundTenantAlias ?? "") : "",
      site_id: compatibilityEnrollmentBound ? (boundLocationAlias ?? "") : "",
    }));
  }, [boundLocationAlias, boundTenantAlias, compatibilityEnrollmentBound]);

  useEffect(() => {
    if (!scopeReady) {
      setEndpoints([]);
      if (!demoMode) {
        setSource("loading");
      }
      return;
    }
    if (demoMode) {
      const demoEndpoints = initialEndpoints ?? getFixtureEndpoints();
      setEndpoints(
        demoEndpoints.filter(
          (endpoint) =>
            (!scope.client_id || endpoint.client_id === scope.client_id) &&
            (!scope.location_id || endpoint.location_id === scope.location_id),
        ),
      );
      setSource("demo");
      setError(null);
      return;
    }

    let cancelled = false;
    setSource("loading");
    setError(null);
    listEndpoints(scope)
      .then((items) => {
        if (cancelled) {
          return;
        }
        setEndpoints(items);
        setSource("live");
      })
      .catch((caught) => {
        if (!cancelled) {
          setEndpoints([]);
          setSource("error");
          setError(caught instanceof Error ? caught.message : "Unable to load live endpoint inventory.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [demoMode, initialEndpoints, scope.client_id, scope.location_id, scopeReady]);

  const summary = useMemo(() => fleetSummary(endpoints), [endpoints]);

  const visibleEndpoints = useMemo(() => {
    return endpoints
      .filter((endpoint) => {
        if (filter === "windows") {
          return endpoint.platform === "windows";
        }
        if (filter === "linux") {
          return endpoint.platform === "linux";
        }
        if (filter === "macos") {
          return endpoint.platform === "macos";
        }
        if (filter === "attention") {
          return endpointTone(endpoint) !== "success";
        }
        return true;
      })
      .filter((endpoint) => {
        const query = search.trim().toLowerCase();
        if (!query) {
          return true;
        }
        return [
          endpoint.hostname,
          endpoint.endpoint_id,
          endpoint.client_id,
          endpoint.location_id,
          endpoint.site_id ?? "",
          endpoint.tenant_id ?? "",
        ]
          .join(" ")
          .toLowerCase()
          .includes(query);
      })
      .sort((left, right) => {
        const leftScore = endpointScore(left) ?? 0;
        const rightScore = endpointScore(right) ?? 0;
        return leftScore - rightScore || left.hostname.localeCompare(right.hostname);
      });
  }, [endpoints, filter, search]);

  async function handleEnroll(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      source !== "live" ||
      !compatibilityEnrollmentBound ||
      !boundTenantAlias ||
      !boundLocationAlias
    ) {
      return;
    }
    setPending(true);
    setMessage(null);
    setError(null);

    try {
      const submissionScope = {
        client_id: scope.client_id,
        location_id: scope.location_id,
      };
      const enrolled = await enrollEndpoint({
        ...enrollForm,
        tenant_id: boundTenantAlias,
        site_id: boundLocationAlias,
      });
      const belongsToSelectedScope =
        enrolled.client_id === submissionScope.client_id &&
        enrolled.location_id === submissionScope.location_id;
      if (!belongsToSelectedScope) {
        setError(
          "Enrollment response did not match the selected client and location. The endpoint was not added to this view; investigate its quarantine assignment.",
        );
        return;
      }
      if (
        activeScopeRef.current.client_id !== submissionScope.client_id ||
        activeScopeRef.current.location_id !== submissionScope.location_id
      ) {
        setError(
          "Enrollment completed for the previously selected scope. The endpoint was not added to the current view.",
        );
        return;
      }
      setEndpoints((current) => [enrolled, ...current.filter((item) => item.endpoint_id !== enrolled.endpoint_id)]);
      setSource("live");
      setMessage(`Endpoint ${enrolled.hostname} enrolled.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to enroll endpoint.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Fleet Inventory"
            title="Fleet Overview"
            description="Monitor connected host inventory, posture health scores, and platform distribution."
          />
          <div className="stat-grid">
            <StatCard label="Registered" value={summary.totalEndpoints} meta="Known endpoints" tone="info" />
            <StatCard label="Connected" value={summary.connectedEndpoints} meta="Healthy control-plane links" tone="success" />
            <StatCard label="Degraded" value={summary.degradedEndpoints} meta="Hosts with posture drift or unstable signal" tone="warning" />
            <StatCard label="Unscanned" value={summary.unscannedEndpoints} meta="Enrolled without posture evidence" tone="danger" />
          </div>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Filter"
            title="Search & Filter"
            description="Filter inventory by hostname, platform, or posture state."
          />
          <div className="toolbar">
            <label className="field field--grow" htmlFor="fleet-search">
              <span className="field__label">Search endpoints</span>
              <input
                id="fleet-search"
                className="field__control"
                onChange={(event) => setSearch(event.target.value)}
                placeholder="hostname, endpoint id, site, tenant"
                type="search"
                value={search}
              />
            </label>
            <div className="segmented-control" role="tablist" aria-label="Fleet filters">
              {FILTERS.map((item) => (
                <button
                  aria-pressed={filter === item.key}
                  className="segmented-control__button"
                  key={item.key}
                  onClick={() => setFilter(item.key)}
                  type="button"
                >
                  {item.label}
                </button>
              ))}
            </div>
            <Badge tone={source === "live" ? "success" : source === "error" ? "danger" : "warning"}>
              {source === "live" ? "Live inventory" : source === "demo" ? "Demo fixtures" : source === "loading" ? "Loading live inventory" : "Live inventory unavailable"}
            </Badge>
          </div>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Fleet Status"
            title="Registered Endpoints"
            description="Endpoint inventory showing posture scores, OS platform, and active connectivity state."
          />
          {error ? <p className="inline-feedback inline-feedback--danger" role="alert">Endpoint inventory load failed: {error}</p> : null}
          {visibleEndpoints.length ? (
            <div className="table-card">
              <div className="table-card__header table-card__row">
                <span>Endpoint</span>
                <span>Platform</span>
                <span>Status</span>
                <span>Signal</span>
                <span>Seen</span>
                <span>Route</span>
              </div>
              {visibleEndpoints.map((endpoint) => (
                <div className="table-card__row" key={endpoint.endpoint_id}>
                  <div>
                    <strong>{endpoint.hostname}</strong>
                    <p>{endpoint.endpoint_id}</p>
                  </div>
                  <div>
                    <strong>{platformDisplayName(endpoint.platform)}</strong>
                    <p>{endpoint.site_id ?? endpoint.tenant_id ?? "Unscoped"}</p>
                    {endpoint.client_id === QUARANTINE_CLIENT_ID ? (
                      <Badge tone="warning">Migration quarantine</Badge>
                    ) : null}
                  </div>
                  <div>
                    <Badge tone={endpointTone(endpoint)}>{endpointStateLabel(endpoint)}</Badge>
                    <p>Score {endpointScore(endpoint) ?? "--"}</p>
                  </div>
                  <div>
                    <Badge tone={connectivityTone(endpoint.connectivity_status)}>{connectivityDisplay(endpoint.connectivity_status)}</Badge>
                    <p>{endpoint.last_platform_profile ?? "Profile pending"}</p>
                  </div>
                  <div>
                    <strong>{formatDateTime(endpoint.last_seen_at)}</strong>
                    <p>agent {endpoint.agent_version}</p>
                  </div>
                  <div>
                    <a
                      className="action-button action-button--secondary"
                      href={href(`/endpoints/${endpoint.endpoint_id}`)}
                    >
                      Open endpoint {endpoint.hostname}
                    </a>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title={source === "loading" ? "Loading live endpoint inventory" : source === "error" ? "Endpoint inventory unavailable" : "No endpoints match this filter"}
              body={source === "loading" ? "Waiting for the endpoint API." : source === "error" ? "Resolve the API or authentication failure before managing endpoints." : "Broaden the search or enroll a new endpoint to repopulate the fleet board."}
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Enrollment"
            title="Register a new endpoint"
            description="Compatibility enrollment is bound to the selected active client and location aliases. Global, all-location, archived, and quarantine viewpoints cannot enroll."
          />
          <form className="form-grid" onSubmit={handleEnroll}>
            <label className="field" htmlFor="enroll-hostname">
              <span className="field__label">Hostname</span>
              <input
                className="field__control"
                id="enroll-hostname"
                onChange={(event) => setEnrollForm((current) => ({ ...current, hostname: event.target.value }))}
                required
                value={enrollForm.hostname}
              />
            </label>
            <label className="field" htmlFor="enroll-fingerprint">
              <span className="field__label">Agent fingerprint</span>
              <input
                className="field__control"
                id="enroll-fingerprint"
                onChange={(event) => setEnrollForm((current) => ({ ...current, agent_fingerprint: event.target.value }))}
                required
                value={enrollForm.agent_fingerprint}
              />
            </label>
            <label className="field" htmlFor="enroll-platform">
              <span className="field__label">Platform</span>
              <select
                className="field__control"
                id="enroll-platform"
                onChange={(event) =>
                  setEnrollForm((current) => ({ ...current, platform: event.target.value as Platform }))
                }
                value={enrollForm.platform}
              >
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
              </select>
            </label>
            <label className="field" htmlFor="enroll-platform-version">
              <span className="field__label">Platform version</span>
              <input
                className="field__control"
                id="enroll-platform-version"
                onChange={(event) => setEnrollForm((current) => ({ ...current, platform_version: event.target.value }))}
                value={enrollForm.platform_version}
              />
            </label>
            <label className="field" htmlFor="enroll-agent-version">
              <span className="field__label">Agent version</span>
              <input
                className="field__control"
                id="enroll-agent-version"
                onChange={(event) => setEnrollForm((current) => ({ ...current, agent_version: event.target.value }))}
                required
                value={enrollForm.agent_version}
              />
            </label>
            <label className="field" htmlFor="enroll-tenant-id">
              <span className="field__label">Bound client alias</span>
              <input
                className="field__control"
                id="enroll-tenant-id"
                readOnly
                value={enrollForm.tenant_id}
              />
            </label>
            <label className="field" htmlFor="enroll-site-id">
              <span className="field__label">Bound location alias</span>
              <input
                className="field__control"
                id="enroll-site-id"
                readOnly
                value={enrollForm.site_id}
              />
            </label>
            <div className="form-actions">
              <button
                className="action-button action-button--primary"
                disabled={pending || source !== "live" || !compatibilityEnrollmentBound}
                type="submit"
              >
                {pending
                  ? "Enrolling…"
                  : source === "demo"
                    ? "Enrollment disabled in demo"
                    : source !== "live"
                      ? "Waiting for live inventory"
                      : compatibilityEnrollmentBound
                        ? "Enroll endpoint"
                        : "Select an active client and location"}
              </button>
              {message ? <span className="inline-feedback inline-feedback--success">{message}</span> : null}
              {error ? <span className="inline-feedback inline-feedback--danger">{error}</span> : null}
            </div>
          </form>
        </Panel>
      </section>
    </>
  );
}
