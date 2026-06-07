"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";

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
  listEndpoints,
  platformDisplayName,
  type EndpointInventoryItem,
  type Platform,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";

type FleetConsoleProps = {
  initialEndpoints?: EndpointInventoryItem[];
};

const FILTERS = [
  { key: "all", label: "All" },
  { key: "windows", label: "Windows" },
  { key: "linux", label: "Linux" },
  { key: "attention", label: "Needs attention" },
] as const;

export default function FleetConsole({ initialEndpoints = getFixtureEndpoints() }: FleetConsoleProps) {
  const [endpoints, setEndpoints] = useState(initialEndpoints);
  const [source, setSource] = useState<"fixture" | "live">("fixture");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["key"]>("all");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [enrollForm, setEnrollForm] = useState({
    hostname: "demo-lab-linux-01",
    agent_fingerprint: "demo-fingerprint-demo-lab-linux-01",
    platform: "linux" as Platform,
    platform_version: "Ubuntu 24.04 LTS",
    agent_version: "1.0.0",
    tenant_id: "tenant-demo",
    site_id: "site-demo-lab-linux",
  });

  useEffect(() => {
    let cancelled = false;
    listEndpoints()
      .then((items) => {
        if (cancelled) {
          return;
        }
        setEndpoints(items);
        setSource("live");
      })
      .catch(() => {
        if (!cancelled) {
          setSource("fixture");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

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
        return [endpoint.hostname, endpoint.endpoint_id, endpoint.site_id ?? "", endpoint.tenant_id ?? ""]
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
    setPending(true);
    setMessage(null);
    setError(null);

    try {
      const enrolled = await enrollEndpoint(enrollForm);
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
            eyebrow="Fleet status"
            title="Endpoint command board"
            description="Search the fleet, pivot by platform, and drill straight into live endpoint detail routes."
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
            eyebrow="Fleet search"
            title="Filter lane"
            description="Use dense operator filters instead of scrolling static cards."
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
            <Badge tone={source === "live" ? "success" : "warning"}>{source === "live" ? "Live inventory" : "Fixture inventory"}</Badge>
          </div>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Endpoint matrix"
            title="Reachable endpoint routes"
            description="Every row exposes a direct endpoint route with posture, connectivity, and package metadata."
          />
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
                    <a className="action-button action-button--secondary" href={`/endpoints/${endpoint.endpoint_id}`}>
                      Open endpoint {endpoint.hostname}
                    </a>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No endpoints match this filter"
              body="Broaden the search or enroll a new endpoint to repopulate the fleet board."
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Enrollment"
            title="Register a new endpoint"
            description="Use the live enroll API to add a device directly from the control plane."
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
              <span className="field__label">Tenant id</span>
              <input
                className="field__control"
                id="enroll-tenant-id"
                onChange={(event) => setEnrollForm((current) => ({ ...current, tenant_id: event.target.value }))}
                value={enrollForm.tenant_id}
              />
            </label>
            <label className="field" htmlFor="enroll-site-id">
              <span className="field__label">Site id</span>
              <input
                className="field__control"
                id="enroll-site-id"
                onChange={(event) => setEnrollForm((current) => ({ ...current, site_id: event.target.value }))}
                value={enrollForm.site_id}
              />
            </label>
            <div className="form-actions">
              <button className="action-button action-button--primary" disabled={pending} type="submit">
                {pending ? "Enrolling…" : "Enroll endpoint"}
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
