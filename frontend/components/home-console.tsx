"use client";

import { useEffect, useMemo, useState } from "react";

import {
  approvalRiskDisplay,
  approvalRiskTone,
  approvalStatusDisplay,
  approvalStatusTone,
  connectivityDisplay,
  connectivityTone,
  endpointScore,
  endpointStateLabel,
  endpointTone,
  fleetSummary,
  formatDateTime,
  formatRelativeTime,
  getFixtureApprovalGrants,
  getFixtureApprovalRequests,
  getFixtureEndpoints,
  getFixtureInstallerProfiles,
  isDemoMode,
  listApprovalGrants,
  listApprovalRequests,
  listEndpoints,
  listInstallerProfiles,
  platformDisplayName,
  policyModeDisplay,
  policyModeTone,
  type ApprovalGrant,
  type ApprovalRequest,
  type EndpointInventoryItem,
  type InstallerProfile,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";
import { useScope } from "./scope-context";

type HomeConsoleProps = {
  initialEndpoints?: EndpointInventoryItem[];
  initialRequests?: ApprovalRequest[];
  initialGrants?: ApprovalGrant[];
  initialProfiles?: InstallerProfile[];
  demoMode?: boolean;
};

export default function HomeConsole({
  initialEndpoints,
  initialRequests,
  initialGrants,
  initialProfiles,
  demoMode = isDemoMode(),
}: HomeConsoleProps) {
  const { href } = useScope();
  const [endpoints, setEndpoints] = useState(() => initialEndpoints ?? (demoMode ? getFixtureEndpoints() : []));
  const [requests, setRequests] = useState(() => initialRequests ?? (demoMode ? getFixtureApprovalRequests() : []));
  const [grants, setGrants] = useState(() => initialGrants ?? (demoMode ? getFixtureApprovalGrants() : []));
  const [profiles, setProfiles] = useState(() => initialProfiles ?? (demoMode ? getFixtureInstallerProfiles() : []));
  const [source, setSource] = useState<"loading" | "demo" | "live" | "error">(demoMode ? "demo" : "loading");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (demoMode) {
      setSource("demo");
      setError(null);
      return;
    }

    let cancelled = false;
    setSource("loading");
    setError(null);
    Promise.allSettled([listEndpoints(), listApprovalRequests(), listApprovalGrants(), listInstallerProfiles()]).then(
      ([endpointResult, requestResult, grantResult, profileResult]) => {
        if (cancelled) {
          return;
        }
        if (endpointResult.status === "fulfilled") {
          setEndpoints(endpointResult.value);
        }
        if (requestResult.status === "fulfilled") {
          setRequests(requestResult.value);
        }
        if (grantResult.status === "fulfilled") {
          setGrants(grantResult.value);
        }
        if (profileResult.status === "fulfilled") {
          setProfiles(profileResult.value);
        }
        const failures = [endpointResult, requestResult, grantResult, profileResult].filter(
          (result): result is PromiseRejectedResult => result.status === "rejected",
        );
        setSource(failures.length ? "error" : "live");
        setError(
          failures.length
            ? `Partial live data: ${failures
                .map((result) => (result.reason instanceof Error ? result.reason.message : "resource unavailable"))
                .join(" ")}`
            : null,
        );
      },
    );

    return () => {
      cancelled = true;
    };
  }, [demoMode, initialEndpoints, initialGrants, initialProfiles, initialRequests]);

  const summary = useMemo(() => fleetSummary(endpoints, requests, grants), [endpoints, grants, requests]);
  const watchlist = useMemo(
    () => [...endpoints].sort((left, right) => (endpointScore(right) ?? 0) - (endpointScore(left) ?? 0)).slice(0, 4),
    [endpoints],
  );
  const pendingRequests = useMemo(() => requests.filter((request) => request.status === "pending").slice(0, 3), [requests]);

  return (
    <>
      <section className="hero-grid">
        <Panel className="hero-panel hero-panel--primary">
          <div className="hero-panel__masthead">
            <div>
              <p className="hero-panel__eyebrow">Fleet Posture</p>
              <h2>Real-time endpoint hardening, posture compliance, and approval workflows.</h2>
              <p className="hero-panel__copy">
                OS hardening baseline verification, posture snapshot analysis, and human-in-the-loop approvals across Linux and Windows endpoints.
              </p>
            </div>
            <Badge tone={source === "live" ? "success" : source === "error" ? "danger" : "warning"}>
              {source === "live" ? "Live backend" : source === "demo" ? "Demo mode" : source === "loading" ? "Connecting to backend" : "Backend offline"}
            </Badge>
          </div>
          {error ? <p className="inline-feedback inline-feedback--danger" role="alert">Data load status: {error}</p> : null}
          <div className="stat-grid">
            <StatCard label="Endpoints" value={summary.totalEndpoints} meta="Registered assets" tone="info" />
            <StatCard label="Average score" value={summary.averageScore || "--"} meta="Posture confidence score" tone="success" />
            <StatCard label="Pending approvals" value={summary.pendingApprovals} meta="Awaiting operator review" tone="warning" />
            <StatCard label="Active grants" value={summary.activeGrants} meta="Elevated access windows" tone="danger" />
          </div>
        </Panel>

        <Panel className="hero-panel hero-panel--secondary">
          <SectionHeader
            eyebrow="Fleet Command"
            title="Operator Navigation"
            description="Access live endpoint posture, approval review queues, and installer packages."
          />
          <div className="command-list">
            <a className="command-link" href={href("/hierarchy")}>
              <strong>Hierarchy & Systems</strong>
              <span>Inspect clients, locations, host systems, and posture compliance.</span>
            </a>
            <a className="command-link" href={href("/approvals")}>
              <strong>Approval review</strong>
              <span>Review elevated requests and issue time-boxed troubleshooting grants.</span>
            </a>
            <a className="command-link" href={href("/installers")}>
              <strong>Installer profiles</strong>
              <span>View enrollment packages and control-plane policy modes.</span>
            </a>
          </div>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Fleet Inventory"
            title="Active Endpoints"
            description="Endpoints sorted by current posture score and compliance state."
          />
          <div className="operator-list">
            {watchlist.map((endpoint) => (
              <a
                className="operator-list__item"
                href={href(`/endpoints/${endpoint.endpoint_id}`)}
                key={endpoint.endpoint_id}
              >
                <div>
                  <div className="operator-list__title-row">
                    <strong>{endpoint.hostname}</strong>
                    <Badge tone={endpointTone(endpoint)}>{endpointStateLabel(endpoint)}</Badge>
                    <Badge tone={connectivityTone(endpoint.connectivity_status)}>{connectivityDisplay(endpoint.connectivity_status)}</Badge>
                  </div>
                  <p>
                    {platformDisplayName(endpoint.platform)} • {endpoint.last_platform_profile ?? "profile pending"} • last signal {formatRelativeTime(endpoint.last_seen_at)}
                  </p>
                </div>
                <div className="operator-list__metric">{endpointScore(endpoint) ?? "--"}</div>
              </a>
            ))}
          </div>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Approval Queue"
            title="Pending Hardening Requests"
            description="Disruptive configuration changes and elevated access windows requiring human approval."
          />
          {pendingRequests.length ? (
            <div className="operator-list">
              {pendingRequests.map((request) => (
                <a
                  className="operator-list__item"
                  href={href("/approvals")}
                  key={request.approval_request_id}
                >
                  <div>
                    <div className="operator-list__title-row">
                      <strong>{request.reason}</strong>
                      <Badge tone={approvalStatusTone(request.status)}>{approvalStatusDisplay(request.status)}</Badge>
                      <Badge tone={approvalRiskTone(request.risk)}>Risk {approvalRiskDisplay(request.risk)}</Badge>
                    </div>
                    <p>
                      Requested by {request.requested_by} • TTL {request.requested_ttl_minutes}m • opened {formatDateTime(request.created_at)}
                    </p>
                  </div>
                </a>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No pending requests"
              body="No approval requests are currently awaiting review."
              action={
                <a className="action-button action-button--secondary" href={href("/approvals")}>
                  Open approval console
                </a>
              }
            />
          )}
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Platform Profiles"
            title="Deployment Profiles"
            description="Platform installer definitions and policy enforcement modes."
          />
          {profiles.length ? (
            <div className="card-grid">
              {profiles.slice(0, 3).map((profile) => (
                <article className="mini-card" key={profile.id}>
                  <div className="operator-list__title-row">
                    <strong>{profile.name}</strong>
                    <Badge tone={policyModeTone(profile.policy_mode)}>{policyModeDisplay(profile.policy_mode)}</Badge>
                  </div>
                  <p>
                    {platformDisplayName(profile.platform)} • {profile.control_plane_url}
                  </p>
                </article>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No installer profiles"
              body="Platform installer profiles define baseline configurations for new endpoints."
              action={
                <a className="action-button action-button--secondary" href={href("/installers")}>
                  Create profile
                </a>
              }
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="System Events"
            title="Recent Activity"
            description="Recent endpoint telemetry and health status changes."
          />
          <div className="timeline-list">
            {endpoints.slice(0, 4).map((endpoint) => (
              <div className="timeline-list__item" key={endpoint.endpoint_id}>
                <span className={`timeline-list__dot timeline-list__dot--${endpointTone(endpoint)}`} />
                <div>
                  <strong>{endpoint.hostname}</strong>
                  <p>
                    {endpointStateLabel(endpoint)} • {formatDateTime(endpoint.last_seen_at)} • {platformDisplayName(endpoint.platform)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </section>
    </>
  );
}
