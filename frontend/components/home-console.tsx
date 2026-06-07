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

type HomeConsoleProps = {
  initialEndpoints?: EndpointInventoryItem[];
  initialRequests?: ApprovalRequest[];
  initialGrants?: ApprovalGrant[];
  initialProfiles?: InstallerProfile[];
};

export default function HomeConsole({
  initialEndpoints = getFixtureEndpoints(),
  initialRequests = getFixtureApprovalRequests(),
  initialGrants = getFixtureApprovalGrants(),
  initialProfiles = getFixtureInstallerProfiles(),
}: HomeConsoleProps) {
  const [endpoints, setEndpoints] = useState(initialEndpoints);
  const [requests, setRequests] = useState(initialRequests);
  const [grants, setGrants] = useState(initialGrants);
  const [profiles, setProfiles] = useState(initialProfiles);
  const [source, setSource] = useState<"fixture" | "live">("fixture");

  useEffect(() => {
    let cancelled = false;

    Promise.all([listEndpoints(), listApprovalRequests(), listApprovalGrants(), listInstallerProfiles()])
      .then(([liveEndpoints, liveRequests, liveGrants, liveProfiles]) => {
        if (cancelled) {
          return;
        }
        setEndpoints(liveEndpoints);
        setRequests(liveRequests);
        setGrants(liveGrants);
        setProfiles(liveProfiles);
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
              <p className="hero-panel__eyebrow">Containment posture</p>
              <h2>Operator-grade visibility for endpoint drift, approvals, and installer readiness.</h2>
              <p className="hero-panel__copy">
                SHA keeps hardening changes bounded: collect posture, route risky actions through human approval, and keep
                operator context anchored to the live fleet whenever the backend is reachable.
              </p>
            </div>
            <Badge tone={source === "live" ? "success" : "warning"}>{source === "live" ? "Live backend" : "Fixture rail"}</Badge>
          </div>
          <div className="stat-grid">
            <StatCard label="Endpoints" value={summary.totalEndpoints} meta="Registered control-plane assets" tone="info" />
            <StatCard label="Average score" value={summary.averageScore || "--"} meta="Weighted posture confidence" tone="success" />
            <StatCard label="Pending approvals" value={summary.pendingApprovals} meta="Disruptive changes awaiting review" tone="warning" />
            <StatCard label="Active grants" value={summary.activeGrants} meta="Time-boxed elevated access windows" tone="danger" />
          </div>
        </Panel>

        <Panel className="hero-panel hero-panel--secondary">
          <SectionHeader
            eyebrow="Control doctrine"
            title="Execution rails"
            description="Direct every action through a bounded lane — observe, approve, or package."
          />
          <div className="command-list">
            <a className="command-link" href="/fleet">
              <strong>Fleet watch</strong>
              <span>Search live endpoints, inspect drift, and register new agents.</span>
            </a>
            <a className="command-link" href="/approvals">
              <strong>Approval review</strong>
              <span>Decide high-risk rollout requests and create emergency grants.</span>
            </a>
            <a className="command-link" href="/installers">
              <strong>Installer profiles</strong>
              <span>Define per-platform enrollment packages and control-plane policy modes.</span>
            </a>
          </div>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Priority watchlist"
            title="Fleet command board"
            description="Highest-signal endpoints sorted by current posture and control drift."
          />
          <div className="operator-list">
            {watchlist.map((endpoint) => (
              <a className="operator-list__item" href={`/endpoints/${endpoint.endpoint_id}`} key={endpoint.endpoint_id}>
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
            eyebrow="Approval pressure"
            title="Risk queue"
            description="Human review remains the gate for disruptive controls and temporary troubleshooting windows."
          />
          {pendingRequests.length ? (
            <div className="operator-list">
              {pendingRequests.map((request) => (
                <a className="operator-list__item" href="/approvals" key={request.approval_request_id}>
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
              title="No live approval queue"
              body="The backend currently has no pending approval requests. Use the approvals console to create one when a rollout needs human review."
              action={
                <a className="action-button action-button--secondary" href="/approvals">
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
            eyebrow="Packaging"
            title="Installer profile posture"
            description="Profiles remain package metadata until operators create live platform definitions."
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
              body="Create a platform profile to turn enrollment into a repeatable package lane."
              action={
                <a className="action-button action-button--secondary" href="/installers">
                  Create profile
                </a>
              }
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Telemetry integrity"
            title="Command timeline"
            description="Recent fleet events that influence operator trust in the control plane."
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
