"use client";

import { useEffect, useMemo, useState } from "react";

import {
  aggregateControlRollup,
  endpointScore,
  endpointTone,
  formatDateTime,
  getControlLibrary,
  getFixtureApprovalRequests,
  getFixtureEndpointDetails,
  getEndpoint,
  getSourcePack,
  listApprovalRequests,
  listEndpoints,
  listSourcePacks,
  type ApprovalRequest,
  type EndpointDetail,
  type SourcePackDetail,
  type SourcePackSummary,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";

type ControlsConsoleProps = {
  initialDetails?: EndpointDetail[];
  initialRequests?: ApprovalRequest[];
};

export default function ControlsConsole({
  initialDetails = getFixtureEndpointDetails(),
  initialRequests = getFixtureApprovalRequests(),
}: ControlsConsoleProps) {
  const [details, setDetails] = useState(initialDetails);
  const [requests, setRequests] = useState(initialRequests);
  const [library, setLibrary] = useState<SourcePackSummary[]>(() =>
    getControlLibrary().map((item, index) => ({
      pack_id: item.id,
      source_family: "fixture",
      source_name: item.title,
      source_version: item.phase,
      control_count: index + 1,
    })),
  );
  const [selectedPackId, setSelectedPackId] = useState<string | null>(null);
  const [selectedPack, setSelectedPack] = useState<SourcePackDetail | null>(null);
  const [source, setSource] = useState<"fixture" | "live">("fixture");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    Promise.all([listEndpoints(), listApprovalRequests(), listSourcePacks()])
      .then(async ([endpoints, liveRequests, sourcePacks]) => {
        if (cancelled) {
          return;
        }
        setLibrary(sourcePacks);
        setSelectedPackId((current) => current ?? sourcePacks[0]?.pack_id ?? null);
        if (!endpoints.length) {
          setDetails([]);
          setRequests(liveRequests);
          setSource("live");
          return;
        }
        const liveDetails = await Promise.all(endpoints.map((endpoint) => getEndpoint(endpoint.endpoint_id)));
        if (!cancelled) {
          setDetails(liveDetails);
          setRequests(liveRequests);
          setSource("live");
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setSource("fixture");
          setError(caught instanceof Error ? caught.message : "Unable to load control posture.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    if (!selectedPackId || source !== "live") {
      setSelectedPack(null);
      return () => {
        cancelled = true;
      };
    }
    getSourcePack(selectedPackId)
      .then((pack) => {
        if (!cancelled) {
          setSelectedPack(pack);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedPack(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedPackId, source]);

  const rollups = useMemo(() => aggregateControlRollup(details, requests).slice(0, 8), [details, requests]);
  const averageScore = useMemo(() => {
    const scores = details.map(endpointScore).filter((score): score is number => typeof score === "number");
    return scores.length ? Math.round(scores.reduce((total, score) => total + score, 0) / scores.length) : 0;
  }, [details]);

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Control doctrine"
            title="Policy lattice"
            description="This page derives live control health from endpoint posture results and correlates pending approval work."
          />
          <div className="stat-grid">
            <StatCard label="Tracked controls" value={rollups.length} meta="Control keys seen in latest posture" tone="info" />
            <StatCard label="Average posture" value={averageScore || "--"} meta="Weighted endpoint score" tone="success" />
            <StatCard label="Pending changes" value={requests.filter((request) => request.status === "pending").length} meta="Approval requests touching controls" tone="warning" />
            <StatCard label="Source" value={source === "live" ? "Live" : "Fixture"} meta="Control aggregation backend state" tone={source === "live" ? "success" : "warning"} />
          </div>
          {error ? <p className="inline-feedback inline-feedback--danger">{error}</p> : null}
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Library"
            title="Operator control packages"
            description="Use the generated source-pack catalog to inspect pack provenance, platform reach, and control counts."
          />
          <div className="card-grid">
            {library.map((item) => (
              <button className="mini-card mini-card--interactive" data-active={selectedPackId === item.pack_id ? "true" : "false"} key={item.pack_id} onClick={() => setSelectedPackId(item.pack_id)} type="button">
                <div className="operator-list__title-row">
                  <strong>{item.source_name}</strong>
                  <Badge tone="info">{item.source_family}</Badge>
                </div>
                <p>{item.control_count} controls • {item.source_version}</p>
                <p>{item.pack_id}</p>
              </button>
            ))}
          </div>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Control pressure"
            title="Live drift matrix"
            description="Rollup of control failures, warnings, and open requests across endpoint detail payloads."
          />
          {rollups.length ? (
            <div className="operator-list">
              {rollups.map((rollup) => (
                <div className="operator-list__item" key={rollup.controlKey}>
                  <div>
                    <div className="operator-list__title-row">
                      <strong>{rollup.title}</strong>
                      <Badge tone={rollup.tone}>{rollup.controlKey}</Badge>
                    </div>
                    <p>
                      endpoints {rollup.impactedEndpoints.join(", ") || "none"} • fails {rollup.failCount} • warns {rollup.warnCount} • pending changes {rollup.openRequestCount}
                    </p>
                  </div>
                  <div className="operator-list__metric">{rollup.failCount + rollup.warnCount + rollup.errorCount}</div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No posture controls yet" body="Once endpoints post posture snapshots, control rollups will aggregate here automatically." />
          )}
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Endpoint readiness"
            title="Posture sources"
            description="Each endpoint contributes the latest posture summary and remediation pressure."
          />
          <div className="operator-list">
            {details.map((detail) => (
              <a className="operator-list__item" href={`/endpoints/${detail.endpoint_id}`} key={detail.endpoint_id}>
                <div>
                  <div className="operator-list__title-row">
                    <strong>{detail.hostname}</strong>
                    <Badge tone={endpointTone(detail)}>{detail.last_platform_profile ?? "No profile"}</Badge>
                  </div>
                  <p>
                    {detail.latest_posture_summary
                      ? `snapshot ${formatDateTime(detail.latest_posture_summary.observed_at)} • pass ${detail.latest_posture_summary.pass_count} • fail ${detail.latest_posture_summary.fail_count}`
                      : "Awaiting first posture snapshot"}
                  </p>
                </div>
                <div className="operator-list__metric">{endpointScore(detail) ?? "--"}</div>
              </a>
            ))}
          </div>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Selected pack"
            title={selectedPack?.source_name ?? "Pack detail unavailable"}
            description="Inspect pack metadata, provenance, and representative controls before pushing a policy into rollout or approval lanes."
          />
          {selectedPack ? (
            <div className="stack-gap">
              <div className="detail-grid">
                <div className="detail-card">
                  <span>Family</span>
                  <strong>{selectedPack.source_family}</strong>
                </div>
                <div className="detail-card">
                  <span>Version</span>
                  <strong>{selectedPack.source_version}</strong>
                </div>
                <div className="detail-card">
                  <span>Platforms</span>
                  <strong>{selectedPack.platforms.join(", ")}</strong>
                </div>
                <div className="detail-card">
                  <span>Profiles</span>
                  <strong>{selectedPack.profiles.join(", ")}</strong>
                </div>
              </div>
              <div className="tag-row">
                <Badge tone="info">{selectedPack.pack_id}</Badge>
                <Badge tone="warning">{selectedPack.controls.length} controls</Badge>
              </div>
              <p className="muted">{selectedPack.summary}</p>
              <div className="operator-list">
                {selectedPack.controls.slice(0, 4).map((control) => (
                  <div className="operator-list__item" key={control.control_id}>
                    <div>
                      <div className="operator-list__title-row">
                        <strong>{control.title}</strong>
                        <Badge tone={control.auto_remediation_candidate ? "success" : "warning"}>{control.severity}</Badge>
                      </div>
                      <p>{control.control_id} • {control.provenance.source_locator}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState
              title="Select a source pack"
              body="Choose a pack from the library to inspect its metadata and representative controls."
            />
          )}
        </Panel>
      </section>
    </>
  );
}
