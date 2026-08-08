"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  createInstallerProfile,
  formatDateTime,
  getFixtureInstallerProfiles,
  getFixtureLocations,
  getInstallerArtifact,
  installerChannelDisplay,
  isDemoMode,
  listInstallerProfiles,
  listLocations,
  platformDisplayName,
  policyModeDisplay,
  policyModeTone,
  QUARANTINE_CLIENT_ID,
  type InstallerPolicyMode,
  type InstallerProfile,
  type Location,
  type Platform,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader } from "./console-primitives";
import { hierarchyDisplayName, useScope } from "./scope-context";

type InstallersConsoleProps = {
  initialProfiles?: InstallerProfile[];
  demoMode?: boolean;
};

export default function InstallersConsole({ initialProfiles, demoMode = isDemoMode() }: InstallersConsoleProps) {
  const { scope, clients, ready: scopeReady } = useScope();
  const [profiles, setProfiles] = useState(() => initialProfiles ?? (demoMode ? getFixtureInstallerProfiles() : []));
  const [source, setSource] = useState<"loading" | "demo" | "live" | "error">(
    demoMode ? "demo" : initialProfiles ? "live" : "loading",
  );
  const [pending, setPending] = useState(false);
  const [artifactPending, setArtifactPending] = useState(false);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(
    (initialProfiles ?? (demoMode ? getFixtureInstallerProfiles() : []))[0]?.id ?? null,
  );
  const [lastDownload, setLastDownload] = useState<{
    profileId: string;
    filename: string;
    mediaType: string;
    sha256: string;
  } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [profileLocations, setProfileLocations] = useState<Location[]>(() =>
    demoMode && scope.client_id ? getFixtureLocations(scope.client_id) : [],
  );
  const [knownProfileLocations, setKnownProfileLocations] = useState<Record<string, Location>>({});
  const activeScopeRef = useRef(scope);
  activeScopeRef.current = scope;
  const [form, setForm] = useState({
    name: "Branch Office Linux",
    platform: "linux" as Platform,
    channel: "stable" as InstallerProfile["channel"],
    control_plane_url: "https://sha.example.test",
    policy_mode: "approval_required" as InstallerPolicyMode,
    client_id: scope.client_id ?? "",
    location_id: scope.location_id ?? "",
  });
  const selectedFormClient = clients.find((client) => client.client_id === form.client_id) ?? null;
  const selectedFormLocation =
    profileLocations.find((location) => location.location_id === form.location_id) ?? null;
  const profileScopeAssignable = Boolean(
    selectedFormClient?.state === "active" &&
      !selectedFormClient.is_system &&
      selectedFormLocation?.state === "active" &&
      !selectedFormLocation.is_system &&
      selectedFormLocation.client_id === selectedFormClient.client_id,
  );

  useEffect(() => {
    if (!scopeReady) {
      setProfiles([]);
      setSelectedProfileId(null);
      if (!demoMode) {
        setSource("loading");
      }
      return;
    }
    if (demoMode) {
      const demoProfiles = initialProfiles ?? getFixtureInstallerProfiles();
      const scopedProfiles = demoProfiles.filter(
        (profile) =>
          (!scope.client_id || profile.client_id === scope.client_id) &&
          (!scope.location_id || profile.location_id === scope.location_id),
      );
      setProfiles(scopedProfiles);
      setSelectedProfileId(scopedProfiles[0]?.id ?? null);
      setSource("demo");
      setError(null);
      return;
    }

    let cancelled = false;
    setSource("loading");
    setError(null);
    listInstallerProfiles(scope)
      .then((items) => {
        if (cancelled) {
          return;
        }
        setProfiles(items);
        setSelectedProfileId((current) => (current && items.some((item) => item.id === current) ? current : items[0]?.id ?? null));
        setSource("live");
      })
      .catch((caught) => {
        if (!cancelled) {
          setProfiles([]);
          setSelectedProfileId(null);
          setSource("error");
          setError(caught instanceof Error ? caught.message : "Unable to load live installer profiles.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [demoMode, initialProfiles, scope.client_id, scope.location_id, scopeReady]);

  useEffect(() => {
    setForm((current) => ({
      ...current,
      client_id: scope.client_id ?? "",
      location_id: scope.location_id ?? "",
    }));
  }, [scope.client_id, scope.location_id]);

  useEffect(() => {
    if (!form.client_id) {
      setProfileLocations([]);
      return;
    }
    if (demoMode) {
      setProfileLocations(getFixtureLocations(form.client_id));
      return;
    }

    let cancelled = false;
    listLocations(form.client_id)
      .then((items) => {
        if (!cancelled) {
          setProfileLocations(items);
          setForm((current) => ({
            ...current,
            location_id: items.some((item) => item.location_id === current.location_id)
              ? current.location_id
              : "",
          }));
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setProfileLocations([]);
          setError(caught instanceof Error ? caught.message : "Unable to load profile locations.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [demoMode, form.client_id]);

  useEffect(() => {
    const clientIds = [...new Set(profiles.map((profile) => profile.client_id))];
    if (!clientIds.length) {
      setKnownProfileLocations({});
      return;
    }

    if (demoMode) {
      setKnownProfileLocations(
        Object.fromEntries(
          clientIds
            .flatMap((clientId) => getFixtureLocations(clientId))
            .map((location) => [location.location_id, location]),
        ),
      );
      return;
    }

    let cancelled = false;
    Promise.allSettled(clientIds.map((clientId) => listLocations(clientId))).then((results) => {
      if (cancelled) {
        return;
      }
      setKnownProfileLocations(
        Object.fromEntries(
          results.flatMap((result) =>
            result.status === "fulfilled"
              ? result.value.map((location) => [location.location_id, location] as const)
              : [],
          ),
        ),
      );
    });
    return () => {
      cancelled = true;
    };
  }, [demoMode, profiles]);

  async function downloadArtifact(profileId: string) {
    if (source !== "live") {
      return;
    }
    setArtifactPending(true);
    setError(null);
    setSelectedProfileId(profileId);
    try {
      const rendered = await getInstallerArtifact(profileId);
      const url = URL.createObjectURL(new Blob([rendered.content], { type: rendered.mediaType }));
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = rendered.filename;
        document.body.append(link);
        link.click();
        link.remove();
      } finally {
        URL.revokeObjectURL(url);
      }
      setLastDownload({
        profileId,
        filename: rendered.filename,
        mediaType: rendered.mediaType,
        sha256: rendered.sha256,
      });
      setMessage(`Downloaded ${rendered.filename}. Verify its SHA-256 before running the local file.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to download installer artifact.");
    } finally {
      setArtifactPending(false);
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (source !== "live" || !profileScopeAssignable) {
      return;
    }
    setPending(true);
    setMessage(null);
    setError(null);

    try {
      const created = await createInstallerProfile(form);
      const currentScope = activeScopeRef.current;
      try {
        const refreshed = await listInstallerProfiles(currentScope);
        const scopedProfiles = refreshed.filter(
          (profile) =>
            (!currentScope.client_id || profile.client_id === currentScope.client_id) &&
            (!currentScope.location_id || profile.location_id === currentScope.location_id),
        );
        const createdIsVisible = scopedProfiles.some((profile) => profile.id === created.id);
        setProfiles(scopedProfiles);
        setSelectedProfileId(
          createdIsVisible ? created.id : scopedProfiles[0]?.id ?? null,
        );
        setMessage(
          createdIsVisible
            ? `Created installer profile ${created.name}.`
            : `Created installer profile ${created.name}; it is outside the active viewpoint and is not displayed.`,
        );
      } catch (caught) {
        setProfiles((current) =>
          current.filter(
            (profile) =>
              (!currentScope.client_id || profile.client_id === currentScope.client_id) &&
              (!currentScope.location_id || profile.location_id === currentScope.location_id),
          ),
        );
        setSelectedProfileId(null);
        setMessage(`Created installer profile ${created.name}.`);
        setError(
          caught instanceof Error
            ? `Profile created, but the active registry view could not refresh: ${caught.message}`
            : "Profile created, but the active registry view could not refresh.",
        );
      }
      setLastDownload(null);
      setSource("live");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create installer profile.");
    } finally {
      setPending(false);
    }
  }

  const selectedProfile = profiles.find((profile) => profile.id === selectedProfileId) ?? null;
  const selectedDownload =
    lastDownload && selectedProfile && lastDownload.profileId === selectedProfile.id ? lastDownload : null;

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Package registry"
            title="Installer profiles"
            description="Define per-platform package metadata so enrollment becomes repeatable and policy-aware."
          />
          {profiles.length ? (
            <div className="card-grid">
              {profiles.map((profile) => {
                const profileClient =
                  clients.find((client) => client.client_id === profile.client_id) ?? null;
                const profileLocation = knownProfileLocations[profile.location_id] ?? null;
                const quarantined =
                  profile.client_id === QUARANTINE_CLIENT_ID ||
                  profileClient?.state === "migration_quarantine" ||
                  profileLocation?.state === "migration_quarantine";
                const archived =
                  profileClient?.state === "archived" || profileLocation?.state === "archived";
                return (
                  <article className="mini-card mini-card--interactive" data-active={selectedProfileId === profile.id ? "true" : "false"} key={profile.id}>
                    <div className="operator-list__title-row">
                      <strong>{profile.name}</strong>
                      <Badge tone={policyModeTone(profile.policy_mode)}>{policyModeDisplay(profile.policy_mode)}</Badge>
                    </div>
                    <p>
                      {platformDisplayName(profile.platform)} • {installerChannelDisplay(profile.channel)} • {profile.control_plane_url}
                    </p>
                    <p>
                      scope {profile.tenant_id ?? profile.client_id}/{profile.site_id ?? profile.location_id} • updated {formatDateTime(profile.updated_at)}
                    </p>
                    {quarantined ? <Badge tone="warning">Migration quarantine</Badge> : null}
                    {archived ? <Badge tone="warning">Archived scope</Badge> : null}
                    <div className="button-row button-row--wrap">
                      <button className="action-button action-button--secondary" disabled={source !== "live" || artifactPending} onClick={() => downloadArtifact(profile.id)} type="button">
                        {artifactPending && selectedProfileId === profile.id
                          ? "Preparing download…"
                          : `Download compatibility ${profile.platform === "windows" ? "PowerShell" : "shell"} reporter`}
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <EmptyState
              title={source === "loading" ? "Loading live installer profiles" : source === "error" ? "Installer registry unavailable" : "No live installer profiles"}
              body={source === "loading" ? "Waiting for the installer profile API." : source === "error" ? "Resolve the API or authentication failure before managing installer profiles." : "Create a profile to define how new endpoints should enroll into the control plane."}
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Create profile"
            title="Package definition form"
            description="Define platform installer configuration and policy enforcement mode."
          />
          <form className="form-grid" onSubmit={handleSubmit}>
            <label className="field field--span-2" htmlFor="profile-name">
              <span className="field__label">Profile name</span>
              <input
                className="field__control"
                id="profile-name"
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                required
                value={form.name}
              />
            </label>
            <label className="field" htmlFor="profile-platform">
              <span className="field__label">Platform</span>
              <select
                className="field__control"
                id="profile-platform"
                onChange={(event) => setForm((current) => ({ ...current, platform: event.target.value as Platform }))}
                value={form.platform}
              >
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
              </select>
            </label>
            <label className="field" htmlFor="profile-channel">
              <span className="field__label">Channel</span>
              <select
                className="field__control"
                id="profile-channel"
                onChange={(event) =>
                  setForm((current) => ({ ...current, channel: event.target.value as InstallerProfile["channel"] }))
                }
                value={form.channel}
              >
                <option value="stable">Stable</option>
                <option value="preview">Preview</option>
              </select>
            </label>
            <label className="field" htmlFor="profile-policy-mode">
              <span className="field__label">Policy mode</span>
              <select
                className="field__control"
                id="profile-policy-mode"
                onChange={(event) =>
                  setForm((current) => ({ ...current, policy_mode: event.target.value as InstallerPolicyMode }))
                }
                value={form.policy_mode}
              >
                <option value="observe">Observe</option>
                <option value="safe_auto">Safe auto</option>
                <option value="approval_required">Approval required</option>
              </select>
            </label>
            <label className="field field--span-2" htmlFor="profile-control-plane-url">
              <span className="field__label">Control plane url</span>
              <input
                className="field__control"
                id="profile-control-plane-url"
                onChange={(event) => setForm((current) => ({ ...current, control_plane_url: event.target.value }))}
                required
                type="url"
                value={form.control_plane_url}
              />
            </label>
            <label className="field" htmlFor="profile-client-id">
              <span className="field__label">Client</span>
              <select
                className="field__control"
                disabled={Boolean(scope.client_id)}
                id="profile-client-id"
                onChange={(event) =>
                  setForm((current) => ({
                    ...current,
                    client_id: event.target.value,
                    location_id: "",
                  }))
                }
                required
                value={form.client_id}
              >
                <option value="">Select a client</option>
                {clients.map((client) => (
                  <option key={client.client_id} value={client.client_id}>
                    {hierarchyDisplayName(client)}
                  </option>
                ))}
              </select>
            </label>
            <label className="field" htmlFor="profile-location-id">
              <span className="field__label">Location</span>
              <select
                className="field__control"
                disabled={!form.client_id || Boolean(scope.location_id)}
                id="profile-location-id"
                onChange={(event) =>
                  setForm((current) => ({ ...current, location_id: event.target.value }))
                }
                required
                value={form.location_id}
              >
                <option value="">Select a location</option>
                {profileLocations.map((location) => (
                  <option key={location.location_id} value={location.location_id}>
                    {hierarchyDisplayName(location)}
                  </option>
                ))}
              </select>
            </label>
            <div className="form-actions">
              <button
                className="action-button action-button--primary"
                disabled={pending || source !== "live" || !profileScopeAssignable}
                type="submit"
              >
                {pending ? "Creating…" : source === "demo" ? "Creation disabled in demo" : source === "live" ? "Create installer profile" : "Waiting for live registry"}
              </button>
              <Badge tone={source === "live" ? "success" : source === "error" ? "danger" : "warning"}>
                {source === "live" ? "Live registry" : source === "demo" ? "Demo fixtures" : source === "loading" ? "Loading live registry" : "Live registry unavailable"}
              </Badge>
              {message ? <span className="inline-feedback inline-feedback--success">{message}</span> : null}
              {form.client_id && form.location_id && !profileScopeAssignable ? (
                <span className="inline-feedback inline-feedback--danger">
                  Archived, system, and migration-quarantine scopes cannot receive new installer profiles.
                </span>
              ) : null}
              {error ? <span className="inline-feedback inline-feedback--danger">{error}</span> : null}
            </div>
          </form>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Protected artifact"
            title={selectedProfile ? `Download for ${selectedProfile.name}` : "Select an installer profile"}
            description="Compatibility reporters can contain an agent credential. SHA never previews or retains their body in the page."
          />
          {selectedDownload ? (
            <div className="stack-gap">
              <div className="tag-row">
                <Badge tone="success">{selectedDownload.filename}</Badge>
                <Badge tone="info">{selectedDownload.mediaType}</Badge>
                <Badge tone="warning">sha256 {selectedDownload.sha256}</Badge>
              </div>
              <p>Artifact body downloaded once through the authenticated request. Compare this digest with a local SHA-256 calculation before execution.</p>
            </div>
          ) : (
            <EmptyState
              title="No artifact downloaded"
              body="Choose a live profile and download its compatibility reporter. Token-bearing bodies are not rendered in the browser."
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Operator runbooks"
            title="Verify, then install"
            description="Save the artifact first. Never pipe a network response directly into a privileged shell."
          />
          {selectedProfile ? (
            <div className="stack-gap">
              {selectedProfile.platform === "windows" ? (
                <div className="mini-card">
                  <strong>Windows</strong>
                  <p>Download above, run Get-FileHash .\sha-*.ps1 -Algorithm SHA256, and compare the full digest shown here.</p>
                  <p>Then run the saved file from an elevated PowerShell session using your approved execution-policy process.</p>
                </div>
              ) : (
                <div className="mini-card">
                  <strong>{selectedProfile.platform === "macos" ? "macOS" : "Linux"}</strong>
                  <p>Download above, run sha256sum ./sha-*.sh, and compare the full digest shown here.</p>
                  <p>Then inspect the saved file and run sudo bash ./sha-*.sh.</p>
                </div>
              )}
            </div>
          ) : (
            <EmptyState title="Select a profile" body="Installer commands appear once a profile has been selected." />
          )}
        </Panel>
      </section>
    </>
  );
}
