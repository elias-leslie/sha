"use client";

import { useEffect, useState, type FormEvent } from "react";

import {
  createInstallerProfile,
  formatDateTime,
  getFixtureInstallerProfiles,
  getInstallerArtifact,
  getInstallerArtifactUrl,
  installerChannelDisplay,
  listInstallerProfiles,
  platformDisplayName,
  policyModeDisplay,
  policyModeTone,
  type InstallerArtifact,
  type InstallerPolicyMode,
  type InstallerProfile,
  type Platform,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader } from "./console-primitives";

type InstallersConsoleProps = {
  initialProfiles?: InstallerProfile[];
};

export default function InstallersConsole({ initialProfiles = getFixtureInstallerProfiles() }: InstallersConsoleProps) {
  const [profiles, setProfiles] = useState(initialProfiles);
  const [source, setSource] = useState<"fixture" | "live">("fixture");
  const [pending, setPending] = useState(false);
  const [artifactPending, setArtifactPending] = useState(false);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(initialProfiles[0]?.id ?? null);
  const [artifact, setArtifact] = useState<{ profileId: string; artifact: InstallerArtifact } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "Branch Office Linux",
    platform: "linux" as Platform,
    channel: "stable" as InstallerProfile["channel"],
    control_plane_url: "https://sha.example.test",
    policy_mode: "approval_required" as InstallerPolicyMode,
    tenant_id: "tenant-branch",
    site_id: "site-demo-branch",
  });
  const installOrigin = typeof window === "undefined" ? "https://sha.example.test" : window.location.origin;

  useEffect(() => {
    let cancelled = false;
    listInstallerProfiles()
      .then((items) => {
        if (cancelled) {
          return;
        }
        setProfiles(items);
        setSelectedProfileId((current) => (current && items.some((item) => item.id === current) ? current : items[0]?.id ?? null));
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

  async function loadArtifact(profileId: string) {
    setArtifactPending(true);
    setError(null);
    setSelectedProfileId(profileId);
    try {
      const rendered = await getInstallerArtifact(profileId);
      setArtifact({ profileId, artifact: rendered });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to fetch installer artifact.");
    } finally {
      setArtifactPending(false);
    }
  }

  async function downloadArtifact(profileId: string) {
    setArtifactPending(true);
    setError(null);
    setSelectedProfileId(profileId);
    try {
      const rendered = await getInstallerArtifact(profileId);
      setArtifact({ profileId, artifact: rendered });
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
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to download installer artifact.");
    } finally {
      setArtifactPending(false);
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setMessage(null);
    setError(null);

    try {
      const created = await createInstallerProfile(form);
      setProfiles((current) => [created, ...current.filter((item) => item.id !== created.id)]);
      setSelectedProfileId(created.id);
      setArtifact(null);
      setSource("live");
      setMessage(`Created installer profile ${created.name}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create installer profile.");
    } finally {
      setPending(false);
    }
  }

  const selectedProfile = profiles.find((profile) => profile.id === selectedProfileId) ?? null;
  const selectedArtifact = artifact && selectedProfile && artifact.profileId === selectedProfile.id ? artifact.artifact : null;

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
              {profiles.map((profile) => (
                <article className="mini-card mini-card--interactive" data-active={selectedProfileId === profile.id ? "true" : "false"} key={profile.id}>
                  <div className="operator-list__title-row">
                    <strong>{profile.name}</strong>
                    <Badge tone={policyModeTone(profile.policy_mode)}>{policyModeDisplay(profile.policy_mode)}</Badge>
                  </div>
                  <p>
                    {platformDisplayName(profile.platform)} • {installerChannelDisplay(profile.channel)} • {profile.control_plane_url}
                  </p>
                  <p>
                    scope {profile.tenant_id ?? "global"}/{profile.site_id ?? "all-sites"} • updated {formatDateTime(profile.updated_at)}
                  </p>
                  <div className="button-row button-row--wrap">
                    <button className="action-button action-button--secondary" onClick={() => loadArtifact(profile.id)} type="button">
                      {artifactPending && selectedProfileId === profile.id ? "Loading artifact…" : "Preview artifact"}
                    </button>
                    <button className="action-button action-button--ghost" onClick={() => downloadArtifact(profile.id)} type="button">
                      {artifactPending && selectedProfileId === profile.id
                        ? "Preparing download…"
                        : `Download ${profile.platform === "linux" ? "shell" : "PowerShell"}`}
                    </button>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No live installer profiles"
              body="Create a profile to define how new endpoints should enroll into the control plane."
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Create profile"
            title="Package definition form"
            description="This operator form is wired directly to POST /api/installer-profiles."
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
            <label className="field" htmlFor="profile-tenant-id">
              <span className="field__label">Tenant id</span>
              <input
                className="field__control"
                id="profile-tenant-id"
                onChange={(event) => setForm((current) => ({ ...current, tenant_id: event.target.value }))}
                value={form.tenant_id}
              />
            </label>
            <label className="field" htmlFor="profile-site-id">
              <span className="field__label">Site id</span>
              <input
                className="field__control"
                id="profile-site-id"
                onChange={(event) => setForm((current) => ({ ...current, site_id: event.target.value }))}
                value={form.site_id}
              />
            </label>
            <div className="form-actions">
              <button className="action-button action-button--primary" disabled={pending} type="submit">
                {pending ? "Creating…" : "Create installer profile"}
              </button>
              <Badge tone={source === "live" ? "success" : "warning"}>{source === "live" ? "Live registry" : "Fixture registry"}</Badge>
              {message ? <span className="inline-feedback inline-feedback--success">{message}</span> : null}
              {error ? <span className="inline-feedback inline-feedback--danger">{error}</span> : null}
            </div>
          </form>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--two-up">
        <Panel>
          <SectionHeader
            eyebrow="Bootstrap artifact"
            title={selectedProfile ? `Preview for ${selectedProfile.name}` : "Select an installer profile"}
            description="Preview the generated bootstrap and download it through the authenticated console for VM or host installation."
          />
          {selectedArtifact ? (
            <div className="stack-gap">
              <div className="tag-row">
                <Badge tone="success">{selectedArtifact.filename}</Badge>
                <Badge tone="info">{selectedArtifact.mediaType}</Badge>
                <Badge tone="warning">sha256 {selectedArtifact.sha256.slice(0, 12)}</Badge>
              </div>
              <pre className="code-pane">{selectedArtifact.content}</pre>
            </div>
          ) : (
            <EmptyState
              title="No artifact preview loaded"
              body="Choose a profile above to inspect the generated shell or PowerShell bootstrap before you install it on a host."
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Operator runbooks"
            title="Install commands"
            description="Use the generated artifact directly or curl it into a host-specific install flow."
          />
          {selectedProfile ? (
            <div className="stack-gap">
              <div className="mini-card">
                <strong>Linux</strong>
                <p>curl -fsSL {installOrigin}{getInstallerArtifactUrl(selectedProfile.id)} | sudo bash</p>
                <p>If token protection is enabled, add -H "Authorization: Bearer $SHA_API_TOKEN" before the URL.</p>
              </div>
              <div className="mini-card">
                <strong>Windows</strong>
                <p>iwr {installOrigin}{getInstallerArtifactUrl(selectedProfile.id)} -OutFile sha-agent.ps1; powershell -ExecutionPolicy Bypass -File .\sha-agent.ps1</p>
                <p>If token protection is enabled, pass -Headers @{"{Authorization='Bearer ' + $env:SHA_API_TOKEN}"} to iwr.</p>
              </div>
            </div>
          ) : (
            <EmptyState title="Select a profile" body="Installer commands appear once a profile has been selected." />
          )}
        </Panel>
      </section>
    </>
  );
}
