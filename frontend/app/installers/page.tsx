import NavShell from "../../components/nav-shell";
import { getInstallerProfiles, platformDisplayName } from "../../lib/api";

function PlatformBadge({ platform }: { platform: "windows" | "linux" }) {
  return <span className="pill pill--info">{platformDisplayName(platform)}</span>;
}

export default function InstallersPage() {
  const profiles = getInstallerProfiles();

  return (
    <NavShell
      title="Installer workspace"
      description="Prepare Windows and Linux profile selection now; package generation wiring will arrive later in the lane."
    >
      <section className="panel stack">
        <div>
          <p className="eyebrow">Profile selection</p>
          <h2>Windows and Linux installer profiles</h2>
        </div>
        <div className="selection-grid">
          {profiles.map((profile) => (
            <article className="profile-card" key={profile.id}>
              <div className="profile-card__meta">
                <PlatformBadge platform={profile.platform} />
                <span className="pill">{profile.packageName}</span>
              </div>
              <h3>{profile.displayName}</h3>
              <p>{profile.description}</p>
              <div className="button-placeholder">Selection placeholder</div>
            </article>
          ))}
        </div>
      </section>

      <section className="subgrid">
        <article className="panel callout">
          <p className="callout__title">Future package generation</p>
          <p>
            This placeholder-only lane leaves space for manifest selection, signing, checksums, and distribution
            targets without requiring the backend to be online.
          </p>
        </article>

        <article className="panel stack">
          <div>
            <p className="eyebrow">Workflow</p>
            <h2>Reserved for package creation</h2>
          </div>
          <p className="muted">
            When generation work arrives, this page can host a platform picker, build summaries, and a launch button
            without any navigation churn.
          </p>
          <div className="button-placeholder">Generate package</div>
        </article>
      </section>
    </NavShell>
  );
}
