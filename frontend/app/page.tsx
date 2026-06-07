import HomeConsole from "../components/home-console";
import NavShell from "../components/nav-shell";
import {
  getFixtureApprovalGrants,
  getFixtureApprovalRequests,
  getFixtureEndpoints,
  getFixtureInstallerProfiles,
} from "../lib/api";

export default function HomePage() {
  return (
    <NavShell
      currentPath="/"
      title="Security control plane"
      description="Dark amber operator workspace for endpoint hardening, bounded approvals, and installer orchestration."
    >
      <HomeConsole
        initialEndpoints={getFixtureEndpoints()}
        initialGrants={getFixtureApprovalGrants()}
        initialProfiles={getFixtureInstallerProfiles()}
        initialRequests={getFixtureApprovalRequests()}
      />
    </NavShell>
  );
}
