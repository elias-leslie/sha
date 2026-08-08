import ApprovalsConsole from "../../components/approvals-console";
import NavShell from "../../components/nav-shell";
import { getFixtureControlRegistry, isDemoMode } from "../../lib/api";

export default function ApprovalsPage() {
  const demoMode = isDemoMode();
  return (
    <NavShell
      currentPath="/approvals"
      title="Approval Queue"
      description="Review and authorize pending configuration changes, elevated access requests, and temporary troubleshooting grants."
    >
      <ApprovalsConsole
        demoMode={demoMode}
        initialControls={demoMode ? getFixtureControlRegistry() : undefined}
      />
    </NavShell>
  );
}
