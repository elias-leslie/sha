import ApprovalsConsole from "../../components/approvals-console";
import NavShell from "../../components/nav-shell";
import { getFixtureControlRegistry, isDemoMode } from "../../lib/api";

export default function ApprovalsPage() {
  const demoMode = isDemoMode();
  return (
    <NavShell
      currentPath="/approvals"
      title="Approval command queue"
      description="Operator review surface for hardening changes, bounded troubleshooting, and manual emergency grants."
    >
      <ApprovalsConsole
        demoMode={demoMode}
        initialControls={demoMode ? getFixtureControlRegistry() : undefined}
      />
    </NavShell>
  );
}
