import ApprovalsConsole from "../../components/approvals-console";
import NavShell from "../../components/nav-shell";
import {
  getFixtureApprovalGrants,
  getFixtureApprovalRequests,
  getFixtureEndpoints,
} from "../../lib/api";

export default function ApprovalsPage() {
  return (
    <NavShell
      currentPath="/approvals"
      title="Approval command queue"
      description="Operator review surface for hardening changes, bounded troubleshooting, and manual emergency grants."
    >
      <ApprovalsConsole
        initialEndpoints={getFixtureEndpoints()}
        initialGrants={getFixtureApprovalGrants()}
        initialRequests={getFixtureApprovalRequests()}
      />
    </NavShell>
  );
}
