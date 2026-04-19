import ControlsConsole from "../../components/controls-console";
import NavShell from "../../components/nav-shell";
import { getFixtureApprovalRequests, getFixtureEndpointDetails } from "../../lib/api";

export default function ControlsPage() {
  return (
    <NavShell
      currentPath="/controls"
      title="Control lattice"
      description="Live drift rollups, doctrine packages, and approval pressure mapped onto the active endpoint posture."
    >
      <ControlsConsole initialDetails={getFixtureEndpointDetails()} initialRequests={getFixtureApprovalRequests()} />
    </NavShell>
  );
}
