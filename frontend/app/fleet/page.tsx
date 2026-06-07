import FleetConsole from "../../components/fleet-console";
import NavShell from "../../components/nav-shell";
import { getFixtureEndpoints } from "../../lib/api";

export default function FleetPage() {
  return (
    <NavShell
      currentPath="/fleet"
      title="Fleet command board"
      description="Search, filter, and enroll endpoints from a dense operator surface instead of static status cards."
    >
      <FleetConsole initialEndpoints={getFixtureEndpoints()} />
    </NavShell>
  );
}
