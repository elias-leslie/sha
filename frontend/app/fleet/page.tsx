import FleetConsole from "../../components/fleet-console";
import FleetMetadataConsole from "../../components/fleet-metadata-console";
import NavShell from "../../components/nav-shell";

export default function FleetPage() {
  return (
    <NavShell
      currentPath="/fleet"
      scopeAware
      title="Fleet command board"
      description="Search, filter, and enroll endpoints from a dense operator surface instead of static status cards."
    >
      <FleetConsole />
      <FleetMetadataConsole />
    </NavShell>
  );
}
