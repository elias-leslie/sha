import FleetMetadataConsole from "../../components/fleet-metadata-console";
import HierarchyConsole from "../../components/hierarchy-console";
import NavShell from "../../components/nav-shell";

export default function FleetPage() {
  return (
    <NavShell
      currentPath="/hierarchy"
      scopeAware
      title="Infrastructure & Systems Hierarchy"
      description="Interactive hierarchy of clients, locations, and host systems with posture assessment and control actions."
    >
      <HierarchyConsole />
      <FleetMetadataConsole />
    </NavShell>
  );
}
