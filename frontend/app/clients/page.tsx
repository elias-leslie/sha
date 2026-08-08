import HierarchyConsole from "../../components/hierarchy-console";
import NavShell from "../../components/nav-shell";

export default function ClientsPage() {
  return (
    <NavShell
      currentPath="/clients"
      scopeAware
      title="Infrastructure & Systems Hierarchy"
      description="Interactive hierarchy of clients, locations, and host systems with posture assessment and control actions."
    >
      <HierarchyConsole />
    </NavShell>
  );
}
