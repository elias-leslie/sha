import HierarchyConsole from "../../components/hierarchy-console";
import NavShell from "../../components/nav-shell";

export default function HierarchyPage() {
  return (
    <NavShell
      currentPath="/hierarchy"
      scopeAware
      title="Infrastructure & Endpoint Compliance Console"
      description="Unified client tree, endpoint posture checks, and incident response hardening playbooks."
    >
      <HierarchyConsole />
    </NavShell>
  );
}
