import InstallersConsole from "../../components/installers-console";
import NavShell from "../../components/nav-shell";

export default function InstallersPage() {
  return (
    <NavShell
      currentPath="/installers"
      scopeAware
      title="Installer Profiles"
      description="Agent deployment packages, platform profiles, and enforcement policy modes for endpoint enrollment."
    >
      <InstallersConsole />
    </NavShell>
  );
}
