import InstallersConsole from "../../components/installers-console";
import NavShell from "../../components/nav-shell";

export default function InstallersPage() {
  return (
    <NavShell
      currentPath="/installers"
      scopeAware
      title="Installer profile registry"
      description="Package-definition console for Windows, Linux, and macOS enrollment profiles, channels, and policy modes."
    >
      <InstallersConsole />
    </NavShell>
  );
}
