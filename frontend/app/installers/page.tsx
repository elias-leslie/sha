import InstallersConsole from "../../components/installers-console";
import NavShell from "../../components/nav-shell";
import { getFixtureInstallerProfiles } from "../../lib/api";

export default function InstallersPage() {
  return (
    <NavShell
      currentPath="/installers"
      title="Installer profile registry"
      description="Package-definition console for Windows, Linux, and macOS enrollment profiles, channels, and policy modes."
    >
      <InstallersConsole initialProfiles={getFixtureInstallerProfiles()} />
    </NavShell>
  );
}
