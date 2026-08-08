import ControlsConsole from "../../components/controls-console";
import NavShell from "../../components/nav-shell";

export default function ControlsPage() {
  return (
    <NavShell
      currentPath="/controls"
      title="Hardening Controls"
      description="OS security controls, compliance benchmark mapping (NIST/DISA/CISA), and posture enforcement status across endpoints."
    >
      <ControlsConsole />
    </NavShell>
  );
}
