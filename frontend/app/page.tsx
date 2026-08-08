import HomeConsole from "../components/home-console";
import NavShell from "../components/nav-shell";

export default function HomePage() {
  return (
    <NavShell
      currentPath="/"
      title="Security Hardening Automation"
      description="Control plane for endpoint posture monitoring, security compliance auditing, and human-in-the-loop approvals."
    >
      <HomeConsole />
    </NavShell>
  );
}
