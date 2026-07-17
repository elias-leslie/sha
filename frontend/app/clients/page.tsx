import ClientsConsole from "../../components/clients-console";
import NavShell from "../../components/nav-shell";

export default function ClientsPage() {
  return (
    <NavShell
      currentPath="/clients"
      title="Client and location hierarchy"
      description="Manage canonical customer and site boundaries used by endpoint inventory, installer profiles, and later authorization."
    >
      <ClientsConsole />
    </NavShell>
  );
}
