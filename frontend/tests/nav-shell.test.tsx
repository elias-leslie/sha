import { render, screen, waitFor } from "@testing-library/react"

import FleetPage from "../app/fleet/page"
import HomePage from "../app/page"
import EndpointDetailPage from "../app/endpoints/[endpointId]/page"
import NavShell from "../components/nav-shell"
import { getFixtureClients } from "../lib/api"

describe("SHA dashboard shell", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/")
  })

  it("renders the shared navigation with active operator context", () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, json: async () => ({ items: getFixtureClients() }) }) as Response),
    )

    render(
      <NavShell currentPath="/fleet" title="Test title" description="Test description">
        <p>Child content</p>
      </NavShell>,
    )

    expect(screen.getByRole("heading", { name: "Test title" })).toBeInTheDocument()
    expect(screen.getAllByText(/operator supervised autonomy/i).length).toBeGreaterThan(0)
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute("href", "/fleet")
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute("data-active", "true")
    expect(screen.getByRole("link", { name: "Clients" })).toHaveAttribute("href", "/clients")
    expect(screen.queryByRole("region", { name: /scope selector/i })).not.toBeInTheDocument()
    expect(screen.getByRole("region", { name: /scope applicability/i })).toHaveTextContent(
      /global-only view/i,
    )
    expect(screen.getByText("Child content")).toBeInTheDocument()
  })

  it("retains selected scope in navigation without claiming global pages are filtered", async () => {
    window.history.replaceState({}, "", "/approvals?client_id=cl_alpha&location_id=loc_main")
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input)
        if (path === "/api/clients") {
          return {
            ok: true,
            json: async () => ({
              items: [
                {
                  client_id: "cl_alpha",
                  key: "tenant-alpha",
                  name: "Alpha",
                  state: "active",
                  is_system: false,
                  created_at: "2026-07-17T12:00:00Z",
                  updated_at: "2026-07-17T12:00:00Z",
                },
              ],
            }),
          } as Response
        }
        if (path === "/api/clients/cl_alpha/locations") {
          return {
            ok: true,
            json: async () => ({
              items: [
                {
                  location_id: "loc_main",
                  client_id: "cl_alpha",
                  key: "site-main",
                  name: "Main",
                  state: "active",
                  is_system: false,
                  created_at: "2026-07-17T12:00:00Z",
                  updated_at: "2026-07-17T12:00:00Z",
                },
              ],
            }),
          } as Response
        }
        throw new Error(`Unexpected request: ${path}`)
      }),
    )

    render(
      <NavShell currentPath="/approvals" title="Global actions" description="Global action page">
        <p>Global content</p>
      </NavShell>,
    )

    expect(screen.queryByRole("region", { name: /scope selector/i })).not.toBeInTheDocument()
    expect(screen.getByRole("region", { name: /scope applicability/i })).toHaveTextContent(
      /does not filter or authorize this page/i,
    )
    await waitFor(() =>
      expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute(
        "href",
        "/fleet?client_id=cl_alpha&location_id=loc_main",
      ),
    )
  })

  it("makes explicit demo mode global and disables live mutations", () => {
    const previousDemoMode = process.env.NEXT_PUBLIC_SHA_DEMO_MODE
    process.env.NEXT_PUBLIC_SHA_DEMO_MODE = "true"
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<FleetPage />)
      expect(screen.getByRole("status")).toHaveTextContent(/demo mode.*fixture data only.*mutations disabled/i)
      expect(screen.getByText(/demo fixtures/i)).toBeInTheDocument()
      expect(screen.getByRole("button", { name: /enrollment disabled in demo/i })).toBeDisabled()
      expect(fetchMock).not.toHaveBeenCalled()
    } finally {
      if (previousDemoMode === undefined) {
        delete process.env.NEXT_PUBLIC_SHA_DEMO_MODE
      } else {
        process.env.NEXT_PUBLIC_SHA_DEMO_MODE = previousDemoMode
      }
    }
  })

  it("renders the redesigned home page and delays endpoint actions until live identity loads", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})))

    render(<HomePage />)
    expect(screen.getByRole("heading", { name: /security control plane/i })).toBeInTheDocument()
    expect(screen.getByText(/containment posture/i)).toBeInTheDocument()

    render(<EndpointDetailPage params={{ endpointId: "ep_demo_linux_01" }} />)
    expect(screen.getByRole("heading", { name: /loading endpoint ep_demo_linux_01/i })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /send heartbeat/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /record posture snapshot/i })).not.toBeInTheDocument()
  })
})
