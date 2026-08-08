import { render, screen, waitFor } from "@testing-library/react"

import FleetPage from "../app/fleet/page"
import HierarchyPage from "../app/hierarchy/page"
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
    expect(screen.getByText(/endpoint posture & compliance/i)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Computers" })).toHaveAttribute("href", "/hierarchy")
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

    await waitFor(() =>
      expect(screen.getByRole("link", { name: "Computers" })).toHaveAttribute(
        "href",
        "/hierarchy?client_id=cl_alpha&location_id=loc_main",
      ),
    )
    expect(screen.getByRole("link", { name: "Sessions" })).toHaveAttribute(
      "href",
      "/approvals?client_id=cl_alpha&location_id=loc_main",
    )
  })

  it("makes explicit demo mode global and disables live mutations", () => {
    const previousDemoMode = process.env.NEXT_PUBLIC_SHA_DEMO_MODE
    process.env.NEXT_PUBLIC_SHA_DEMO_MODE = "true"
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<HierarchyPage />)
      expect(screen.getByRole("status")).toHaveTextContent(/demo mode.*fixture data only.*mutations disabled/i)
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
    expect(screen.getByRole("heading", { name: /security hardening automation/i })).toBeInTheDocument()
    expect(screen.getAllByText(/posture compliance/i).length).toBeGreaterThan(0)

    render(<EndpointDetailPage params={{ endpointId: "ep_demo_linux_01" }} />)
    expect(screen.getByRole("heading", { name: /loading endpoint ep_demo_linux_01/i })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /send heartbeat/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /record posture snapshot/i })).not.toBeInTheDocument()
  })
})
