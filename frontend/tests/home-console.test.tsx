import { render, screen, waitFor } from "@testing-library/react"

import HomePage from "../app/page"
import HomeConsole from "../components/home-console"
import { ScopeProvider } from "../components/scope-context"
import { getFixtureEndpoints } from "../lib/api"

describe("SHA home console", () => {
  it("keeps successful dashboard datasets when another resource fails", async () => {
    const endpoint = getFixtureEndpoints()[0]
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/endpoints")) {
          return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
        }
        if (url.endsWith("/api/approval-requests")) {
          return { ok: false, status: 503, json: async () => ({ detail: "approval data unavailable" }) } as Response
        }
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }),
    )

    render(
      <ScopeProvider demoMode={false}>
        <HomeConsole />
      </ScopeProvider>,
    )

    expect(await screen.findByRole("alert")).toHaveTextContent(/partial live data: approval data unavailable/i)
    expect(screen.getAllByText(endpoint.hostname).length).toBeGreaterThan(0)
    expect(screen.getByText(/live backend unavailable/i)).toBeInTheDocument()
  })

  it("preserves selected scope in dashboard links while remaining a global-only view", async () => {
    window.history.replaceState({}, "", "/?client_id=cl_alpha&location_id=loc_main")
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
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }),
    )

    render(<HomePage />)

    expect(screen.queryByRole("region", { name: /scope selector/i })).not.toBeInTheDocument()
    expect(screen.getByRole("region", { name: /scope applicability/i })).toHaveTextContent(
      /global-only view/i,
    )
    await waitFor(() =>
      expect(screen.getByRole("link", { name: /fleet watch/i })).toHaveAttribute(
        "href",
        "/fleet?client_id=cl_alpha&location_id=loc_main",
      ),
    )
    expect(screen.getByRole("link", { name: /approval review/i })).toHaveAttribute(
      "href",
      "/approvals?client_id=cl_alpha&location_id=loc_main",
    )
    expect(screen.getByRole("link", { name: /installer profiles/i })).toHaveAttribute(
      "href",
      "/installers?client_id=cl_alpha&location_id=loc_main",
    )
  })
})
