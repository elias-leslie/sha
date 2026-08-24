import { render, screen, waitFor } from "@testing-library/react"

import HierarchyPage from "../app/hierarchy/page"
import { fetchJson, getDemoClients, getDemoEndpoints } from "../lib/api"

function withDemoMode(run: () => void | Promise<void>) {
  const previous = process.env.NEXT_PUBLIC_SHA_DEMO_MODE
  process.env.NEXT_PUBLIC_SHA_DEMO_MODE = "true"
  const restore = () => {
    if (previous === undefined) {
      delete process.env.NEXT_PUBLIC_SHA_DEMO_MODE
    } else {
      process.env.NEXT_PUBLIC_SHA_DEMO_MODE = previous
    }
  }
  return Promise.resolve()
    .then(run)
    .finally(restore)
}

describe("SHA demo mode", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/")
  })

  it("serves an invented fleet without contacting the API", async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    await withDemoMode(async () => {
      render(<HierarchyPage />)

      // The tenant appears in both the scope selector and the client tree.
      await waitFor(() => {
        expect(screen.getAllByText("Northwind Trading Co.").length).toBeGreaterThan(0)
      })
      expect(screen.getAllByText("Cascade Orthopedics").length).toBeGreaterThan(0)
      expect(fetchMock).not.toHaveBeenCalled()
    })
  })

  it("refuses every mutation instead of reaching the backend", async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    await withDemoMode(async () => {
      await expect(
        fetchJson("/api/clients", { method: "POST", body: "{}" }),
      ).rejects.toThrow(/disabled while the console is in demo mode/i)
      expect(fetchMock).not.toHaveBeenCalled()
    })
  })

  it("publishes no real tenant, site, or host identifiers", () => {
    const clients = getDemoClients()
    const endpoints = getDemoEndpoints()

    expect(clients.length).toBeGreaterThan(0)
    expect(endpoints.length).toBeGreaterThan(0)

    const text = JSON.stringify({ clients, endpoints }).toLowerCase()
    for (const forbidden of ["summitflow", "davion", "elias", "leslie", "tenant_home_primary", "quarantine"]) {
      expect(text).not.toContain(forbidden)
    }
  })
})
