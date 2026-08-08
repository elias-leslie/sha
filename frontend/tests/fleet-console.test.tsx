import { render, screen } from "@testing-library/react"
import { describe, expect, it, beforeEach, vi } from "vitest"

import FleetPage from "../app/fleet/page"
import { getFixtureClients, getFixtureEndpoints } from "../lib/api"

describe("SHA fleet control plane", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/")
  })

  it("renders unified infrastructure hierarchy console", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path === "/api/clients") {
        return Promise.resolve({ ok: true, json: async () => ({ items: getFixtureClients() }) } as Response)
      }
      if (path === "/api/endpoints") {
        return Promise.resolve({ ok: true, json: async () => getFixtureEndpoints() } as Response)
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [] }) } as Response)
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<FleetPage />)

    expect(
      screen.getByRole("heading", { name: "Infrastructure & Systems Hierarchy" }),
    ).toBeInTheDocument()
    expect(screen.getByPlaceholderText("Filter hierarchy...")).toBeInTheDocument()
    expect(screen.getByText("Organizational Hierarchy")).toBeInTheDocument()
  })
})
