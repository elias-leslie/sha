import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import ClientsPage from "../app/clients/page"
import {
  QUARANTINE_CLIENT_ID,
  QUARANTINE_LOCATION_ID,
  type Client,
  type Location,
} from "../lib/api"

const now = "2026-07-17T12:00:00Z"

function hierarchyFixtures() {
  const clients: Client[] = [
    {
      client_id: "cl_alpha",
      key: "tenant-alpha",
      name: "Alpha Health",
      state: "active",
      is_system: false,
      created_at: now,
      updated_at: now,
    },
    {
      client_id: QUARANTINE_CLIENT_ID,
      key: null,
      name: "Legacy scope quarantine",
      state: "migration_quarantine",
      is_system: true,
      created_at: now,
      updated_at: now,
    },
  ]
  const locations = new Map<string, Location[]>([
    [
      "cl_alpha",
      [
        {
          location_id: "loc_alpha_main",
          client_id: "cl_alpha",
          key: "site-main",
          name: "Main office",
          state: "active",
          is_system: false,
          created_at: now,
          updated_at: now,
        },
      ],
    ],
  ])
  return { clients, locations }
}

function hierarchyFetch() {
  const fixtures = hierarchyFixtures()
  const requests: Array<{ url: string; init?: RequestInit }> = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? "GET"
    requests.push({ url, init })

    if (url === "/api/clients" && method === "GET") {
      return { ok: true, json: async () => ({ items: fixtures.clients }) } as Response
    }
    if (url === "/api/endpoints" && method === "GET") {
      return { ok: true, json: async () => [] } as Response
    }

    const locationMatch = url.match(/^\/api\/clients\/([^/]+)\/locations$/)
    if (locationMatch && method === "GET") {
      return {
        ok: true,
        json: async () => ({ items: fixtures.locations.get(locationMatch[1]) ?? [] }),
      } as Response
    }

    return {
      ok: false,
      status: 404,
      json: async () => ({ detail: `not found: ${method} ${url}` }),
    } as Response
  })
  return { fetchMock, requests }
}

describe("SHA client hierarchy route", () => {
  it("renders unified infrastructure hierarchy console", async () => {
    const { fetchMock } = hierarchyFetch()
    vi.stubGlobal("fetch", fetchMock)

    render(<ClientsPage />)

    expect((await screen.findAllByText("Alpha Health")).length).toBeGreaterThan(0)
    expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument()
  })
})
