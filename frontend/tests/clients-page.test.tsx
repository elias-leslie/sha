import { fireEvent, render, screen, waitFor } from "@testing-library/react"

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
    {
      client_id: "cl_archived",
      key: "tenant-archived",
      name: "Archived Health",
      state: "archived",
      is_system: false,
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
    [
      QUARANTINE_CLIENT_ID,
      [
        {
          location_id: QUARANTINE_LOCATION_ID,
          client_id: QUARANTINE_CLIENT_ID,
          key: null,
          name: "Unassigned",
          state: "migration_quarantine",
          is_system: true,
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
    if (url === "/api/clients" && method === "POST") {
      const payload = JSON.parse(String(init?.body)) as { key: string; name: string }
      const created: Client = {
        client_id: "cl_bravo",
        key: payload.key,
        name: payload.name,
        state: "active",
        is_system: false,
        created_at: now,
        updated_at: now,
      }
      fixtures.clients.push(created)
      fixtures.locations.set(created.client_id, [])
      return { ok: true, json: async () => created } as Response
    }

    const locationMatch = url.match(/^\/api\/clients\/([^/]+)\/locations$/)
    if (locationMatch && method === "GET") {
      return {
        ok: true,
        json: async () => ({ items: fixtures.locations.get(locationMatch[1]) ?? [] }),
      } as Response
    }
    if (locationMatch && method === "POST") {
      const clientId = locationMatch[1]
      const payload = JSON.parse(String(init?.body)) as { key: string; name: string }
      const created: Location = {
        location_id: "loc_bravo_soc",
        client_id: clientId,
        key: payload.key,
        name: payload.name,
        state: "active",
        is_system: false,
        created_at: now,
        updated_at: now,
      }
      fixtures.locations.set(clientId, [...(fixtures.locations.get(clientId) ?? []), created])
      return { ok: true, json: async () => created } as Response
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
  it("shows canonical clients, locations, and migration quarantine boundaries", async () => {
    const { fetchMock } = hierarchyFetch()
    vi.stubGlobal("fetch", fetchMock)

    render(<ClientsPage />)

    expect((await screen.findAllByText("Alpha Health")).length).toBeGreaterThan(0)
    expect(await screen.findByText("Main office")).toBeInTheDocument()
    expect(screen.getByText("Legacy scope quarantine")).toBeInTheDocument()
    expect(screen.getAllByText("Migration quarantine").length).toBeGreaterThan(0)
    expect(screen.getByText("Archived Health")).toBeInTheDocument()
    expect(screen.getByText("Archived")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: /Archived Health/i }))
    expect(screen.getByRole("button", { name: /create location/i })).toBeDisabled()
    expect(
      screen.getByText(/locations cannot be created beneath archived/i),
    ).toBeInTheDocument()
  })

  it("creates clients and locations through canonical hierarchy APIs", async () => {
    const { fetchMock, requests } = hierarchyFetch()
    vi.stubGlobal("fetch", fetchMock)

    render(<ClientsPage />)
    await screen.findAllByText("Alpha Health")

    fireEvent.change(screen.getByLabelText("Client key"), { target: { value: "tenant-bravo" } })
    fireEvent.change(screen.getByLabelText("Client name"), { target: { value: "Bravo Legal" } })
    fireEvent.click(screen.getByRole("button", { name: "Create client" }))

    expect(await screen.findByText("Created client Bravo Legal.")).toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText("Parent client")).toHaveValue("cl_bravo"))

    fireEvent.change(screen.getByLabelText("Location key"), { target: { value: "site-soc" } })
    fireEvent.change(screen.getByLabelText("Location name"), { target: { value: "SOC" } })
    fireEvent.click(screen.getByRole("button", { name: "Create location" }))

    expect(await screen.findByText("Created location SOC.")).toBeInTheDocument()
    expect(screen.getAllByText("SOC").length).toBeGreaterThan(0)

    const clientPost = requests.find(
      (request) => request.url === "/api/clients" && request.init?.method === "POST",
    )
    expect(JSON.parse(String(clientPost?.init?.body))).toEqual({
      key: "tenant-bravo",
      name: "Bravo Legal",
    })
    const locationPost = requests.find(
      (request) =>
        request.url === "/api/clients/cl_bravo/locations" && request.init?.method === "POST",
    )
    expect(JSON.parse(String(locationPost?.init?.body))).toEqual({ key: "site-soc", name: "SOC" })
  })

  it("keeps hierarchy management global while retaining URL context in navigation", async () => {
    window.history.replaceState(
      {},
      "",
      `/clients?client_id=${QUARANTINE_CLIENT_ID}&location_id=${QUARANTINE_LOCATION_ID}`,
    )
    const { fetchMock } = hierarchyFetch()
    vi.stubGlobal("fetch", fetchMock)

    render(<ClientsPage />)

    await screen.findAllByText("Legacy scope quarantine")
    expect(screen.queryByRole("region", { name: /scope selector/i })).not.toBeInTheDocument()
    expect(screen.getByRole("region", { name: /scope applicability/i })).toHaveTextContent(
      /global-only view/i,
    )
    await waitFor(() =>
      expect(screen.getByLabelText("Parent client")).toHaveValue(QUARANTINE_CLIENT_ID),
    )
    expect(screen.getAllByText(/migration quarantine/i).length).toBeGreaterThan(0)
  })
})
