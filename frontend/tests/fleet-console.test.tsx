import { act, fireEvent, render, screen, waitFor } from "@testing-library/react"

import FleetPage from "../app/fleet/page"
import { getFixtureClients, getFixtureEndpoints } from "../lib/api"

describe("SHA fleet control plane", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/")
  })

  it("shows loading without fixtures until live inventory resolves", async () => {
    let resolveInventory: ((response: Response) => void) | undefined
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path === "/api/clients") {
        return Promise.resolve({ ok: true, json: async () => ({ items: getFixtureClients() }) } as Response)
      }
      if (path === "/api/endpoints") {
        return new Promise<Response>((resolve) => {
          resolveInventory = resolve
        })
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })
    vi.stubGlobal(
      "fetch",
      fetchMock,
    )

    render(<FleetPage />)

    expect(screen.getByText(/loading live endpoint inventory/i)).toBeInTheDocument()
    expect(screen.queryByText("demo-linux-01")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /waiting for live inventory/i })).toBeDisabled()

    await waitFor(() => expect(resolveInventory).toBeDefined())
    await act(async () => {
      resolveInventory?.({ ok: true, json: async () => ({ items: getFixtureEndpoints() }) } as Response)
    })

    const search = await screen.findByLabelText(/search endpoints/i)
    fireEvent.change(search, { target: { value: "demo-linux-01" } })
    expect(await screen.findByRole("link", { name: /open endpoint demo-linux-01/i })).toHaveAttribute(
      "href",
      "/endpoints/ep_demo_linux_01",
    )
    expect(screen.queryByText("demo-windows-01")).not.toBeInTheDocument()
  })

  it("shows authentication failure without fixture fallback", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input) === "/api/clients") {
          return { ok: true, json: async () => ({ items: getFixtureClients() }) } as Response
        }
        return { ok: false, status: 401, json: async () => ({ detail: "operator token required" }) } as Response
      }),
    )

    render(<FleetPage />)

    expect(await screen.findByRole("alert")).toHaveTextContent(/operator token required/i)
    expect(screen.queryByText("demo-linux-01")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /waiting for live inventory/i })).toBeDisabled()
  })

  it("loads URL-scoped inventory and preserves scope across fleet routes", async () => {
    window.history.replaceState({}, "", "/fleet?client_id=cl_acme&location_id=loc_hq")
    const client = {
      client_id: "cl_acme",
      key: "acme",
      name: "Acme Corp",
      state: "active",
      is_system: false,
      created_at: "2026-07-17T12:00:00Z",
      updated_at: "2026-07-17T12:00:00Z",
    }
    const location = {
      location_id: "loc_hq",
      client_id: client.client_id,
      key: "hq",
      name: "HQ",
      state: "active",
      is_system: false,
      created_at: "2026-07-17T12:00:00Z",
      updated_at: "2026-07-17T12:00:00Z",
    }
    const endpoint = {
      ...getFixtureEndpoints()[0],
      endpoint_id: "ep_acme_linux_01",
      hostname: "acme-linux-01",
      client_id: client.client_id,
      location_id: location.location_id,
    }
    const scopedEndpointPath = "/api/endpoints?client_id=cl_acme&location_id=loc_hq"
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === "/api/clients") {
        return { ok: true, json: async () => ({ items: [client] }) } as Response
      }
      if (path === "/api/clients/cl_acme/locations") {
        return { ok: true, json: async () => ({ items: [location] }) } as Response
      }
      if (path === scopedEndpointPath) {
        return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
      }
      if (path === "/api/endpoints/enroll" && init?.method === "POST") {
        return { ok: true, json: async () => endpoint } as Response
      }
      if (path === "/api/endpoints?client_id=cl_acme") {
        return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
      }
      if (path === "/api/endpoints") {
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }
      throw new Error(`Unexpected request: ${path}`)
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<FleetPage />)

    const endpointLink = await screen.findByRole("link", { name: /open endpoint acme-linux-01/i })
    expect(fetchMock.mock.calls.some(([input]) => String(input) === scopedEndpointPath)).toBe(true)
    expect(fetchMock.mock.calls.some(([input]) => String(input) === "/api/endpoints")).toBe(false)
    expect(screen.getByLabelText(/client scope/i)).toHaveValue(client.client_id)
    expect(screen.getByLabelText(/location scope/i)).toHaveValue(location.location_id)
    expect(screen.getByText("Acme Corp / HQ")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute(
      "href",
      "/fleet?client_id=cl_acme&location_id=loc_hq",
    )
    expect(screen.getByRole("link", { name: "Clients" })).toHaveAttribute(
      "href",
      "/clients?client_id=cl_acme&location_id=loc_hq",
    )
    expect(endpointLink).toHaveAttribute(
      "href",
      "/endpoints/ep_acme_linux_01?client_id=cl_acme&location_id=loc_hq",
    )
    expect(screen.getByLabelText(/bound client alias/i)).toHaveValue("acme")
    expect(screen.getByLabelText(/bound location alias/i)).toHaveValue("hq")
    const enrollButton = screen.getByRole("button", { name: /^enroll endpoint$/i })
    expect(enrollButton).toBeEnabled()
    fireEvent.click(enrollButton)
    expect(await screen.findByText(/endpoint acme-linux-01 enrolled/i)).toBeInTheDocument()
    const enrollmentCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input) === "/api/endpoints/enroll" && init?.method === "POST",
    )
    expect(JSON.parse(String(enrollmentCall?.[1]?.body))).toMatchObject({
      tenant_id: "acme",
      site_id: "hq",
    })

    fireEvent.change(screen.getByLabelText(/location scope/i), { target: { value: "" } })
    expect(window.location.search).toBe("?client_id=cl_acme")
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute(
      "href",
      "/fleet?client_id=cl_acme",
    )

    fireEvent.change(screen.getByLabelText(/client scope/i), { target: { value: "" } })
    expect(window.location.search).toBe("")
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute("href", "/fleet")
  })

  it("disables compatibility enrollment for migration-quarantine locations", async () => {
    window.history.replaceState(
      {},
      "",
      "/fleet?client_id=cl_alpha&location_id=loc_unassigned",
    )
    const client = {
      client_id: "cl_alpha",
      key: "tenant-alpha",
      name: "Alpha",
      state: "active",
      is_system: false,
      created_at: "2026-07-17T12:00:00Z",
      updated_at: "2026-07-17T12:00:00Z",
    }
    const location = {
      location_id: "loc_unassigned",
      client_id: client.client_id,
      key: null,
      name: "Unassigned",
      state: "migration_quarantine",
      is_system: true,
      created_at: "2026-07-17T12:00:00Z",
      updated_at: "2026-07-17T12:00:00Z",
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(input)
      if (path === "/api/clients") {
        return { ok: true, json: async () => ({ items: [client] }) } as Response
      }
      if (path === "/api/clients/cl_alpha/locations") {
        return { ok: true, json: async () => ({ items: [location] }) } as Response
      }
      if (path === "/api/endpoints?client_id=cl_alpha&location_id=loc_unassigned") {
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }
      throw new Error(`Unexpected request: ${path}`)
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<FleetPage />)

    expect(await screen.findByText("Alpha / Unassigned")).toBeInTheDocument()
    expect(screen.getByText(/^migration quarantine$/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/bound client alias/i)).toHaveValue("")
    expect(screen.getByLabelText(/bound location alias/i)).toHaveValue("")
    expect(
      await screen.findByRole("button", { name: /select an active client and location/i }),
    ).toBeDisabled()
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false)
  })
})
