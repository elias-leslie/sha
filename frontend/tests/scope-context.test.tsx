import { act, fireEvent, render, screen, waitFor } from "@testing-library/react"

import { ScopeProvider, useScope } from "../components/scope-context"
import ScopeSelector from "../components/scope-selector"
import type { Client, Location } from "../lib/api"

const now = "2026-07-17T12:00:00Z"
const clients: Client[] = [
  {
    client_id: "cl_alpha",
    key: "tenant-alpha",
    name: "Alpha",
    state: "active",
    is_system: false,
    created_at: now,
    updated_at: now,
  },
  {
    client_id: "cl_bravo",
    key: "tenant-bravo",
    name: "Bravo",
    state: "active",
    is_system: false,
    created_at: now,
    updated_at: now,
  },
]
const alphaLocation: Location = {
  location_id: "loc_alpha",
  client_id: "cl_alpha",
  key: "site-alpha",
  name: "Alpha location",
  state: "active",
  is_system: false,
  created_at: now,
  updated_at: now,
}
const bravoLocation: Location = {
  ...alphaLocation,
  location_id: "loc_bravo",
  client_id: "cl_bravo",
  key: "site-bravo",
  name: "Bravo location",
}

function jsonResponse(body: unknown) {
  return { ok: true, json: async () => body } as Response
}

function ScopeProbe() {
  const { locations, ready, scope, setScope } = useScope()
  return (
    <div>
      <span data-testid="scope-state">
        {ready ? "ready" : "pending"}:{scope.client_id ?? "global"}:{scope.location_id ?? "all"}
      </span>
      <span data-testid="location-state">
        {locations.map((location) => location.location_id).join(",")}
      </span>
      <button type="button" onClick={() => setScope({ client_id: "cl_alpha", location_id: null })}>
        Select Alpha
      </button>
      <button type="button" onClick={() => setScope({ client_id: "cl_bravo", location_id: null })}>
        Select Bravo
      </button>
    </div>
  )
}

describe("scope context", () => {
  it("canonicalizes unknown clients and mismatched locations without presenting raw ids", async () => {
    window.history.replaceState(
      {},
      "",
      "/fleet?client_id=cl_alpha&location_id=loc_from_another_client",
    )
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input)
        if (path === "/api/clients") {
          return jsonResponse({ items: clients })
        }
        if (path === "/api/clients/cl_alpha/locations") {
          return jsonResponse({ items: [alphaLocation] })
        }
        throw new Error(`Unexpected request: ${path}`)
      }),
    )

    const { unmount } = render(
      <ScopeProvider demoMode={false}>
        <ScopeSelector />
      </ScopeProvider>,
    )

    expect(await screen.findByText("Alpha / All locations")).toBeInTheDocument()
    expect(window.location.search).toBe("?client_id=cl_alpha")
    expect(screen.queryByText(/loc_from_another_client/i)).not.toBeInTheDocument()
    unmount()

    window.history.replaceState({}, "", "/fleet?client_id=cl_missing&location_id=loc_missing")
    render(
      <ScopeProvider demoMode={false}>
        <ScopeSelector />
      </ScopeProvider>,
    )

    expect(await screen.findByText("Global / All clients")).toBeInTheDocument()
    expect(window.location.search).toBe("")
    expect(screen.queryByText(/cl_missing|loc_missing/i)).not.toBeInTheDocument()
  })

  it("ignores late location results from a previously selected client", async () => {
    let resolveAlpha: ((response: Response) => void) | undefined
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path === "/api/clients") {
        return Promise.resolve(jsonResponse({ items: clients }))
      }
      if (path === "/api/clients/cl_alpha/locations") {
        return new Promise<Response>((resolve) => {
          resolveAlpha = resolve
        })
      }
      if (path === "/api/clients/cl_bravo/locations") {
        return Promise.resolve(jsonResponse({ items: [bravoLocation] }))
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })
    vi.stubGlobal("fetch", fetchMock)

    render(
      <ScopeProvider demoMode={false}>
        <ScopeProbe />
      </ScopeProvider>,
    )

    await waitFor(() => expect(screen.getByTestId("scope-state")).toHaveTextContent("ready:global:all"))
    fireEvent.click(screen.getByRole("button", { name: "Select Alpha" }))
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([input]) => String(input) === "/api/clients/cl_alpha/locations"),
      ).toBe(true),
    )
    fireEvent.click(screen.getByRole("button", { name: "Select Bravo" }))

    await waitFor(() => expect(screen.getByTestId("scope-state")).toHaveTextContent("ready:cl_bravo:all"))
    expect(screen.getByTestId("location-state")).toHaveTextContent("loc_bravo")

    await act(async () => {
      resolveAlpha?.(jsonResponse({ items: [alphaLocation] }))
    })
    expect(screen.getByTestId("location-state")).toHaveTextContent("loc_bravo")
    expect(screen.getByTestId("location-state")).not.toHaveTextContent("loc_alpha")
  })
})
