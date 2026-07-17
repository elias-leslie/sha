import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import AuthSessionStatus from "../components/auth-session-status"

function json(body: unknown, status = 200, headers?: HeadersInit) {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", ...Object.fromEntries(new Headers(headers)) },
    status,
  })
}

const oidcSession = {
  subject: "alice-subject",
  display_name: "Alice Operator",
  status: "active",
  authentication_method: "oidc_session",
  bindings: [
    {
      binding_id: "urb_global",
      role: "Viewer",
      scope_type: "global",
      client_id: null,
      location_id: null,
      permissions: ["endpoint.read"],
    },
    {
      binding_id: "urb_client",
      role: "ClientOperator",
      scope_type: "client",
      client_id: "cl_alpha",
      location_id: null,
      permissions: ["response_action.create"],
    },
    {
      binding_id: "urb_location",
      role: "IncidentResponder",
      scope_type: "location",
      client_id: "cl_alpha",
      location_id: "loc_main",
      permissions: ["response_action.create"],
    },
  ],
  csrf_token: "csrf-browser-session",
}

describe("operator authentication status", () => {
  it("shows sign-in state and preserves only the current local return path", async () => {
    window.history.replaceState({}, "", "/fleet?client_id=cl_alpha&location_id=loc_main")
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "authentication required" }, 401)))

    render(<AuthSessionStatus demoMode={false} scope={{ client_id: "cl_alpha", location_id: "loc_main" }} />)

    const signIn = await screen.findByRole("link", { name: "Sign in" })
    expect(screen.getByText(/live data and actions require an operator identity/i)).toBeInTheDocument()
    expect(signIn).toHaveAttribute(
      "href",
      "/api/auth/oidc/login?return_to=%2Ffleet%3Fclient_id%3Dcl_alpha%26location_id%3Dloc_main",
    )
  })

  it("shows current identity and only roles effective in the selected viewpoint", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(oidcSession)))

    render(<AuthSessionStatus demoMode={false} scope={{ client_id: "cl_alpha", location_id: "loc_main" }} />)

    expect(await screen.findByText("Alice Operator")).toBeInTheDocument()
    expect(screen.getByText(/Viewer · global/i)).toBeInTheDocument()
    expect(screen.getByText(/ClientOperator · client cl_alpha/i)).toBeInTheDocument()
    expect(screen.getByText(/IncidentResponder · location loc_main/i)).toBeInTheDocument()
    expect(screen.getByText(/alice-subject · oidc session/i)).toBeInTheDocument()
  })

  it("makes pending users explicitly zero-authority", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json({ ...oidcSession, status: "pending", bindings: [] })),
    )

    render(<AuthSessionStatus demoMode={false} scope={{ client_id: null, location_id: null }} />)

    expect(await screen.findByText(/pending identity · zero authority/i)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Sign out all" })).toBeInTheDocument()
  })

  it("signs out one or all sessions with CSRF and never writes tokens to browser storage", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem")
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(input)
      if (path === "/api/auth/session") {
        return json(oidcSession)
      }
      if (path === "/api/auth/logout" || path === "/api/auth/logout-all") {
        return json({ status: "logged_out" })
      }
      return json({ detail: "not found" }, 404)
    })
    vi.stubGlobal("fetch", fetchMock)

    const first = render(<AuthSessionStatus demoMode={false} scope={{ client_id: null, location_id: null }} />)
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }))
    expect(await screen.findByRole("link", { name: "Sign in" })).toBeInTheDocument()

    const logoutCall = fetchMock.mock.calls.find(([input]) => String(input) === "/api/auth/logout")
    expect(logoutCall?.[1]?.credentials).toBe("same-origin")
    expect(new Headers(logoutCall?.[1]?.headers).get("x-sha-csrf")).toBe(oidcSession.csrf_token)

    first.unmount()
    const second = render(<AuthSessionStatus demoMode={false} scope={{ client_id: null, location_id: null }} />)
    fireEvent.click(await screen.findByRole("button", { name: "Sign out all" }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input) === "/api/auth/logout-all")).toBe(true))
    const logoutAllCall = fetchMock.mock.calls.find(([input]) => String(input) === "/api/auth/logout-all")
    expect(new Headers(logoutAllCall?.[1]?.headers).get("x-sha-csrf")).toBe(oidcSession.csrf_token)
    expect(setItem).not.toHaveBeenCalled()
    second.unmount()
  })

  it("renders authorization denial separately from the sign-in state", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "identity has no applicable role" }, 403)))

    render(<AuthSessionStatus demoMode={false} scope={{ client_id: null, location_id: null }} />)

    expect(await screen.findByText("Access denied")).toBeInTheDocument()
    expect(screen.getByText(/current identity and scope/i)).toBeInTheDocument()
    expect(screen.queryByText(/not signed in/i)).not.toBeInTheDocument()
  })
})
