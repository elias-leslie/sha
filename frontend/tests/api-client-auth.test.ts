import {
  fetchJson,
  fetchText,
  getAuthSession,
  safeReturnPath,
} from "../lib/api"

const activeSession = {
  subject: "https://id.example.test|alice",
  display_name: "Alice Operator",
  status: "active",
  authentication_method: "oidc_session",
  bindings: [
    {
      binding_id: "urb_global_admin",
      role: "GlobalAdmin",
      scope_type: "global",
      client_id: null,
      location_id: null,
      permissions: ["hierarchy.manage"],
    },
  ],
  csrf_token: "csrf-session-bound-value",
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json" },
    status,
  })
}

describe("same-origin API client authentication boundary", () => {
  it("loads a fresh session once and attaches its CSRF value to every mutation method", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
      String(input) === "/api/auth/session" ? json(activeSession) : json({ ok: true }),
    )
    vi.stubGlobal("fetch", fetchMock)

    await getAuthSession({ refresh: true })
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      await fetchJson<{ ok: boolean }>(`/api/mutations/${method.toLowerCase()}`, {
        body: JSON.stringify({ method }),
        headers: { "X-SHA-CSRF": "caller-forged-value" },
        method,
      })
    }
    await fetchText("/api/mutations/text", { method: "POST" })

    const mutationCalls = fetchMock.mock.calls.filter(
      ([input]) => String(input).startsWith("/api/mutations/"),
    )
    expect(mutationCalls).toHaveLength(6)
    for (const [, init] of mutationCalls) {
      expect(init?.credentials).toBe("same-origin")
      const headers = new Headers(init?.headers)
      expect(headers.get("x-sha-csrf")).toBe(activeSession.csrf_token)
      expect(headers.has("authorization")).toBe(false)
      expect(headers.has("x-sha-api-token")).toBe(false)
    }
    expect(fetchMock.mock.calls.filter(([input]) => String(input) === "/api/auth/session")).toHaveLength(1)
  })

  it("includes cookies but never sends the CSRF header on reads", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
      String(input) === "/api/auth/session" ? json(activeSession) : json({ value: "ok" }),
    )
    vi.stubGlobal("fetch", fetchMock)
    await getAuthSession({ refresh: true })

    await fetchJson<{ value: string }>("/api/read")
    await fetchText("/api/read-text")

    for (const [input, init] of fetchMock.mock.calls.filter(
      ([input]) => String(input) === "/api/read" || String(input) === "/api/read-text",
    )) {
      expect(String(input)).toMatch(/^\/api\/read/)
      expect(init?.credentials).toBe("same-origin")
      expect(new Headers(init?.headers).has("x-sha-csrf")).toBe(false)
    }
  })

  it("refuses external or malformed targets before session data can be attached", async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    await expect(fetchJson("https://evil.example.test/collect", { method: "POST" })).rejects.toThrow(
      "same-origin /api path",
    )
    await expect(fetchJson("//evil.example.test/collect", { method: "POST" })).rejects.toThrow(
      "same-origin /api path",
    )
    await expect(fetchJson("/api\\evil", { method: "POST" })).rejects.toThrow("same-origin /api path")
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("makes authentication and authorization failures distinct", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ detail: "authentication required" }, 401))
      .mockResolvedValueOnce(json({ detail: "scope does not grant this action" }, 403))
    vi.stubGlobal("fetch", fetchMock)

    await expect(fetchJson("/api/private")).rejects.toMatchObject({
      status: 401,
      message: expect.stringMatching(/authentication required.*sign in/i),
    })
    await expect(fetchJson("/api/forbidden")).rejects.toMatchObject({
      status: 403,
      message: expect.stringMatching(/access denied.*current identity and scope/i),
    })
  })

  it("accepts only same-origin return paths", () => {
    expect(safeReturnPath("/fleet?client_id=cl_alpha#watch")).toBe("/fleet?client_id=cl_alpha#watch")
    expect(safeReturnPath("https://evil.example.test/steal")).toBe("/")
    expect(safeReturnPath("//evil.example.test/steal")).toBe("/")
    expect(safeReturnPath("/\\evil.example.test/steal")).toBe("/")
  })
})
