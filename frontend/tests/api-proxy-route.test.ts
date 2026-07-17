import type { NextRequest } from "next/server"

import { GET, POST } from "../app/api/[...path]/route"

function request(
  method: "GET" | "POST",
  headers: Record<string, string> = {},
): NextRequest {
  return {
    arrayBuffer: async () => new TextEncoder().encode('{"ok":true}').buffer,
    headers: new Headers(headers),
    method,
    nextUrl: new URL("https://sha.example.test/api/endpoints?status=active"),
  } as unknown as NextRequest
}

describe("frontend API proxy authorization boundary", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response('{"items":[]}', {
        headers: { "Content-Type": "application/json" },
        status: 200,
      })),
    )
  })

  it("does not grant operator authority to an unauthenticated request", async () => {
    await GET(request("GET"), {
      params: Promise.resolve({ path: ["endpoints"] }),
    })

    const [, init] = vi.mocked(fetch).mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(headers.has("authorization")).toBe(false)
    expect(headers.has("x-sha-api-token")).toBe(false)
  })

  it("forwards caller authorization without following credential-bearing redirects", async () => {
    await POST(request("POST", { Authorization: "Bearer caller-token" }), {
      params: Promise.resolve({ path: ["response-actions"] }),
    })

    const [target, init] = vi.mocked(fetch).mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(String(target)).toBe("http://127.0.0.1:8010/api/response-actions?status=active")
    expect(headers.get("authorization")).toBe("Bearer caller-token")
    expect(init?.redirect).toBe("manual")
  })

  it("strips caller-supplied external-auth trust headers", async () => {
    await GET(
      request("GET", {
        "X-SHA-External-Auth": "forged-proxy-secret",
        "X-SHA-External-Role": "operator",
        "X-SHA-External-User": "mallory@example.test",
      }),
      { params: Promise.resolve({ path: ["endpoints"] }) },
    )

    const [, init] = vi.mocked(fetch).mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(headers.has("x-sha-external-auth")).toBe(false)
    expect(headers.has("x-sha-external-role")).toBe(false)
    expect(headers.has("x-sha-external-user")).toBe(false)
  })
})
