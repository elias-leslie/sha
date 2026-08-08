import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import FleetPage from "../app/fleet/page"
import { clearAuthSessionCache, getFixtureEndpoints } from "../lib/api"

describe("fleet metadata console", () => {
  beforeEach(() => {
    clearAuthSessionCache()
    window.history.replaceState({}, "", "/fleet?client_id=cl_a&location_id=loc_a")
  })

  it("shows scoped tags and views, previews a group, and emits scoped mutations", async () => {
    const endpoint = {
      ...getFixtureEndpoints()[0],
      endpoint_id: "ep_a",
      hostname: "host-a",
      client_id: "cl_a",
      location_id: "loc_a",
    }
    const tag = {
      tag_id: "tag_a",
      name: "IR priority",
      description: null,
      scope_type: "location",
      client_id: "cl_a",
      location_id: "loc_a",
      created_by: "user:operator",
      created_at: "2026-07-17T12:00:00Z",
      updated_at: "2026-07-17T12:00:00Z",
    }
    const savedView = {
      saved_view_id: "view_a",
      name: "Linux targets",
      description: null,
      visibility: "shared",
      scope_type: "location",
      client_id: "cl_a",
      location_id: "loc_a",
      owner_user_id: "usr_operator",
      owner_actor: "user:operator",
      current_version: 1,
      current_filter: {
        schema_version: 1,
        match: "all",
        rules: [{ field: "platform", op: "eq", value: "linux" }],
      },
      content_hash: "a".repeat(64),
      created_at: "2026-07-17T12:00:00Z",
      updated_at: "2026-07-17T12:00:00Z",
    }
    const group = {
      dynamic_group_id: "grp_a",
      name: "Linux response group",
      description: null,
      scope_type: "location",
      client_id: "cl_a",
      location_id: "loc_a",
      saved_view_id: "view_a",
      saved_view_version: 1,
      filter_hash: "a".repeat(64),
      owner_user_id: "usr_operator",
      owner_actor: "user:operator",
      created_at: "2026-07-17T12:00:00Z",
      updated_at: "2026-07-17T12:00:00Z",
    }
    const calls: Array<{ path: string; init?: RequestInit }> = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      calls.push({ path, init })
      if (path === "/api/auth/session") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            subject: "user:operator",
            display_name: "Operator",
            status: "active",
            authentication_method: "oidc_session",
            bindings: [],
            csrf_token: "csrf-value",
          }),
        } as Response
      }
      if (path === "/api/clients") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [{
              client_id: "cl_a",
              key: "tenant-a",
              name: "Tenant A",
              state: "active",
              is_system: false,
              created_at: "2026-07-17T12:00:00Z",
              updated_at: "2026-07-17T12:00:00Z",
            }],
          }),
        } as Response
      }
      if (path === "/api/clients/cl_a/locations") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [{
              location_id: "loc_a",
              client_id: "cl_a",
              key: "site-a",
              name: "Site A",
              state: "active",
              is_system: false,
              created_at: "2026-07-17T12:00:00Z",
              updated_at: "2026-07-17T12:00:00Z",
            }],
          }),
        } as Response
      }
      if (path.startsWith("/api/endpoints")) {
        return { ok: true, status: 200, json: async () => ({ items: [endpoint] }) } as Response
      }
      if (path === "/api/tags?client_id=cl_a&location_id=loc_a") {
        return { ok: true, status: 200, json: async () => ({ items: [tag] }) } as Response
      }
      if (path === "/api/saved-views?client_id=cl_a&location_id=loc_a") {
        return { ok: true, status: 200, json: async () => ({ items: [savedView] }) } as Response
      }
      if (path === "/api/dynamic-groups?client_id=cl_a&location_id=loc_a") {
        return { ok: true, status: 200, json: async () => ({ items: [group] }) } as Response
      }
      if (path === "/api/endpoints/ep_a/tags" && (!init?.method || init.method === "GET")) {
        return { ok: true, status: 200, json: async () => ({ items: [] }) } as Response
      }
      if (path === "/api/dynamic-groups/grp_a/preview?limit=100") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            dynamic_group_id: "grp_a",
            saved_view_id: "view_a",
            saved_view_version: 1,
            filter_hash: "a".repeat(64),
            evaluated_endpoint_count: 1,
            matched_endpoint_count: 1,
            result_limit: 100,
            truncated: false,
            items: [{
              endpoint_id: "ep_a",
              hostname: "host-a",
              platform: "linux",
              status: "active",
              connectivity_status: "online",
              client_id: "cl_a",
              location_id: "loc_a",
            }],
          }),
        } as Response
      }
      if (path === "/api/tags" && init?.method === "POST") {
        const payload = JSON.parse(String(init.body))
        return {
          ok: true,
          status: 201,
          json: async () => ({ ...tag, tag_id: "tag_new", name: payload.name }),
        } as Response
      }
      throw new Error(`Unexpected request: ${path} ${init?.method ?? "GET"}`)
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<FleetPage />)

    expect(await screen.findByText("Linux response group")).toBeInTheDocument()
    expect(screen.getAllByText("Linux targets").length).toBeGreaterThan(0)
    expect(screen.getByText("Creation scope: Location loc_a")).toBeInTheDocument()

    fireEvent.click(screen.getByRole("button", { name: "Preview Linux response group" }))
    expect(await screen.findByText(/1 matched of 1 authorized endpoints/i)).toBeInTheDocument()
    expect(screen.getAllByText("host-a").length).toBeGreaterThan(0)

    fireEvent.change(screen.getByLabelText("New tag name"), { target: { value: "Forensics" } })
    fireEvent.click(screen.getByRole("button", { name: "Create tag" }))
    expect(await screen.findByText(/tag Forensics created at Location loc_a scope/i)).toBeInTheDocument()
    const createCall = calls.find(({ path, init }) => path === "/api/tags" && init?.method === "POST")
    expect(JSON.parse(String(createCall?.init?.body))).toEqual({
      scope_type: "location",
      client_id: "cl_a",
      location_id: "loc_a",
      name: "Forensics",
    })
    await waitFor(() => expect(createCall?.init?.headers).toMatchObject({ "x-sha-csrf": "csrf-value" }))
  })
})
