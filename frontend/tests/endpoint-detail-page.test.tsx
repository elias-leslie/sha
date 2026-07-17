import { act, fireEvent, render, screen, waitFor } from "@testing-library/react"

import EndpointDetailPage from "../app/endpoints/[endpointId]/page"
import EndpointDetailConsole from "../components/endpoint-detail-console"
import {
  declaresActionCapability,
  getFixtureControlRegistry,
  responseActionStatusDisplay,
  responseActionStatusTone,
  type EndpointDetail,
} from "../lib/api"

const liveEndpoint: EndpointDetail = {
  endpoint_id: "ep_live_windows_01",
  hostname: "cf-test-win",
  platform: "windows",
  platform_version: "Windows 11 24H2",
  agent_version: "1.0.7",
  tenant_id: "tenant-a",
  site_id: "site-a",
  status: "active",
  connectivity_status: "degraded",
  last_seen_at: "2026-04-21T16:58:00Z",
  last_heartbeat_at: "2026-04-21T16:58:00Z",
  created_at: "2026-04-21T16:00:00Z",
  updated_at: "2026-04-21T16:58:00Z",
  last_platform_profile: "windows-workstation",
  declared_capabilities: ["enroll", "heartbeat"],
  execution_hooks: {
    captures_rollback_artifacts: true,
    reports_execution_results: true,
    supports_dry_run: false,
  },
  latest_posture_summary: null,
  latest_results: [],
}

function liveFetch(endpoint = liveEndpoint) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith(`/api/endpoints/${endpoint.endpoint_id}`)) {
      return { ok: true, json: async () => endpoint } as Response
    }
    if (url.endsWith("/api/control-registry")) {
      return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
    }
    if (url.endsWith("/api/approval-grants") || url.includes("/response-actions")) {
      return { ok: true, json: async () => ({ items: [] }) } as Response
    }
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
  })
}

describe("SHA endpoint detail route", () => {
  it("checks generic and per-control action capabilities", () => {
    expect(declaresActionCapability(["apply_control"], "apply_control", "control.windows.any")).toBe(true)
    expect(
      declaresActionCapability(
        ["rollback_control:control.windows.firewall-all-profiles"],
        "rollback_control",
        "control.windows.firewall-all-profiles",
      ),
    ).toBe(true)
    expect(
      declaresActionCapability(
        ["rollback_control:control.windows.firewall-all-profiles"],
        "rollback_control",
        "control.windows.defender-real-time-protection",
      ),
    ).toBe(false)
  })

  it("renders a claimed response action as in progress", () => {
    expect(responseActionStatusDisplay("leased")).toBe("In progress")
    expect(responseActionStatusTone("leased")).toBe("info")
  })

  it("hydrates valid live endpoints absent from static fixtures", async () => {
    vi.stubGlobal("fetch", liveFetch())

    render(<EndpointDetailPage params={{ endpointId: liveEndpoint.endpoint_id }} />)

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: /endpoint cf-test-win/i })).toBeInTheDocument()
      expect(screen.getByRole("heading", { level: 2, name: /endpoint cf-test-win/i })).toBeInTheDocument()
      expect(screen.getByLabelText(/agent version/i)).toHaveValue("1.0.7")
    })
    expect(screen.getByLabelText(/platform version/i)).toHaveValue("Windows 11 24H2")
    expect(screen.getAllByLabelText(/platform profile/i)[0]).toHaveValue("windows-workstation")
    expect(screen.getByLabelText(/connectivity/i)).toHaveValue("degraded")
  })

  it("mounts no endpoint mutation surfaces while identity is delayed", async () => {
    const resolvers: Array<(response: Response) => void> = []
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith(`/api/endpoints/${liveEndpoint.endpoint_id}`)) {
          return new Promise<Response>((resolve) => resolvers.push(resolve))
        }
        return Promise.resolve({ ok: true, json: async () => ({ items: [] }) } as Response)
      }),
    )

    render(<EndpointDetailPage params={{ endpointId: liveEndpoint.endpoint_id }} />)

    expect(screen.getByText(/waiting for live endpoint identity/i)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /send heartbeat/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /record posture snapshot/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /queue response action/i })).not.toBeInTheDocument()

    await act(async () => {
      for (const resolve of resolvers) {
        resolve({ ok: true, json: async () => liveEndpoint } as Response)
      }
    })

    expect(await screen.findByRole("button", { name: /send heartbeat/i })).toBeInTheDocument()
  })

  it.each([
    [401, "operator token required"],
    [404, "endpoint not found"],
    [500, "endpoint service failed"],
  ])("shows %s endpoint read failures and mounts no mutation forms", async (status, detail) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status, json: async () => ({ detail }) }) as Response),
    )

    render(<EndpointDetailPage params={{ endpointId: "ep_unknown" }} />)

    expect(await screen.findByText(new RegExp(detail, "i"))).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 1, name: /endpoint unavailable/i })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /send heartbeat/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /record posture snapshot/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /queue response action/i })).not.toBeInTheDocument()
  })

  it("does not substitute a matching fixture endpoint after a live 404", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 404, json: async () => ({ detail: "live endpoint missing" }) }) as Response),
    )

    render(<EndpointDetailPage params={{ endpointId: "ep_demo_linux_01" }} />)

    expect(await screen.findByText(/live endpoint missing/i)).toBeInTheDocument()
    expect(screen.queryByText(/demo-linux-01/i)).not.toBeInTheDocument()
  })

  it("keeps demo endpoint views useful without mounting mutation surfaces", () => {
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    const { unmount } = render(<EndpointDetailConsole demoMode endpointId="ep_demo_linux_01" />)

    expect(screen.getByRole("heading", { name: /endpoint demo-linux-01/i })).toBeInTheDocument()
    expect(screen.getByText(/fixture-only endpoint preview/i)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /send heartbeat/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /record posture snapshot/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /queue response action/i })).not.toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()

    unmount()
    render(<EndpointDetailConsole demoMode endpointId="ep_unknown_demo" />)
    expect(screen.getByText(/demo endpoint ep_unknown_demo was not found/i)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /send heartbeat/i })).not.toBeInTheDocument()
  })

  it("retains action history when approval grants fail", async () => {
    const capableEndpoint = { ...liveEndpoint, declared_capabilities: ["collect_security_context"] }
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith(`/api/endpoints/${liveEndpoint.endpoint_id}`)) {
          return { ok: true, json: async () => capableEndpoint } as Response
        }
        if (url.endsWith("/api/approval-grants")) {
          return { ok: false, status: 503, json: async () => ({ detail: "grant read failed" }) } as Response
        }
        if (url.includes("/response-actions")) {
          return {
            ok: true,
            json: async () => ({
              items: [
                {
                  response_action_id: "act-retained",
                  endpoint_id: liveEndpoint.endpoint_id,
                  approval_grant_id: "grant-old",
                  action: "collect_security_context",
                  control_id: null,
                  troubleshooting_scope: "process_inventory",
                  idempotency_key: "retained-action",
                  requested_by: "operator",
                  reason: "Retained action history",
                  status: "succeeded",
                  lease_expires_at: "2026-04-21T16:02:00Z",
                  leased_at: "2026-04-21T16:00:00Z",
                  attempt_count: 1,
                  result_summary: "complete",
                  created_at: "2026-04-21T16:00:00Z",
                  updated_at: "2026-04-21T16:01:00Z",
                  completed_at: "2026-04-21T16:01:00Z",
                },
              ],
            }),
          } as Response
        }
        return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
      }),
    )

    render(<EndpointDetailConsole endpointId={liveEndpoint.endpoint_id} />)

    expect(await screen.findByText(/retained action history/i)).toBeInTheDocument()
    expect(screen.getByRole("alert")).toHaveTextContent(/grant read failed/i)
    expect(screen.getByRole("button", { name: /queue response action/i })).toBeDisabled()
  })

  it("refreshes only endpoint identity after heartbeat writes", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith(`/api/endpoints/${liveEndpoint.endpoint_id}/heartbeat`) && init?.method === "POST") {
        return { ok: true, json: async () => ({ accepted: true }) } as Response
      }
      if (url.endsWith(`/api/endpoints/${liveEndpoint.endpoint_id}`)) {
        return { ok: true, json: async () => liveEndpoint } as Response
      }
      if (url.endsWith("/api/approval-grants") || url.includes("/response-actions")) {
        return { ok: false, status: 503, json: async () => ({ detail: "related unavailable" }) } as Response
      }
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<EndpointDetailConsole endpointId={liveEndpoint.endpoint_id} />)
    fireEvent.click(await screen.findByRole("button", { name: /send heartbeat/i }))

    expect(await screen.findByText(/heartbeat accepted/i)).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/api/approval-grants"))).toHaveLength(1)
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes("/response-actions"))).toHaveLength(1)
  })

  it("adds a unique idempotency key when queueing a response action", async () => {
    const endpoint = { ...liveEndpoint, declared_capabilities: ["collect_security_context"] }
    const grant = {
      approval_grant_id: "grant-response-action",
      approval_request_id: null,
      endpoint_ids: [endpoint.endpoint_id],
      allowed_actions: ["collect_security_context"],
      control_ids: [],
      troubleshooting_scopes: ["process_inventory"],
      requested_by: "operator",
      approved_by: "security",
      reason: "Approved response",
      expires_at: "2099-01-01T00:00:00Z",
      status: "approved",
      created_at: "2026-04-21T16:00:00Z",
      updated_at: "2026-04-21T16:00:00Z",
    }
    let createBody: Record<string, unknown> | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith(`/api/endpoints/${endpoint.endpoint_id}`)) {
        return { ok: true, json: async () => endpoint } as Response
      }
      if (url.endsWith("/api/approval-grants")) {
        return { ok: true, json: async () => ({ items: [grant] }) } as Response
      }
      if (url.endsWith(`/api/endpoints/${endpoint.endpoint_id}/response-actions`)) {
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }
      if (url.endsWith("/api/response-actions") && init?.method === "POST") {
        createBody = JSON.parse(String(init.body)) as Record<string, unknown>
        return {
          ok: true,
          json: async () => ({
            response_action_id: "act-created",
            ...createBody,
            requested_by: "operator:authenticated",
            status: "queued",
            lease_expires_at: null,
            leased_at: null,
            attempt_count: 0,
            result_summary: null,
            created_at: "2026-04-21T16:01:00Z",
            updated_at: "2026-04-21T16:01:00Z",
            completed_at: null,
          }),
        } as Response
      }
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<EndpointDetailConsole endpointId={endpoint.endpoint_id} />)

    const queueButton = await screen.findByRole("button", { name: /queue response action/i })
    await waitFor(() => expect(queueButton).toBeEnabled())
    expect(screen.queryByLabelText(/^requested by$/i)).not.toBeInTheDocument()
    expect(screen.getByText(/action attribution comes from the authenticated API principal/i)).toBeInTheDocument()
    fireEvent.click(queueButton)

    expect(await screen.findByText(/queued response action act-created/i)).toBeInTheDocument()
    expect(createBody).toMatchObject({
      endpoint_id: endpoint.endpoint_id,
      approval_grant_id: grant.approval_grant_id,
      action: "collect_security_context",
      idempotency_key: expect.stringMatching(/^[0-9a-f-]{36}$/i),
    })
    expect(createBody).not.toHaveProperty("requested_by")
  })

  it("filters declared actions and controls, then invalidates an expired grant", async () => {
    vi.useFakeTimers()
    const endpoint = {
      ...liveEndpoint,
      declared_capabilities: [
        "collect_security_context",
        "apply_control:control.windows.firewall-all-profiles",
      ],
    }
    const grant = {
      approval_grant_id: "grant-short",
      approval_request_id: null,
      endpoint_ids: [liveEndpoint.endpoint_id],
      allowed_actions: ["collect_security_context"],
      control_ids: [],
      troubleshooting_scopes: ["process_inventory"],
      requested_by: "operator",
      approved_by: "security",
      reason: "Short window",
      expires_at: new Date(Date.now() + 1_000).toISOString(),
      status: "approved",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith(`/api/endpoints/${liveEndpoint.endpoint_id}`)) {
          return { ok: true, json: async () => endpoint } as Response
        }
        if (url.endsWith("/api/approval-grants")) {
          return { ok: true, json: async () => ({ items: [grant] }) } as Response
        }
        if (url.endsWith("/api/control-registry")) {
          return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
        }
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }),
    )

    render(<EndpointDetailConsole endpointId={liveEndpoint.endpoint_id} />)
    await act(async () => {})

    const actionSelect = screen.getByLabelText(/^action$/i)
    expect(actionSelect).toHaveTextContent(/collect security context/i)
    expect(actionSelect).toHaveTextContent(/apply control/i)
    expect(actionSelect).not.toHaveTextContent(/rollback control/i)
    fireEvent.change(actionSelect, { target: { value: "apply_control" } })
    expect(screen.getByLabelText(/control id/i)).toHaveTextContent(/windows firewall all profiles/i)
    expect(screen.getByLabelText(/control id/i)).not.toHaveTextContent(/defender/i)

    fireEvent.change(actionSelect, { target: { value: "collect_security_context" } })
    expect(screen.getByRole("button", { name: /queue response action/i })).toBeEnabled()
    await act(async () => vi.advanceTimersByTime(1_001))
    expect(screen.getByRole("button", { name: /queue response action/i })).toBeDisabled()
    vi.useRealTimers()
  })
})
