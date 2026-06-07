import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import EndpointDetailPage from "../app/endpoints/[endpointId]/page"
import EndpointDetailConsole from "../components/endpoint-detail-console"
import type { EndpointDetail } from "../lib/api"

describe("SHA endpoint detail route", () => {
  it("hydrates unknown live endpoints into matching shell and form state", async () => {
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

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith(`/api/endpoints/${liveEndpoint.endpoint_id}`)) {
        return {
          ok: true,
          json: async () => liveEndpoint,
        } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<EndpointDetailPage params={{ endpointId: liveEndpoint.endpoint_id }} />)

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: /endpoint cf-test-win/i })).toBeInTheDocument()
      expect(screen.getByRole("heading", { level: 2, name: /endpoint cf-test-win/i })).toBeInTheDocument()
      expect(screen.getByLabelText(/agent version/i)).toHaveValue("1.0.7")
      expect(screen.getByLabelText(/platform version/i)).toHaveValue("Windows 11 24H2")
      expect(screen.getAllByLabelText(/platform profile/i)[0]).toHaveValue("windows-workstation")
      expect(screen.getByLabelText(/connectivity/i)).toHaveValue("degraded")
    })
  })

  it("refreshes the shell title when a fixture endpoint has a newer live hostname", async () => {
    const liveEndpoint: EndpointDetail = {
      endpoint_id: "ep_demo_linux_01",
      hostname: "demo-linux-01-live",
      platform: "linux",
      platform_version: "Ubuntu 24.04 LTS",
      agent_version: "1.3.2",
      tenant_id: "tenant-a",
      site_id: "site-a",
      status: "active",
      connectivity_status: "online",
      last_seen_at: "2026-04-21T16:58:00Z",
      last_heartbeat_at: "2026-04-21T16:58:00Z",
      created_at: "2026-04-21T16:00:00Z",
      updated_at: "2026-04-21T16:58:00Z",
      last_platform_profile: "linux-server",
      declared_capabilities: ["enroll", "heartbeat"],
      execution_hooks: {
        captures_rollback_artifacts: false,
        reports_execution_results: false,
        supports_dry_run: false,
      },
      latest_posture_summary: null,
      latest_results: [],
    }

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith(`/api/endpoints/${liveEndpoint.endpoint_id}`)) {
        return {
          ok: true,
          json: async () => liveEndpoint,
        } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<EndpointDetailPage params={{ endpointId: liveEndpoint.endpoint_id }} />)

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: /endpoint demo-linux-01-live/i })).toBeInTheDocument()
      expect(screen.getByRole("heading", { level: 2, name: /endpoint demo-linux-01-live/i })).toBeInTheDocument()
    })
  })

  it("preserves in-progress form edits while the late live endpoint fetch resolves", async () => {
    const liveEndpoint: EndpointDetail = {
      endpoint_id: "ep_demo_linux_01",
      hostname: "demo-linux-01-live",
      platform: "linux",
      platform_version: "Ubuntu 24.04.1 LTS",
      agent_version: "2.0.0",
      tenant_id: "tenant-a",
      site_id: "site-a",
      status: "active",
      connectivity_status: "online",
      last_seen_at: "2026-04-21T16:58:00Z",
      last_heartbeat_at: "2026-04-21T16:58:00Z",
      created_at: "2026-04-21T16:00:00Z",
      updated_at: "2026-04-21T16:58:00Z",
      last_platform_profile: "linux-server-live",
      declared_capabilities: ["enroll", "heartbeat"],
      execution_hooks: {
        captures_rollback_artifacts: false,
        reports_execution_results: false,
        supports_dry_run: false,
      },
      latest_posture_summary: null,
      latest_results: [],
    }

    const endpointResolvers: Array<(value: Response) => void> = []
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith("/api/endpoints/ep_demo_linux_01")) {
        return new Promise<Response>((resolve) => {
          endpointResolvers.push(resolve)
        })
      }

      return Promise.resolve({ ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response)
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<EndpointDetailPage params={{ endpointId: liveEndpoint.endpoint_id }} />)

    fireEvent.change(screen.getByLabelText(/agent version/i), { target: { value: "manual-agent-version" } })
    fireEvent.change(screen.getAllByLabelText(/platform profile/i)[1], { target: { value: "manual-snapshot-profile" } })

    endpointResolvers.forEach((resolve) => {
      resolve({ ok: true, json: async () => liveEndpoint } as Response)
    })

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: /endpoint demo-linux-01-live/i })).toBeInTheDocument()
    })

    expect(screen.getByLabelText(/agent version/i)).toHaveValue("manual-agent-version")
    expect(screen.getAllByLabelText(/platform profile/i)[1]).toHaveValue("manual-snapshot-profile")
  })

  it("resets dirty form state when navigating to a different endpoint", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})))

    const endpointA: EndpointDetail = {
      endpoint_id: "ep_a",
      hostname: "alpha-host",
      platform: "linux",
      platform_version: "Ubuntu 24.04 LTS",
      agent_version: "1.0.0",
      tenant_id: "tenant-a",
      site_id: "site-a",
      status: "active",
      connectivity_status: "online",
      last_seen_at: "2026-04-21T16:58:00Z",
      last_heartbeat_at: "2026-04-21T16:58:00Z",
      created_at: "2026-04-21T16:00:00Z",
      updated_at: "2026-04-21T16:58:00Z",
      last_platform_profile: "linux-alpha",
      declared_capabilities: ["enroll", "heartbeat"],
      execution_hooks: {
        captures_rollback_artifacts: false,
        reports_execution_results: false,
        supports_dry_run: false,
      },
      latest_posture_summary: null,
      latest_results: [],
    }
    const endpointB: EndpointDetail = {
      ...endpointA,
      endpoint_id: "ep_b",
      hostname: "beta-host",
      agent_version: "2.0.0",
      last_platform_profile: "linux-beta",
    }

    const { rerender } = render(<EndpointDetailConsole endpointId={endpointA.endpoint_id} initialEndpoint={endpointA} />)

    fireEvent.change(screen.getByLabelText(/agent version/i), { target: { value: "manual-edit" } })
    fireEvent.change(screen.getAllByLabelText(/platform profile/i)[1], { target: { value: "manual-snapshot-profile" } })

    rerender(<EndpointDetailConsole endpointId={endpointB.endpoint_id} initialEndpoint={endpointB} />)

    expect(screen.getByLabelText(/agent version/i)).toHaveValue("2.0.0")
    expect(screen.getAllByLabelText(/platform profile/i)[0]).toHaveValue("linux-beta")
    expect(screen.getAllByLabelText(/platform profile/i)[1]).toHaveValue("linux-beta")
  })

  it("submits fixture heartbeat payloads using the current bounded capability and execution-hook names", async () => {
    const pendingEndpoint = new Promise<Response>(() => {})
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)

      if (url.endsWith("/api/endpoints/ep_demo_linux_01/heartbeat") && init?.method === "POST") {
        return {
          ok: true,
          json: async () => ({
            endpoint_id: "ep_demo_linux_01",
            status: "active",
            connectivity_status: "online",
            last_seen_at: "2026-04-21T16:58:00Z",
            last_heartbeat_at: "2026-04-21T16:58:00Z",
            accepted_capability_count: 4,
            pending_action_count: 0,
            created_at: "2026-04-21T16:00:00Z",
            updated_at: "2026-04-21T16:58:00Z",
          }),
        } as Response
      }

      if (url.endsWith("/api/endpoints/ep_demo_linux_01")) {
        return pendingEndpoint
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<EndpointDetailPage params={{ endpointId: "ep_demo_linux_01" }} />)

    fireEvent.click(await screen.findByRole("button", { name: /send heartbeat/i }))

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/endpoints/ep_demo_linux_01/heartbeat"),
        expect.objectContaining({ method: "POST" }),
      )
    })

    const heartbeatCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input).includes("/api/endpoints/ep_demo_linux_01/heartbeat") && init?.method === "POST",
    )
    const payload = JSON.parse(String(heartbeatCall?.[1]?.body ?? "{}"))

    expect(payload.declared_capabilities).toEqual(["enroll", "heartbeat", "collect_posture_snapshot", "inspect_control"])
    expect(payload.execution_hooks).toEqual({
      captures_rollback_artifacts: false,
      reports_execution_results: false,
      supports_dry_run: false,
    })
  })
})
