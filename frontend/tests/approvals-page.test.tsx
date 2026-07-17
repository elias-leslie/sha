import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import ApprovalsPage from "../app/approvals/page"
import ApprovalsConsole from "../components/approvals-console"
import {
  getFixtureApprovalGrants,
  getFixtureApprovalRequests,
  getFixtureControlRegistry,
  getFixtureEndpoints,
} from "../lib/api"

describe("SHA approvals control plane", () => {
  it("submits an approval decision from the pending review surface", async () => {
    let decisionBody: Record<string, unknown> | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)

      if (url.includes("/api/approval-requests/") && init?.method === "POST") {
        decisionBody = JSON.parse(String(init.body)) as Record<string, unknown>
        return {
          ok: true,
          json: async () => ({
            approval_request_id: "apr_windows_isolation_rollout",
            endpoint_ids: ["ep_demo_windows_01"],
            request_kind: "hardening_change",
            requested_actions: ["apply_control"],
            control_ids: ["control.windows.firewall-endpoint-isolated"],
            troubleshooting_scopes: [],
            requested_ttl_minutes: 45,
            requested_by: "SHAna",
            reason: "Approve Windows endpoint isolation rollout",
            risk: "high",
            status: "approved",
            decision_by: "secops-alpha",
            decision_comment: "Approved for the maintenance window.",
            decision_at: "2026-04-19T12:30:00Z",
            approval_grant_id: "grant_windows_isolation_rollout",
            created_at: "2026-04-18T20:15:00Z",
            updated_at: "2026-04-19T12:30:00Z",
            audit_events: [
              {
                approval_event_id: "ape_windows_isolation_requested",
                event_type: "requested",
                actor: "SHAna",
                comment: "Approve Windows endpoint isolation rollout",
                created_at: "2026-04-18T20:15:00Z",
              },
              {
                approval_event_id: "ape_windows_isolation_approved",
                event_type: "approved",
                actor: "secops-alpha",
                comment: "Approved for the maintenance window.",
                created_at: "2026-04-19T12:30:00Z",
              },
            ],
          }),
        } as Response
      }

      if (url.endsWith("/api/approval-requests")) {
        return { ok: true, json: async () => ({ items: getFixtureApprovalRequests() }) } as Response
      }

      if (url.endsWith("/api/approval-grants")) {
        return { ok: true, json: async () => ({ items: getFixtureApprovalGrants() }) } as Response
      }

      if (url.endsWith("/api/endpoints")) {
        return { ok: true, json: async () => ({ items: getFixtureEndpoints() }) } as Response
      }

      if (url.endsWith("/api/control-registry")) {
        return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<ApprovalsPage />)

    const decisionComment = await screen.findByLabelText(/decision comment/i)
    expect(screen.queryByLabelText(/decision operator/i)).not.toBeInTheDocument()
    expect(screen.getByText(/decision attribution comes from the authenticated API principal/i)).toBeInTheDocument()
    fireEvent.change(decisionComment, {
      target: { value: "Approved for the maintenance window." },
    })
    fireEvent.click(screen.getAllByRole("button", { name: /approve request/i })[0])

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/approval-requests/apr_windows_isolation_rollout/decisions"),
        expect.objectContaining({ method: "POST" }),
      )
    })

    expect(decisionBody).toMatchObject({
      decision: "approve",
      decision_comment: "Approved for the maintenance window.",
    })
    expect(decisionBody).not.toHaveProperty("decided_by")
    expect((await screen.findAllByText(/approved by secops-alpha/i)).length).toBeGreaterThan(0)
  })

  it("does not mix approval fixtures into a failed live load", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503, json: async () => ({ detail: "approval store unavailable" }) }) as Response),
    )

    render(<ApprovalsPage />)

    expect(await screen.findByRole("alert")).toHaveTextContent(/approval store unavailable/i)
    expect(screen.queryByText(/approve windows endpoint isolation rollout/i)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /create approval request/i })).toBeDisabled()
    expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeDisabled()
  })

  it("auto-selects a single live endpoint for both authoring forms", async () => {
    const endpoint = getFixtureEndpoints().find((item) => item.platform === "windows") ?? getFixtureEndpoints()[0]
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/endpoints")) {
          return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
        }
        if (url.endsWith("/api/control-registry")) {
          return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
        }
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }),
    )

    render(<ApprovalsPage />)

    expect(await screen.findByLabelText(/target endpoint/i)).toHaveValue(endpoint.endpoint_id)
    expect(screen.getByLabelText(/^endpoint$/i)).toHaveValue(endpoint.endpoint_id)
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /create approval request/i })).toBeEnabled()
      expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeEnabled()
    })
  })

  it("omits editable actor identity from request and manual grant mutations", async () => {
    const endpoint = getFixtureEndpoints()[0]
    let requestBody: Record<string, unknown> | null = null
    let grantBody: Record<string, unknown> | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith("/api/approval-requests") && init?.method === "POST") {
        requestBody = JSON.parse(String(init.body)) as Record<string, unknown>
        return {
          ok: true,
          json: async () => ({
            ...getFixtureApprovalRequests()[0],
            ...requestBody,
            approval_request_id: "apr-created",
            requested_by: "external:alice",
            status: "pending",
            decision_by: null,
            decision_comment: null,
            decision_at: null,
            approval_grant_id: null,
          }),
        } as Response
      }
      if (url.endsWith("/api/approval-grants") && init?.method === "POST") {
        grantBody = JSON.parse(String(init.body)) as Record<string, unknown>
        return {
          ok: true,
          json: async () => ({
            ...getFixtureApprovalGrants()[0],
            ...grantBody,
            approval_grant_id: "grant-created",
            requested_by: "external:alice",
            approved_by: "external:alice",
          }),
        } as Response
      }
      if (url.endsWith("/api/endpoints")) {
        return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
      }
      if (url.endsWith("/api/control-registry")) {
        return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
      }
      if (url.endsWith("/api/approval-requests") || url.endsWith("/api/approval-grants")) {
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<ApprovalsPage />)

    const createButton = await screen.findByRole("button", { name: /create approval request/i })
    await waitFor(() => expect(createButton).toBeEnabled())
    expect(screen.queryByLabelText(/^requested by$/i)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/^approved by$/i)).not.toBeInTheDocument()
    expect(screen.getByText(/request attribution comes from the authenticated API principal/i)).toBeInTheDocument()
    expect(screen.getByText(/grant attribution comes from the authenticated API principal/i)).toBeInTheDocument()

    fireEvent.click(createButton)
    expect(await screen.findByText(/queued request apr-created/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: /issue manual grant/i }))
    expect(await screen.findByText(/opened manual grant grant-created/i)).toBeInTheDocument()

    expect(requestBody).not.toHaveProperty("requested_by")
    expect(grantBody).not.toHaveProperty("requested_by")
    expect(grantBody).not.toHaveProperty("approved_by")
  })

  it("requires an explicit choice when multiple live endpoints are available", async () => {
    const endpoints = getFixtureEndpoints().slice(0, 2)
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/endpoints")) {
          return { ok: true, json: async () => ({ items: endpoints }) } as Response
        }
        if (url.endsWith("/api/control-registry")) {
          return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
        }
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }),
    )

    render(<ApprovalsPage />)

    const requestEndpoint = await screen.findByLabelText(/target endpoint/i)
    const grantEndpoint = screen.getByLabelText(/^endpoint$/i)
    expect(requestEndpoint).toHaveValue("")
    expect(grantEndpoint).toHaveValue("")
    expect(screen.getByRole("button", { name: /create approval request/i })).toBeDisabled()
    expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeDisabled()

    fireEvent.change(requestEndpoint, { target: { value: endpoints[0].endpoint_id } })
    fireEvent.change(grantEndpoint, { target: { value: endpoints[1].endpoint_id } })
    expect(screen.getByRole("button", { name: /create approval request/i })).toBeEnabled()
    expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeEnabled()
  })

  it("retains supplied snapshots when only their live refresh fails", async () => {
    const request = getFixtureApprovalRequests()[0]
    const grant = getFixtureApprovalGrants()[0]
    const endpoint = getFixtureEndpoints()[0]
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/approval-requests")) {
          return { ok: false, status: 503, json: async () => ({ detail: "request store unavailable" }) } as Response
        }
        if (url.endsWith("/api/approval-grants")) {
          return { ok: false, status: 503, json: async () => ({ detail: "grant store unavailable" }) } as Response
        }
        if (url.endsWith("/api/control-registry")) {
          return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
        }
        return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
      }),
    )

    render(
      <ApprovalsConsole
        initialRequests={[request]}
        initialGrants={[grant]}
        initialEndpoints={[endpoint]}
      />,
    )

    expect(await screen.findByRole("alert")).toHaveTextContent(/request store unavailable.*grant store unavailable/i)
    expect(screen.getAllByText(request.reason).length).toBeGreaterThan(0)
    expect(screen.getByText(grant.reason)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /approve request/i })).toBeEnabled()
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /create approval request/i })).toBeEnabled(),
    )
    expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeEnabled()
  })

  it("gates each mutation on only the resources it depends on", async () => {
    const endpoint = getFixtureEndpoints()[0]
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/approval-requests")) {
          return { ok: false, status: 503, json: async () => ({ detail: "request store unavailable" }) } as Response
        }
        if (url.endsWith("/api/endpoints")) {
          return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
        }
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }),
    )

    render(<ApprovalsPage />)

    expect(await screen.findByRole("alert")).toHaveTextContent(/request store unavailable/i)
    expect(screen.getByRole("button", { name: /create approval request/i })).toBeDisabled()
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeEnabled()
    })
  })

  it("renders only valid actions for terminal requests", () => {
    const denied = {
      ...getFixtureApprovalRequests()[0],
      status: "denied" as const,
      decision_by: "secops-alpha",
      decision_comment: "Denied",
      decision_at: "2026-04-19T12:30:00Z",
    }
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})))

    const { unmount } = render(
      <ApprovalsConsole initialRequests={[denied]} initialGrants={[]} initialEndpoints={getFixtureEndpoints()} />,
    )

    expect(screen.queryByRole("button", { name: /approve request/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /deny request/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /revoke request/i })).not.toBeInTheDocument()

    unmount()
    render(
      <ApprovalsConsole
        initialRequests={[{ ...denied, status: "approved" as const }]}
        initialGrants={[]}
        initialEndpoints={getFixtureEndpoints()}
      />,
    )
    expect(screen.getByRole("button", { name: /revoke request/i })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /approve request/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /deny request/i })).not.toBeInTheDocument()
  })

  it("keeps live requests actionable when auxiliary approval resources fail", async () => {
    const soleEndpoint = getFixtureEndpoints()[0]
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/approval-requests")) {
          return { ok: true, json: async () => ({ items: getFixtureApprovalRequests() }) } as Response
        }
        if (url.endsWith("/api/endpoints")) {
          return { ok: true, json: async () => ({ items: [soleEndpoint] }) } as Response
        }
        if (url.endsWith("/api/control-registry")) {
          return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
        }
        return { ok: false, status: 503, json: async () => ({ detail: "grant store unavailable" }) } as Response
      }),
    )

    render(<ApprovalsConsole />)

    expect(await screen.findByRole("alert")).toHaveTextContent(/grant store unavailable/i)
    expect(screen.getByRole("button", { name: /approve request/i })).toBeEnabled()
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /create approval request/i })).toBeEnabled()
      expect(screen.getByLabelText(/target endpoint/i)).toHaveValue(soleEndpoint.endpoint_id)
      expect(screen.getByLabelText(/^endpoint$/i)).toHaveValue(soleEndpoint.endpoint_id)
    })
    expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeDisabled()
  })

  it("requires an explicit endpoint choice when multiple endpoints are available", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})))

    render(
      <ApprovalsConsole
        initialEndpoints={getFixtureEndpoints().slice(0, 2)}
        initialGrants={[]}
        initialRequests={[]}
      />,
    )

    expect(screen.getByLabelText(/target endpoint/i)).toHaveValue("")
    expect(screen.getByLabelText(/^endpoint$/i)).toHaveValue("")
    expect(screen.getByRole("button", { name: /create approval request/i })).toBeDisabled()
    expect(screen.getByRole("button", { name: /issue manual grant/i })).toBeDisabled()
  })

  it("does not apply a partial request and grant refresh", async () => {
    let requestReads = 0
    const pending = getFixtureApprovalRequests()[0]
    const approved = { ...pending, status: "approved" as const, decision_by: "secops-alpha" }
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes("/decisions") && init?.method === "POST") {
          return { ok: true, json: async () => approved } as Response
        }
        if (url.endsWith("/api/approval-requests")) {
          requestReads += 1
          return { ok: true, json: async () => ({ items: requestReads === 1 ? [pending] : [] }) } as Response
        }
        if (url.endsWith("/api/approval-grants")) {
          return requestReads > 1
            ? ({ ok: false, status: 503, json: async () => ({ detail: "refresh failed" }) } as Response)
            : ({ ok: true, json: async () => ({ items: [] }) } as Response)
        }
        if (url.endsWith("/api/control-registry")) {
          return { ok: true, json: async () => ({ items: getFixtureControlRegistry() }) } as Response
        }
        return { ok: true, json: async () => ({ items: [getFixtureEndpoints()[0]] }) } as Response
      }),
    )

    render(<ApprovalsConsole />)
    fireEvent.click(await screen.findByRole("button", { name: /approve request/i }))

    expect(await screen.findByRole("alert")).toHaveTextContent(/refresh failed/i)
    expect(screen.getByText("Partial")).toBeInTheDocument()
    expect(screen.queryByText(/approved by secops-alpha/i)).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /revoke request/i })).not.toBeInTheDocument()
  })

  it("offers only registry controls supported by the selected endpoint", () => {
    const endpoint = {
      ...getFixtureEndpoints().find((item) => item.platform === "windows")!,
      declared_capabilities: ["apply_control:control.windows.defender-real-time-protection"],
    }
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})))

    render(
      <ApprovalsConsole
        initialControls={getFixtureControlRegistry()}
        initialEndpoints={[endpoint]}
        initialGrants={[]}
        initialRequests={[]}
      />,
    )

    const controlSelect = screen.getByLabelText(/control id/i)
    expect(controlSelect).toHaveTextContent(/windows defender real-time protection/i)
    expect(controlSelect).not.toHaveTextContent(/windows firewall/i)
    expect(controlSelect).not.toHaveTextContent(/linux/i)
    expect(screen.getByRole("button", { name: /create approval request/i })).toBeEnabled()
  })
})
