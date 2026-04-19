import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import ApprovalsPage from "../app/approvals/page"
import {
  getFixtureApprovalGrants,
  getFixtureApprovalRequests,
  getFixtureEndpoints,
} from "../lib/api"

describe("SHA approvals control plane", () => {
  it("submits an approval decision from the pending review surface", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)

      if (url.includes("/api/approval-requests/") && init?.method === "POST") {
        return {
          ok: true,
          json: async () => ({
            approval_request_id: "apr_windows_rdp_rollout",
            endpoint_ids: ["ep_demo_windows_01"],
            request_kind: "hardening_change",
            requested_actions: ["apply_control"],
            control_ids: ["control.windows.rdp-network-level-authentication"],
            troubleshooting_scopes: [],
            requested_ttl_minutes: 45,
            requested_by: "SHAna",
            reason: "Approve RDP network level authentication rollout",
            risk: "high",
            status: "approved",
            decision_by: "secops-alpha",
            decision_comment: "Approved for the maintenance window.",
            decision_at: "2026-04-19T12:30:00Z",
            approval_grant_id: "grant_windows_rdp_rollout",
            created_at: "2026-04-18T20:15:00Z",
            updated_at: "2026-04-19T12:30:00Z",
            audit_events: [
              {
                approval_event_id: "ape_windows_rdp_requested",
                event_type: "requested",
                actor: "SHAna",
                comment: "Approve RDP network level authentication rollout",
                created_at: "2026-04-18T20:15:00Z",
              },
              {
                approval_event_id: "ape_windows_rdp_approved",
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

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<ApprovalsPage />)

    fireEvent.change(screen.getByLabelText(/decision operator/i), { target: { value: "secops-alpha" } })
    fireEvent.change(screen.getByLabelText(/decision comment/i), {
      target: { value: "Approved for the maintenance window." },
    })
    fireEvent.click(screen.getAllByRole("button", { name: /approve request/i })[0])

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/approval-requests/apr_windows_rdp_rollout/decisions"),
        expect.objectContaining({ method: "POST" }),
      )
    })

    expect(await screen.findByText(/approved by secops-alpha/i)).toBeInTheDocument()
  })
})
