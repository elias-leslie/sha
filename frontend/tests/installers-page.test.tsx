import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import InstallersPage from "../app/installers/page"

describe("SHA installer workspace", () => {
  it("creates a live installer profile from the operator form", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)

      if (url.endsWith("/api/installer-profiles") && init?.method === "POST") {
        return {
          ok: true,
          json: async () => ({
            id: "ip_branch_office_linux",
            name: "Branch Office Linux",
            platform: "linux",
            channel: "stable",
            control_plane_url: "https://sha.summitflow.dev",
            policy_mode: "approval_required",
            tenant_id: "tenant-branch",
            site_id: "branch-01",
            created_at: "2026-04-19T12:40:00Z",
            updated_at: "2026-04-19T12:40:00Z",
          }),
        } as Response
      }

      if (url.endsWith("/api/installer-profiles")) {
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    fireEvent.change(screen.getByLabelText(/profile name/i), { target: { value: "Branch Office Linux" } })
    fireEvent.change(screen.getByLabelText(/control plane url/i), {
      target: { value: "https://sha.summitflow.dev" },
    })
    fireEvent.change(screen.getByLabelText(/tenant id/i), { target: { value: "tenant-branch" } })
    fireEvent.change(screen.getByLabelText(/site id/i), { target: { value: "branch-01" } })
    fireEvent.click(screen.getByRole("button", { name: /create installer profile/i }))

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/installer-profiles"),
        expect.objectContaining({ method: "POST" }),
      )
    })

    expect(await screen.findByText("Branch Office Linux")).toBeInTheDocument()
  })

  it("previews a generated installer artifact and exposes its download link", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)

      if (url.endsWith("/api/installer-profiles/ip_linux/ artifact")) {
        return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
      }

      if (url.endsWith("/api/installer-profiles/ip_linux/artifact")) {
        return {
          ok: true,
          text: async () => "#!/usr/bin/env bash\necho install\n",
          headers: new Headers({
            "content-disposition": 'attachment; filename="sha-linux-branch-office-ip_linux.sh"',
            "content-type": "text/x-shellscript; charset=utf-8",
            "x-sha-artifact-sha256": "deadbeefcafebabe",
          }),
        } as Response
      }

      if (url.endsWith("/api/installer-profiles")) {
        return {
          ok: true,
          json: async () => ({
            items: [
              {
                id: "ip_linux",
                name: "Branch Office Linux",
                platform: "linux",
                channel: "stable",
                control_plane_url: "https://sha.summitflow.dev",
                policy_mode: "approval_required",
                tenant_id: "tenant-branch",
                site_id: "branch-01",
                created_at: "2026-04-19T12:40:00Z",
                updated_at: "2026-04-19T12:40:00Z",
              },
            ],
          }),
        } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    fireEvent.click(await screen.findByRole("button", { name: /preview artifact/i }))

    expect(await screen.findByText(/sha-linux-branch-office-ip_linux\.sh/i)).toBeInTheDocument()
    expect(await screen.findByText(/echo install/i)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /download shell/i })).toHaveAttribute(
      "href",
      "/api/installer-profiles/ip_linux/artifact",
    )
  })
})
