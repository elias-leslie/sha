import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import InstallersPage from "../app/installers/page"
import { getFixtureInstallerProfiles } from "../lib/api"

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
            control_plane_url: "https://sha.example.test",
            policy_mode: "approval_required",
            tenant_id: "tenant-branch",
            site_id: "site-demo-branch",
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
      target: { value: "https://sha.example.test" },
    })
    fireEvent.change(screen.getByLabelText(/tenant id/i), { target: { value: "tenant-branch" } })
    fireEvent.change(screen.getByLabelText(/site id/i), { target: { value: "site-demo-branch" } })
    fireEvent.click(screen.getByRole("button", { name: /create installer profile/i }))

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/installer-profiles"),
        expect.objectContaining({ method: "POST" }),
      )
    })

    expect(await screen.findByText("Branch Office Linux")).toBeInTheDocument()
  })

  it("selects the first live profile when fixture state does not exist in the live registry", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)

      if (url.endsWith("/api/installer-profiles")) {
        return {
          ok: true,
          json: async () => ({
            items: [
              {
                id: "ip_live_linux",
                name: "VM100 Linux E2E",
                platform: "linux",
                channel: "stable",
                control_plane_url: "https://sha.example.test",
                policy_mode: "approval_required",
                tenant_id: "tenant-e2e",
                site_id: "vm100",
                created_at: "2026-04-21T16:40:00Z",
                updated_at: "2026-04-21T16:40:00Z",
              },
            ],
          }),
        } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 2, name: /preview for vm100 linux e2e/i })).toBeInTheDocument()
    })

    expect(screen.getByRole("button", { name: /download shell/i })).toBeInTheDocument()
    expect(screen.queryByText(/ip_windows_workstation/i)).not.toBeInTheDocument()
  })

  it("clears a stale fixture artifact when the live registry replaces the selected profile", async () => {
    const fixtureProfile = getFixtureInstallerProfiles()[0]
    const liveProfilesPayload = {
      items: [
        {
          id: "ip_live_linux",
          name: "VM100 Linux E2E",
          platform: "linux",
          channel: "stable",
          control_plane_url: "https://sha.example.test",
          policy_mode: "approval_required",
          tenant_id: "tenant-e2e",
          site_id: "vm100",
          created_at: "2026-04-21T16:40:00Z",
          updated_at: "2026-04-21T16:40:00Z",
        },
      ],
    }

    let resolveProfiles: ((value: Response) => void) | undefined
    const profilesResponse = new Promise<Response>((resolve) => {
      resolveProfiles = resolve
    })

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)

      if (url.endsWith(`/api/installer-profiles/${fixtureProfile.id}/artifact`)) {
        return {
          ok: true,
          text: async () => "#!/usr/bin/env bash\necho stale fixture artifact\n",
          headers: new Headers({
            "content-disposition": `attachment; filename="${fixtureProfile.id}.sh"`,
            "content-type": "text/x-shellscript; charset=utf-8",
            "x-sha-artifact-sha256": "fixturedeadbeef",
          }),
        } as Response
      }

      if (url.endsWith("/api/installer-profiles")) {
        return profilesResponse
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    fireEvent.click(screen.getAllByRole("button", { name: /preview artifact/i })[0])
    expect(await screen.findByText(/stale fixture artifact/i)).toBeInTheDocument()

    resolveProfiles?.({ ok: true, json: async () => liveProfilesPayload } as Response)

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 2, name: /preview for vm100 linux e2e/i })).toBeInTheDocument()
    })
    expect(screen.queryByText(/stale fixture artifact/i)).not.toBeInTheDocument()
    expect(screen.getByText(/no artifact preview loaded/i)).toBeInTheDocument()
  })

  it("does not let a late fixture artifact response clobber the live profile selection", async () => {
    const fixtureProfile = getFixtureInstallerProfiles()[0]
    const liveProfilesPayload = {
      items: [
        {
          id: "ip_live_linux",
          name: "VM100 Linux E2E",
          platform: "linux",
          channel: "stable",
          control_plane_url: "https://sha.example.test",
          policy_mode: "approval_required",
          tenant_id: "tenant-e2e",
          site_id: "vm100",
          created_at: "2026-04-21T16:40:00Z",
          updated_at: "2026-04-21T16:40:00Z",
        },
      ],
    }

    let resolveArtifact: ((value: Response) => void) | undefined
    const artifactResponse = new Promise<Response>((resolve) => {
      resolveArtifact = resolve
    })

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)

      if (url.endsWith(`/api/installer-profiles/${fixtureProfile.id}/artifact`)) {
        return artifactResponse
      }

      if (url.endsWith("/api/installer-profiles")) {
        return { ok: true, json: async () => liveProfilesPayload } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    fireEvent.click(screen.getAllByRole("button", { name: /preview artifact/i })[0])

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 2, name: /preview for vm100 linux e2e/i })).toBeInTheDocument()
    })

    resolveArtifact?.({
      ok: true,
      text: async () => "#!/usr/bin/env bash\necho stale fixture artifact\n",
      headers: new Headers({
        "content-disposition": `attachment; filename="${fixtureProfile.id}.sh"`,
        "content-type": "text/x-shellscript; charset=utf-8",
        "x-sha-artifact-sha256": "fixturedeadbeef",
      }),
    } as Response)

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 2, name: /preview for vm100 linux e2e/i })).toBeInTheDocument()
    })
    expect(screen.queryByRole("heading", { level: 2, name: /select an installer profile/i })).not.toBeInTheDocument()
  })

  it("previews a generated installer artifact and downloads it through the API client", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)

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
                control_plane_url: "https://sha.example.test",
                policy_mode: "approval_required",
                tenant_id: "tenant-branch",
                site_id: "site-demo-branch",
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
    const previousToken = process.env.NEXT_PUBLIC_SHA_API_TOKEN
    process.env.NEXT_PUBLIC_SHA_API_TOKEN = "ui-token"
    const createObjectURL = vi.fn(() => "blob:sha-installer")
    const revokeObjectURL = vi.fn()
    const originalCreateObjectURL = URL.createObjectURL
    const originalRevokeObjectURL = URL.revokeObjectURL
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL })
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL })
    const clickMock = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined)

    try {
      render(<InstallersPage />)

      fireEvent.click(await screen.findByRole("button", { name: /preview artifact/i }))

      expect(await screen.findByText(/sha-linux-branch-office-ip_linux\.sh/i)).toBeInTheDocument()
      expect(await screen.findByText(/echo install/i)).toBeInTheDocument()

      fireEvent.click(screen.getByRole("button", { name: /download shell/i }))

      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledWith(
          expect.stringContaining("/api/installer-profiles/ip_linux/artifact"),
          expect.objectContaining({
            headers: expect.objectContaining({ Authorization: "Bearer ui-token" }),
          }),
        )
      })
      expect(createObjectURL).toHaveBeenCalledTimes(1)
      expect(clickMock).toHaveBeenCalledTimes(1)
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:sha-installer")
    } finally {
      if (previousToken === undefined) {
        delete process.env.NEXT_PUBLIC_SHA_API_TOKEN
      } else {
        process.env.NEXT_PUBLIC_SHA_API_TOKEN = previousToken
      }
      Object.defineProperty(URL, "createObjectURL", { configurable: true, value: originalCreateObjectURL })
      Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: originalRevokeObjectURL })
      clickMock.mockRestore()
    }
  })
})
