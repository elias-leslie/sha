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

    await screen.findByRole("button", { name: /create installer profile/i })
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

  it("creates a macOS installer profile from the operator form", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)

      if (url.endsWith("/api/installer-profiles") && init?.method === "POST") {
        expect(JSON.parse(String(init.body))).toMatchObject({ platform: "macos" })
        return {
          ok: true,
          json: async () => ({
            id: "ip_macos_preview",
            name: "macOS Preview",
            platform: "macos",
            channel: "stable",
            control_plane_url: "https://sha.example.test",
            policy_mode: "observe",
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

    await screen.findByRole("button", { name: /create installer profile/i })
    fireEvent.change(screen.getByLabelText(/profile name/i), { target: { value: "macOS Preview" } })
    fireEvent.change(screen.getByLabelText(/platform/i), { target: { value: "macos" } })
    fireEvent.change(screen.getByLabelText(/policy mode/i), { target: { value: "observe" } })
    fireEvent.click(screen.getByRole("button", { name: /create installer profile/i }))

    expect(await screen.findByText("macOS Preview")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /download compatibility shell reporter/i })).toBeInTheDocument()
    expect(screen.getAllByText("macOS").length).toBeGreaterThan(0)
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
      expect(screen.getByRole("heading", { level: 2, name: /download for vm100 linux e2e/i })).toBeInTheDocument()
    })

    expect(screen.getByRole("button", { name: /download compatibility shell reporter/i })).toBeInTheDocument()
    expect(screen.queryByText(/ip_windows_workstation/i)).not.toBeInTheDocument()
  })

  it("keeps fixture profiles out of a delayed live registry", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})))

    render(<InstallersPage />)

    expect(screen.getByText(/loading live installer profiles/i)).toBeInTheDocument()
    expect(screen.queryByText(getFixtureInstallerProfiles()[0].name)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /waiting for live registry/i })).toBeDisabled()
  })

  it("shows a registry failure without enabling creation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 500, json: async () => ({ detail: "installer registry failed" }) }) as Response),
    )

    render(<InstallersPage />)

    expect(await screen.findByText(/installer registry failed/i)).toBeInTheDocument()
    expect(screen.queryByText(getFixtureInstallerProfiles()[0].name)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /waiting for live registry/i })).toBeDisabled()
  })

  it("downloads an installer without rendering its token-bearing body", async () => {
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
    const createObjectURL = vi.fn(() => "blob:sha-installer")
    const revokeObjectURL = vi.fn()
    const originalCreateObjectURL = URL.createObjectURL
    const originalRevokeObjectURL = URL.revokeObjectURL
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL })
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL })
    const clickMock = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined)

    try {
      render(<InstallersPage />)

      fireEvent.click(await screen.findByRole("button", { name: /download compatibility shell reporter/i }))

      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledWith(
          expect.stringContaining("/api/installer-profiles/ip_linux/artifact"),
          expect.objectContaining({
            cache: "no-store",
            headers: {},
            referrerPolicy: "no-referrer",
          }),
        )
      })
      expect(createObjectURL).toHaveBeenCalledTimes(1)
      expect(clickMock).toHaveBeenCalledTimes(1)
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:sha-installer")
      expect((await screen.findAllByText(/sha-linux-branch-office-ip_linux\.sh/i)).length).toBeGreaterThan(0)
      expect(screen.getByText(/deadbeefcafebabe/i)).toBeInTheDocument()
      expect(screen.queryByText(/echo install/i)).not.toBeInTheDocument()
      expect(screen.queryByText(/curl .*sudo bash/i)).not.toBeInTheDocument()
    } finally {
      Object.defineProperty(URL, "createObjectURL", { configurable: true, value: originalCreateObjectURL })
      Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: originalRevokeObjectURL })
      clickMock.mockRestore()
    }
  })
})
