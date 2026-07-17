import { fireEvent, render, screen, waitFor } from "@testing-library/react"

import InstallersPage from "../app/installers/page"
import { getFixtureInstallerProfiles, type InstallerProfile } from "../lib/api"

const CLIENTS = [
  {
    client_id: "cl_branch",
    key: "branch",
    name: "Branch Client",
    state: "active",
    is_system: false,
    created_at: "2026-04-19T12:00:00Z",
    updated_at: "2026-04-19T12:00:00Z",
  },
  {
    client_id: "cl_legacy_quarantine",
    key: null,
    name: "Legacy client",
    state: "migration_quarantine",
    is_system: true,
    created_at: "2026-04-19T12:00:00Z",
    updated_at: "2026-04-19T12:00:00Z",
  },
]

const LOCATIONS = {
  cl_branch: [
    {
      location_id: "loc_branch_office",
      client_id: "cl_branch",
      key: "branch-office",
      name: "Branch Office",
      state: "active",
      is_system: false,
      created_at: "2026-04-19T12:00:00Z",
      updated_at: "2026-04-19T12:00:00Z",
    },
  ],
  cl_legacy_quarantine: [
    {
      location_id: "loc_legacy_quarantine",
      client_id: "cl_legacy_quarantine",
      key: null,
      name: "Legacy location",
      state: "migration_quarantine",
      is_system: true,
      created_at: "2026-04-19T12:00:00Z",
      updated_at: "2026-04-19T12:00:00Z",
    },
  ],
} as const

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response
}

function requestPath(input: RequestInfo | URL) {
  return new URL(String(input), "https://sha.example.test").pathname
}

function hierarchyResponse(input: RequestInfo | URL, init?: RequestInit) {
  if (init?.method && init.method !== "GET") {
    return null
  }

  const path = requestPath(input)
  if (path === "/api/clients") {
    return jsonResponse({ items: CLIENTS })
  }
  if (path === "/api/clients/cl_branch/locations") {
    return jsonResponse({ items: LOCATIONS.cl_branch })
  }
  if (path === "/api/clients/cl_legacy_quarantine/locations") {
    return jsonResponse({ items: LOCATIONS.cl_legacy_quarantine })
  }
  return null
}

async function selectBranchHierarchy() {
  fireEvent.change(await screen.findByLabelText(/^client$/i), {
    target: { value: "cl_branch" },
  })
  await screen.findByRole("option", { name: "Branch Office" })
  fireEvent.change(screen.getByLabelText(/^location$/i), {
    target: { value: "loc_branch_office" },
  })
}

describe("SHA installer workspace", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/installers")
  })

  it("creates a live installer profile from the operator form", async () => {
    let createdProfile: InstallerProfile | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestPath(input)

      if (path === "/api/installer-profiles" && init?.method === "POST") {
        createdProfile = {
          id: "ip_branch_office_linux",
          name: "Branch Office Linux",
          platform: "linux",
          channel: "stable",
          control_plane_url: "https://sha.example.test",
          policy_mode: "approval_required",
          client_id: "cl_branch",
          location_id: "loc_branch_office",
          tenant_id: null,
          site_id: null,
          created_at: "2026-04-19T12:40:00Z",
          updated_at: "2026-04-19T12:40:00Z",
        }
        return jsonResponse(createdProfile)
      }

      const hierarchy = hierarchyResponse(input, init)
      if (hierarchy) {
        return hierarchy
      }

      if (path === "/api/installer-profiles") {
        return jsonResponse({ items: createdProfile ? [createdProfile] : [] })
      }

      return jsonResponse({ detail: "not found" }, 404)
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    await screen.findByRole("button", { name: /create installer profile/i })
    fireEvent.change(screen.getByLabelText(/profile name/i), { target: { value: "Branch Office Linux" } })
    fireEvent.change(screen.getByLabelText(/control plane url/i), {
      target: { value: "https://sha.example.test" },
    })
    expect((await screen.findAllByRole("option", { name: /migration quarantine/i })).length).toBeGreaterThan(0)
    await selectBranchHierarchy()
    fireEvent.click(screen.getByRole("button", { name: /create installer profile/i }))

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/installer-profiles"),
        expect.objectContaining({ method: "POST" }),
      )
    })

    const postCall = fetchMock.mock.calls.find(
      ([input, init]) => requestPath(input) === "/api/installer-profiles" && init?.method === "POST",
    )
    expect(postCall).toBeDefined()
    const postedBody = JSON.parse(String(postCall?.[1]?.body))
    expect(postedBody).toMatchObject({
      client_id: "cl_branch",
      location_id: "loc_branch_office",
    })
    expect(postedBody).not.toHaveProperty("tenant_id")
    expect(postedBody).not.toHaveProperty("site_id")
    expect(await screen.findByText("Branch Office Linux")).toBeInTheDocument()
  })

  it("creates a macOS installer profile from the operator form", async () => {
    let createdProfile: InstallerProfile | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestPath(input)

      if (path === "/api/installer-profiles" && init?.method === "POST") {
        expect(JSON.parse(String(init.body))).toMatchObject({
          platform: "macos",
          client_id: "cl_branch",
          location_id: "loc_branch_office",
        })
        createdProfile = {
          id: "ip_macos_preview",
          name: "macOS Preview",
          platform: "macos",
          channel: "stable",
          control_plane_url: "https://sha.example.test",
          policy_mode: "observe",
          client_id: "cl_branch",
          location_id: "loc_branch_office",
          tenant_id: null,
          site_id: null,
          created_at: "2026-04-19T12:40:00Z",
          updated_at: "2026-04-19T12:40:00Z",
        }
        return jsonResponse(createdProfile)
      }

      const hierarchy = hierarchyResponse(input, init)
      if (hierarchy) {
        return hierarchy
      }

      if (path === "/api/installer-profiles") {
        return jsonResponse({ items: createdProfile ? [createdProfile] : [] })
      }

      return jsonResponse({ detail: "not found" }, 404)
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    await screen.findByRole("button", { name: /create installer profile/i })
    fireEvent.change(screen.getByLabelText(/profile name/i), { target: { value: "macOS Preview" } })
    fireEvent.change(screen.getByLabelText(/platform/i), { target: { value: "macos" } })
    fireEvent.change(screen.getByLabelText(/policy mode/i), { target: { value: "observe" } })
    await selectBranchHierarchy()
    fireEvent.click(screen.getByRole("button", { name: /create installer profile/i }))

    expect(await screen.findByText("macOS Preview")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /download compatibility shell reporter/i })).toBeInTheDocument()
    expect(screen.getAllByText("macOS").length).toBeGreaterThan(0)
  })

  it("selects the first live profile when fixture state does not exist in the live registry", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestPath(input)

      const hierarchy = hierarchyResponse(input, init)
      if (hierarchy) {
        return hierarchy
      }

      if (path === "/api/installer-profiles") {
        return jsonResponse({
          items: [
            {
              id: "ip_live_linux",
              name: "VM100 Linux E2E",
              platform: "linux",
              channel: "stable",
              control_plane_url: "https://sha.example.test",
              policy_mode: "approval_required",
              client_id: "cl_legacy_quarantine",
              location_id: "loc_legacy_quarantine",
              tenant_id: "tenant-e2e",
              site_id: "vm100",
              created_at: "2026-04-21T16:40:00Z",
              updated_at: "2026-04-21T16:40:00Z",
            },
          ],
        })
      }

      return jsonResponse({ detail: "not found" }, 404)
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 2, name: /download for vm100 linux e2e/i })).toBeInTheDocument()
    })

    expect(screen.getByRole("button", { name: /download compatibility shell reporter/i })).toBeInTheDocument()
    expect(screen.getAllByText(/^migration quarantine$/i).length).toBeGreaterThan(0)
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
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
        hierarchyResponse(input, init) ?? jsonResponse({ detail: "installer registry failed" }, 500),
      ),
    )

    render(<InstallersPage />)

    expect(await screen.findByText(/installer registry failed/i)).toBeInTheDocument()
    expect(screen.queryByText(getFixtureInstallerProfiles()[0].name)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /waiting for live registry/i })).toBeDisabled()
  })

  it("refetches the active viewpoint and does not display a cross-location creation", async () => {
    window.history.replaceState(
      {},
      "",
      "/installers?client_id=cl_branch&location_id=loc_branch_office",
    )
    let created = false
    const crossLocationProfile: InstallerProfile = {
      id: "ip_wrong_location",
      name: "Wrong Location Linux",
      platform: "linux",
      channel: "stable",
      control_plane_url: "https://sha.example.test",
      policy_mode: "approval_required",
      client_id: "cl_branch",
      location_id: "loc_other",
      tenant_id: "branch",
      site_id: "other",
      created_at: "2026-04-19T12:40:00Z",
      updated_at: "2026-04-19T12:40:00Z",
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestPath(input)
      if (path === "/api/installer-profiles" && init?.method === "POST") {
        created = true
        return jsonResponse(crossLocationProfile)
      }
      const hierarchy = hierarchyResponse(input, init)
      if (hierarchy) {
        return hierarchy
      }
      if (path === "/api/installer-profiles") {
        return jsonResponse({ items: created ? [crossLocationProfile] : [] })
      }
      return jsonResponse({ detail: "not found" }, 404)
    })
    vi.stubGlobal("fetch", fetchMock)

    render(<InstallersPage />)

    const createButton = await screen.findByRole("button", { name: /create installer profile/i })
    expect(createButton).toBeEnabled()
    expect(screen.getByLabelText(/^client$/i)).toBeDisabled()
    expect(screen.getByLabelText(/^location$/i)).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/profile name/i), {
      target: { value: crossLocationProfile.name },
    })
    fireEvent.click(createButton)

    expect(await screen.findByText(/outside the active viewpoint and is not displayed/i)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /download compatibility/i })).not.toBeInTheDocument()
    expect(
      fetchMock.mock.calls.filter(
        ([input, init]) =>
          requestPath(input) === "/api/installer-profiles" && (init?.method ?? "GET") === "GET",
      ).length,
    ).toBeGreaterThanOrEqual(2)
  })

  it("marks an active client's migration-quarantine location", async () => {
    const quarantineLocation = {
      location_id: "loc_unassigned",
      client_id: "cl_branch",
      key: null,
      name: "Unassigned",
      state: "migration_quarantine",
      is_system: true,
      created_at: "2026-04-19T12:00:00Z",
      updated_at: "2026-04-19T12:00:00Z",
    }
    const profile: InstallerProfile = {
      id: "ip_unassigned",
      name: "Unassigned Linux",
      platform: "linux",
      channel: "stable",
      control_plane_url: "https://sha.example.test",
      policy_mode: "observe",
      client_id: "cl_branch",
      location_id: quarantineLocation.location_id,
      tenant_id: "branch",
      site_id: null,
      created_at: "2026-04-19T12:40:00Z",
      updated_at: "2026-04-19T12:40:00Z",
    }
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = requestPath(input)
        if (path === "/api/clients") {
          return jsonResponse({ items: [CLIENTS[0]] })
        }
        if (path === "/api/clients/cl_branch/locations") {
          return jsonResponse({ items: [quarantineLocation] })
        }
        if (path === "/api/installer-profiles") {
          return jsonResponse({ items: [profile] })
        }
        return jsonResponse({ detail: "not found" }, 404)
      }),
    )

    render(<InstallersPage />)

    expect(await screen.findByText(profile.name)).toBeInTheDocument()
    expect(await screen.findByText(/^migration quarantine$/i)).toBeInTheDocument()
  })

  it("downloads an installer without rendering its token-bearing body", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestPath(input)

      if (path === "/api/installer-profiles/ip_linux/artifact") {
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

      const hierarchy = hierarchyResponse(input, init)
      if (hierarchy) {
        return hierarchy
      }

      if (path === "/api/installer-profiles") {
        return jsonResponse({
          items: [
            {
              id: "ip_linux",
              name: "Branch Office Linux",
              platform: "linux",
              channel: "stable",
              control_plane_url: "https://sha.example.test",
              policy_mode: "approval_required",
              client_id: "cl_branch",
              location_id: "loc_branch_office",
              tenant_id: "tenant-branch",
              site_id: "site-demo-branch",
              created_at: "2026-04-19T12:40:00Z",
              updated_at: "2026-04-19T12:40:00Z",
            },
          ],
        })
      }

      return jsonResponse({ detail: "not found" }, 404)
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
