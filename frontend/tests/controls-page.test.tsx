import { fireEvent, render, screen } from "@testing-library/react"

import ControlsPage from "../app/controls/page"

describe("SHA controls workspace", () => {
  it("loads live source-pack summaries and shows selected pack detail", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)

      if (url.endsWith("/api/endpoints")) {
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }

      if (url.endsWith("/api/approval-requests")) {
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }

      if (url.endsWith("/api/source-packs")) {
        return {
          ok: true,
          json: async () => ({
            generated_at: "2026-04-18T00:00:00Z",
            pack_count: 2,
            control_count: 4,
            packs: [
              {
                pack_id: "pack.alpha",
                source_family: "legacy_sha",
                source_name: "Legacy SHA Snapshot",
                source_version: "sha256:test",
                control_count: 2,
              },
              {
                pack_id: "pack.beta",
                source_family: "microsoft",
                source_name: "Microsoft Starter",
                source_version: "starter-2026.04",
                control_count: 2,
              },
            ],
          }),
        } as Response
      }

      if (url.endsWith("/api/source-packs/pack.alpha")) {
        return {
          ok: true,
          json: async () => ({
            pack_id: "pack.alpha",
            source_family: "legacy_sha",
            source_name: "Legacy SHA Snapshot",
            source_version: "sha256:test",
            generated_at: "2026-04-18T00:00:00Z",
            source_url: "repo://control-packs/legacy/SecurityControls.csv",
            platforms: ["windows"],
            profiles: ["domain_controller", "endpoint", "server"],
            summary: "Curated starter pack for Legacy SHA Snapshot.",
            controls: [
              {
                control_id: "control.legacy-sha.snapshot.sha001",
                title: "Length of password history maintained",
                platform: "windows",
                profiles: ["domain_controller", "endpoint", "server"],
                severity: "medium",
                disruption: "minimal",
                rollback_complexity: "low",
                auto_remediation_candidate: true,
                reboot_required: false,
                guidance_summary: "Starter guidance for Length of password history maintained.",
                detection_summary: "Check state for Length of password history maintained.",
                remediation_summary: "Apply desired state for Length of password history maintained.",
                rollback_summary: "Rollback desired state for Length of password history maintained.",
                provenance: {
                  source_locator: "SecurityControls.csv#SHA001",
                  notes: "Starter control selected for Legacy SHA Snapshot.",
                },
                mappings: {
                  cis_control_ids: ["4.1"],
                  nist_csf_ids: [],
                  sp80053_ids: [],
                  legacy_sha_ids: ["SHA001"],
                },
              },
            ],
          }),
        } as Response
      }

      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) } as Response
    })

    vi.stubGlobal("fetch", fetchMock)

    render(<ControlsPage />)

    expect(await screen.findByText("Legacy SHA Snapshot")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: /legacy sha snapshot/i }))
    expect(await screen.findByText(/securitycontrols\.csv#sha001/i)).toBeInTheDocument()
    expect(await screen.findByText(/1 controls/i)).toBeInTheDocument()
  })
})
