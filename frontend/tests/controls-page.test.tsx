import { fireEvent, render, screen } from "@testing-library/react"

import ControlsPage from "../app/controls/page"
import ControlsConsole from "../components/controls-console"
import { getFixtureApprovalRequests, getFixtureEndpointDetails } from "../lib/api"

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
            control_count: 6,
            packs: [
              {
                pack_id: "pack.public.nist-800-53-rev5-starter",
                source_family: "nist_800_53",
                source_name: "NIST SP 800-53 Rev. 5 Starter",
                source_version: "5.2.0",
                control_count: 3,
              },
              {
                pack_id: "pack.public.cisa-nsa-communications-hardening-starter",
                source_family: "cisa_nsa",
                source_name: "CISA NSA Communications Hardening Starter",
                source_version: "2025-06",
                control_count: 3,
              },
            ],
          }),
        } as Response
      }

      if (url.endsWith("/api/source-packs/pack.public.nist-800-53-rev5-starter")) {
        return {
          ok: true,
          json: async () => ({
            pack_id: "pack.public.nist-800-53-rev5-starter",
            source_family: "nist_800_53",
            source_name: "NIST SP 800-53 Rev. 5 Starter",
            source_version: "5.2.0",
            generated_at: "2026-04-18T00:00:00Z",
            source_url: "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            platforms: ["windows", "linux"],
            profiles: ["domain_controller", "endpoint", "server"],
            summary: "Curated starter pack for NIST SP 800-53 Rev. 5 Starter.",
            controls: [
              {
                control_id: "control.public.nist-800-53.ac-17",
                title: "Remote Access",
                platform: "windows",
                profiles: ["domain_controller", "endpoint", "server"],
                severity: "high",
                disruption: "minimal",
                rollback_complexity: "low",
                auto_remediation_candidate: false,
                reboot_required: false,
                guidance_summary: "Starter guidance for Remote Access.",
                detection_summary: "Check state for Remote Access.",
                remediation_summary: "Apply desired state for Remote Access.",
                rollback_summary: "Rollback desired state for Remote Access.",
                provenance: {
                  source_locator: "NIST SP 800-53 Rev. 5 control AC-17",
                  notes: "Starter control selected for NIST SP 800-53 Rev. 5 Starter.",
                },
                mappings: {
                  nist_csf_ids: [],
                  sp80053_ids: ["AC-17"],
                  stig_ids: [],
                  cisa_reference_ids: [],
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

    expect(await screen.findByText("NIST SP 800-53 Rev. 5 Starter")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: /nist sp 800-53 rev\. 5 starter/i }))
    expect(await screen.findByText(/NIST SP 800-53 Rev\. 5 control AC-17/i)).toBeInTheDocument()
    expect(await screen.findByText(/1 controls/i)).toBeInTheDocument()
  })

  it("retains successful endpoint details and other control resources", async () => {
    const [first, second] = getFixtureEndpointDetails()
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/endpoints")) {
          return { ok: true, json: async () => ({ items: [first, second] }) } as Response
        }
        if (url.endsWith(`/api/endpoints/${first.endpoint_id}`)) {
          return { ok: true, json: async () => first } as Response
        }
        if (url.endsWith(`/api/endpoints/${second.endpoint_id}`)) {
          return { ok: false, status: 503, json: async () => ({ detail: "one detail failed" }) } as Response
        }
        if (url.endsWith("/api/approval-requests")) {
          return { ok: true, json: async () => ({ items: getFixtureApprovalRequests() }) } as Response
        }
        if (url.endsWith("/api/source-packs")) {
          return {
            ok: true,
            json: async () => ({
              packs: [{ pack_id: "pack-live", source_family: "nist", source_name: "Live Pack", source_version: "1", control_count: 2 }],
            }),
          } as Response
        }
        return { ok: false, status: 503, json: async () => ({ detail: "pack detail unavailable" }) } as Response
      }),
    )

    render(<ControlsPage />)

    expect(await screen.findByText(first.hostname)).toBeInTheDocument()
    expect(screen.getByText("Live Pack")).toBeInTheDocument()
    expect(screen.getByText("1")).toBeInTheDocument()
    expect(screen.getByText(/one detail failed/i)).toBeInTheDocument()
  })

  it("shows selected fixture source-pack detail in demo mode", () => {
    vi.stubGlobal("fetch", vi.fn())

    render(<ControlsConsole demoMode />)
    fireEvent.click(screen.getByRole("button", { name: /windows script execution boundary/i }))

    expect(screen.getByRole("heading", { name: /windows script execution boundary/i })).toBeInTheDocument()
    expect(screen.getByText(/moves powershell into signed-only execution/i)).toBeInTheDocument()
  })
})
