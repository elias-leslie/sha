import { render, screen } from "@testing-library/react"

import HomeConsole from "../components/home-console"
import { getFixtureEndpoints } from "../lib/api"

describe("SHA home console", () => {
  it("keeps successful dashboard datasets when another resource fails", async () => {
    const endpoint = getFixtureEndpoints()[0]
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith("/api/endpoints")) {
          return { ok: true, json: async () => ({ items: [endpoint] }) } as Response
        }
        if (url.endsWith("/api/approval-requests")) {
          return { ok: false, status: 503, json: async () => ({ detail: "approval data unavailable" }) } as Response
        }
        return { ok: true, json: async () => ({ items: [] }) } as Response
      }),
    )

    render(<HomeConsole />)

    expect(await screen.findByRole("alert")).toHaveTextContent(/partial live data: approval data unavailable/i)
    expect(screen.getAllByText(endpoint.hostname).length).toBeGreaterThan(0)
    expect(screen.getByText(/live backend unavailable/i)).toBeInTheDocument()
  })
})
