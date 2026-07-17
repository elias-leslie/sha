import { act, fireEvent, render, screen } from "@testing-library/react"

import FleetPage from "../app/fleet/page"
import { getFixtureEndpoints } from "../lib/api"

describe("SHA fleet control plane", () => {
  it("shows loading without fixtures until live inventory resolves", async () => {
    let resolveInventory: ((response: Response) => void) | undefined
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            resolveInventory = resolve
          }),
      ),
    )

    render(<FleetPage />)

    expect(screen.getByText(/loading live endpoint inventory/i)).toBeInTheDocument()
    expect(screen.queryByText("demo-linux-01")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /waiting for live inventory/i })).toBeDisabled()

    await act(async () => {
      resolveInventory?.({ ok: true, json: async () => ({ items: getFixtureEndpoints() }) } as Response)
    })

    const search = await screen.findByLabelText(/search endpoints/i)
    fireEvent.change(search, { target: { value: "demo-linux-01" } })
    expect(await screen.findByRole("link", { name: /open endpoint demo-linux-01/i })).toHaveAttribute(
      "href",
      "/endpoints/ep_demo_linux_01",
    )
    expect(screen.queryByText("demo-windows-01")).not.toBeInTheDocument()
  })

  it("shows authentication failure without fixture fallback", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 401, json: async () => ({ detail: "operator token required" }) }) as Response),
    )

    render(<FleetPage />)

    expect(await screen.findByRole("alert")).toHaveTextContent(/operator token required/i)
    expect(screen.queryByText("demo-linux-01")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /waiting for live inventory/i })).toBeDisabled()
  })
})
