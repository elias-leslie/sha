import { fireEvent, render, screen } from "@testing-library/react"

import FleetPage from "../app/fleet/page"

describe("SHA fleet control plane", () => {
  it("supports operator search and renders reachable endpoint detail links", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})))

    render(<FleetPage />)

    const search = screen.getByLabelText(/search endpoints/i)
    fireEvent.change(search, { target: { value: "demo-linux-01" } })

    expect(screen.getByRole("link", { name: /open endpoint demo-linux-01/i })).toHaveAttribute(
      "href",
      "/endpoints/ep_demo_linux_01",
    )
    expect(screen.queryByText("demo-windows-01")).not.toBeInTheDocument()
  })
})
