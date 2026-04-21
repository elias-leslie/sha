import { render, screen } from "@testing-library/react"

import HomePage from "../app/page"
import EndpointDetailPage from "../app/endpoints/[endpointId]/page"
import NavShell from "../components/nav-shell"

describe("SHA dashboard shell", () => {
  it("renders the shared navigation with active operator context", () => {
    render(
      <NavShell currentPath="/fleet" title="Test title" description="Test description">
        <p>Child content</p>
      </NavShell>,
    )

    expect(screen.getByRole("heading", { name: "Test title" })).toBeInTheDocument()
    expect(screen.getAllByText(/operator supervised autonomy/i).length).toBeGreaterThan(0)
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute("href", "/fleet")
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute("data-active", "true")
    expect(screen.getByText("Child content")).toBeInTheDocument()
  })

  it("renders the redesigned home page and endpoint detail actions", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})))

    render(<HomePage />)
    expect(screen.getByRole("heading", { name: /security control plane/i })).toBeInTheDocument()
    expect(screen.getByText(/containment posture/i)).toBeInTheDocument()

    render(<EndpointDetailPage params={{ endpointId: "ep_demo_linux_01" }} />)
    expect(screen.getAllByRole("heading", { name: /endpoint build-lnx-01/i }).length).toBeGreaterThan(0)
    expect(screen.getByRole("button", { name: /send heartbeat/i })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /record posture snapshot/i })).toBeInTheDocument()
  })
})
