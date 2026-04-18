import { render, screen } from "@testing-library/react"

import HomePage from "../app/page"
import EndpointDetailPage from "../app/endpoints/[endpointId]/page"
import NavShell from "../components/nav-shell"


describe("SHA dashboard shell", () => {
  it("renders the shared navigation", () => {
    render(
      <NavShell title="Test title" description="Test description">
        <p>Child content</p>
      </NavShell>,
    )

    expect(screen.getByRole("heading", { name: "Test title" })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Fleet" })).toHaveAttribute("href", "/fleet")
    expect(screen.getByRole("link", { name: "Approvals" })).toHaveAttribute("href", "/approvals")
    expect(screen.getByText("Child content")).toBeInTheDocument()
  })

  it("renders the home page and endpoint detail shell from fixtures", () => {
    render(<HomePage />)
    expect(screen.getByRole("heading", { name: "SHA operator workspace" })).toBeInTheDocument()
    expect(screen.getByText(/safe autonomy/i)).toBeInTheDocument()

    render(<EndpointDetailPage params={{ endpointId: "ep_demo_linux_01" }} />)
    expect(screen.getByRole("heading", { name: /Endpoint ep_demo_linux_01/i })).toBeInTheDocument()
    expect(screen.getByText(/Hardening posture/i)).toBeInTheDocument()
  })
})
