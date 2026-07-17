import { render, screen } from "@testing-library/react"

import FleetPage from "../app/fleet/page"
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

  it("makes explicit demo mode global and disables live mutations", () => {
    const previousDemoMode = process.env.NEXT_PUBLIC_SHA_DEMO_MODE
    process.env.NEXT_PUBLIC_SHA_DEMO_MODE = "true"
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    try {
      render(<FleetPage />)
      expect(screen.getByRole("status")).toHaveTextContent(/demo mode.*fixture data only.*mutations disabled/i)
      expect(screen.getByText(/demo fixtures/i)).toBeInTheDocument()
      expect(screen.getByRole("button", { name: /enrollment disabled in demo/i })).toBeDisabled()
      expect(fetchMock).not.toHaveBeenCalled()
    } finally {
      if (previousDemoMode === undefined) {
        delete process.env.NEXT_PUBLIC_SHA_DEMO_MODE
      } else {
        process.env.NEXT_PUBLIC_SHA_DEMO_MODE = previousDemoMode
      }
    }
  })

  it("renders the redesigned home page and delays endpoint actions until live identity loads", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})))

    render(<HomePage />)
    expect(screen.getByRole("heading", { name: /security control plane/i })).toBeInTheDocument()
    expect(screen.getByText(/containment posture/i)).toBeInTheDocument()

    render(<EndpointDetailPage params={{ endpointId: "ep_demo_linux_01" }} />)
    expect(screen.getByRole("heading", { name: /loading endpoint ep_demo_linux_01/i })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /send heartbeat/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /record posture snapshot/i })).not.toBeInTheDocument()
  })
})
