import { render, screen } from "@testing-library/react"

import ApprovalsPage from "../app/approvals/page"


describe("SHA approvals workspace", () => {
  it("renders pending requests, active grants, and the SHAna boundary copy", () => {
    render(<ApprovalsPage />)

    expect(screen.getByRole("heading", { name: "Approval queue" })).toBeInTheDocument()
    expect(screen.getByRole("heading", { name: "Pending requests" })).toBeInTheDocument()
    expect(screen.getByRole("heading", { name: "Active grants" })).toBeInTheDocument()
    expect(screen.getByRole("heading", { name: "Audit trail" })).toBeInTheDocument()
    expect(screen.getByText(/no arbitrary shell access/i)).toBeInTheDocument()
  })

  it("renders the troubleshooting and hardening request fixtures with scoped details", () => {
    render(<ApprovalsPage />)

    expect(screen.getAllByText("Temporary elevated troubleshooting for ops-win-04").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/security logs/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/request_elevated_troubleshooting/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText("Approve RDP network level authentication rollout")).toBeInTheDocument()
    expect(screen.getByText(/control\.windows\.rdp-network-level-authentication/i)).toBeInTheDocument()
    expect(screen.getByText(/grant expired automatically/i)).toBeInTheDocument()
  })
})
