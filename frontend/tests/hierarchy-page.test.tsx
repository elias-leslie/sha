import { render, screen } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import HierarchyPage from "../app/hierarchy/page"

vi.mock("next/navigation", () => ({
  usePathname: () => "/hierarchy",
  useSearchParams: () => new URLSearchParams(),
}))

describe("HierarchyPage", () => {
  it("renders hierarchical structure title and tree container", () => {
    render(<HierarchyPage />)

    expect(
      screen.getByRole("heading", { name: "Infrastructure & Systems Hierarchy" }),
    ).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/filter/i)).toBeInTheDocument()
    expect(screen.getByText("Client Organizations & Sites")).toBeInTheDocument()
  })
})
