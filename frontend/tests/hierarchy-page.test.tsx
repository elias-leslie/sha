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
      screen.getByRole("heading", { name: /compliance console/i }),
    ).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument()
  })
})
