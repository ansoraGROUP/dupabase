import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ExportSection } from "../export-section";

// Mock the auth context
vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ token: "test-token", user: null, loading: false }),
}));

// Mock sonner toast
vi.mock("sonner", () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

describe("ExportSection", () => {
  it("renders format selector", () => {
    render(<ExportSection projectId="proj-123" />);
    expect(screen.getByText("Format")).toBeInTheDocument();
  });

  it("renders download button", () => {
    render(<ExportSection projectId="proj-123" />);
    expect(screen.getByRole("button", { name: /download/i })).toBeInTheDocument();
  });

  it("renders advanced options", () => {
    render(<ExportSection projectId="proj-123" />);
    expect(screen.getByText("Schema only")).toBeInTheDocument();
    expect(screen.getByText("Data only")).toBeInTheDocument();
    expect(screen.getByText("Exclude auth schema")).toBeInTheDocument();
    expect(screen.getByText("Use INSERT statements")).toBeInTheDocument();
  });

  it("renders table filter inputs", () => {
    render(<ExportSection projectId="proj-123" />);
    expect(screen.getByPlaceholderText("e.g. users, orders")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("e.g. logs, temp_data")).toBeInTheDocument();
  });
});
