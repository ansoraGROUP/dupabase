import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { projects, backups, api } from "../api";

const API_URL = "http://localhost:3333";

describe("api helper", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sends GET request with auth header", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "test" }),
    });

    const result = await api("/platform/test", { token: "tok-123" });
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/test`,
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer tok-123",
        }),
      })
    );
    expect(result.data).toEqual({ id: "test" });
    expect(result.error).toBeNull();
  });

  it("returns error for non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({ error: "unauthorized" }),
    });

    const result = await api("/platform/test", { token: "bad" });
    expect(result.data).toBeNull();
    expect(result.error).toBe("unauthorized");
  });

  it("handles network error", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Network failure"));

    const result = await api("/platform/test");
    expect(result.data).toBeNull();
    expect(result.error).toBe("Network failure");
  });
});

describe("projects", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("list constructs correct URL", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [],
    });

    await projects.list("tok-123");
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/projects`,
      expect.any(Object)
    );
  });

  it("list with orgId includes query param", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [],
    });

    await projects.list("tok-123", "org-456");
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/projects?org_id=org-456`,
      expect.any(Object)
    );
  });

  it("get constructs correct URL with project ID", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "proj-1", jwt_secret: "secret" }),
    });

    const result = await projects.get("tok-123", "proj-1");
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/projects/proj-1`,
      expect.any(Object)
    );
    expect(result.data).toEqual({ id: "proj-1", jwt_secret: "secret" });
  });

  it("create sends POST with body", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "new-proj" }),
    });

    await projects.create("tok-123", "My Project");
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/projects`,
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining("My Project"),
      })
    );
  });

  it("delete sends DELETE", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ message: "deleted" }),
    });

    await projects.delete("tok-123", "proj-1");
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/projects/proj-1`,
      expect.objectContaining({ method: "DELETE" })
    );
  });
});

describe("backups", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("getSettings constructs correct URL", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "bs-1", enabled: true }),
    });

    await backups.getSettings("tok-123");
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/backups/settings`,
      expect.any(Object)
    );
  });

  it("getSettings with orgId includes query param", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "bs-1" }),
    });

    await backups.getSettings("tok-123", "org-456");
    expect(mockFetch).toHaveBeenCalledWith(
      `${API_URL}/platform/backups/settings?org_id=org-456`,
      expect.any(Object)
    );
  });
});
