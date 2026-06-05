// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAuthenticatedFetch } from "../src/fetch.js";
import type { AuthenticatedFetchOptions, AuthenticatedFetch } from "../src/fetch.js";
import type { TokenResponse } from "../src/types.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fakeTokens(accessToken: string, refreshToken = "rt_new"): TokenResponse {
  return {
    access_token: accessToken,
    id_token: "id",
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
  };
}

/** Returns a deferred promise along with its resolve/reject handles. */
function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** Builds a fetch mock that returns 401 for `oldToken` and 200 for `newToken`. */
function mockFetchFor(oldToken: string, newToken: string) {
  return vi.fn().mockImplementation(
    (_input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers as HeadersInit);
      if (headers.get("Authorization") === `Bearer ${newToken}`) {
        return Promise.resolve(new Response(null, { status: 200 }));
      }
      if (headers.get("Authorization") === `Bearer ${oldToken}`) {
        return Promise.resolve(new Response(null, { status: 401 }));
      }
      // No auth header → 401
      return Promise.resolve(new Response(null, { status: 401 }));
    },
  );
}

// ─── Suite ───────────────────────────────────────────────────────────────────

describe("createAuthenticatedFetch", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("attaches Bearer token from getAccessToken", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", mockFetch);

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at_123",
      getRefreshToken: () => null,
      refresh: vi.fn(),
    });

    await apiFetch("https://api.example.com/data");

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer at_123");
  });

  it("sends request without Authorization header when getAccessToken returns null", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", mockFetch);

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => null,
      getRefreshToken: () => null,
      refresh: vi.fn(),
    });

    await apiFetch("https://api.example.com/data");

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const init = mockFetch.mock.calls[0][1] as RequestInit | undefined;
    expect(new Headers(init?.headers).get("Authorization")).toBeNull();
  });

  it("returns non-401 responses unchanged without refreshing", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 403 }));
    vi.stubGlobal("fetch", mockFetch);
    const refresh = vi.fn();

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at",
      getRefreshToken: () => "rt",
      refresh,
    });

    const resp = await apiFetch("https://api.example.com/data");

    expect(resp.status).toBe(403);
    expect(refresh).not.toHaveBeenCalled();
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("on 401: refreshes and retries with new token", async () => {
    const AT_OLD = "at_old";
    const AT_NEW = "at_new";
    const refresh = vi.fn().mockResolvedValue(fakeTokens(AT_NEW));
    const onRefresh = vi.fn();

    vi.stubGlobal("fetch", mockFetchFor(AT_OLD, AT_NEW));

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => AT_OLD,
      getRefreshToken: () => "rt",
      refresh,
      onRefresh,
    });

    const resp = await apiFetch("https://api.example.com/data");

    expect(resp.status).toBe(200);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(refresh).toHaveBeenCalledWith("rt");
    expect(onRefresh).toHaveBeenCalledTimes(1);
    expect(onRefresh).toHaveBeenCalledWith(fakeTokens(AT_NEW));
  });

  it("on 401 with no refresh token: calls onRefreshFailure and returns 401", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
    vi.stubGlobal("fetch", mockFetch);
    const refresh = vi.fn();
    const onRefreshFailure = vi.fn();

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at",
      getRefreshToken: () => null,
      refresh,
      onRefreshFailure,
    });

    const resp = await apiFetch("https://api.example.com/data");

    expect(resp.status).toBe(401);
    expect(refresh).not.toHaveBeenCalled();
    expect(onRefreshFailure).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("on 401: calls onRefreshFailure when refresh rejects and returns 401", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
    vi.stubGlobal("fetch", mockFetch);
    const refreshError = new Error("invalid_grant");
    const refresh = vi.fn().mockRejectedValue(refreshError);
    const onRefreshFailure = vi.fn();

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at",
      getRefreshToken: () => "rt",
      refresh,
      onRefreshFailure,
    });

    const resp = await apiFetch("https://api.example.com/data");

    expect(resp.status).toBe(401);
    expect(onRefreshFailure).toHaveBeenCalledTimes(1);
    expect(onRefreshFailure).toHaveBeenCalledWith(refreshError);
  });

  it("de-duplicates concurrent 401 storms — refresh called exactly once", async () => {
    const AT_OLD = "at_old";
    const AT_NEW = "at_new";
    const { promise: refreshPromise, resolve: resolveRefresh } =
      deferred<TokenResponse>();
    const refresh = vi.fn().mockReturnValue(refreshPromise);
    const onRefresh = vi.fn();

    vi.stubGlobal("fetch", mockFetchFor(AT_OLD, AT_NEW));

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => AT_OLD,
      getRefreshToken: () => "rt",
      refresh,
      onRefresh,
    });

    // Fire 5 concurrent requests — all will get 401 on their first attempt.
    const requests = Promise.all([
      apiFetch("/a"),
      apiFetch("/b"),
      apiFetch("/c"),
      apiFetch("/d"),
      apiFetch("/e"),
    ]);

    // Resolve the refresh before awaiting — all callers were already waiting.
    resolveRefresh(fakeTokens(AT_NEW));

    const results = await requests;

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onRefresh).toHaveBeenCalledTimes(1);
    expect(results.every((r) => r.ok)).toBe(true);
  });

  it("de-duplicated storm: onRefreshFailure called once when refresh rejects", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
    vi.stubGlobal("fetch", mockFetch);

    const { promise: refreshPromise, reject: rejectRefresh } =
      deferred<TokenResponse>();
    const refresh = vi.fn().mockReturnValue(refreshPromise);
    const onRefreshFailure = vi.fn();

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at",
      getRefreshToken: () => "rt",
      refresh,
      onRefreshFailure,
    });

    const requests = Promise.all([apiFetch("/a"), apiFetch("/b"), apiFetch("/c")]);

    rejectRefresh(new Error("token_expired"));

    const results = await requests;

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onRefreshFailure).toHaveBeenCalledTimes(1);
    expect(results.every((r) => r.status === 401)).toBe(true);
  });

  it("prepends baseUrl to relative paths", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", mockFetch);

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at",
      getRefreshToken: () => null,
      refresh: vi.fn(),
      baseUrl: "https://api.example.com",
    });

    await apiFetch("/v1/users");

    expect(mockFetch.mock.calls[0][0]).toBe("https://api.example.com/v1/users");
  });

  it("does not modify absolute URLs even when baseUrl is set", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", mockFetch);

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at",
      getRefreshToken: () => null,
      refresh: vi.fn(),
      baseUrl: "https://api.example.com",
    });

    await apiFetch("https://other.example.com/resource");

    expect(mockFetch.mock.calls[0][0]).toBe("https://other.example.com/resource");
  });

  it("passes through custom request headers alongside Authorization", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", mockFetch);

    const apiFetch = createAuthenticatedFetch({
      getAccessToken: () => "at",
      getRefreshToken: () => null,
      refresh: vi.fn(),
    });

    await apiFetch("https://api.example.com/data", {
      headers: { "X-Request-ID": "req_abc" },
    });

    const headers = new Headers(
      (mockFetch.mock.calls[0][1] as RequestInit).headers as HeadersInit,
    );
    expect(headers.get("Authorization")).toBe("Bearer at");
    expect(headers.get("X-Request-ID")).toBe("req_abc");
  });
});
