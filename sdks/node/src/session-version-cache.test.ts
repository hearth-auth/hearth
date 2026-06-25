/** §8 — Managed SessionVersionCache tests (C-20). Written before implementation (TDD). */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SessionVersionCache, type SessionVersionConfig } from "./session-version-cache.js";
import {
  SessionVersionRevokedError,
  SessionVersionCacheStaleError,
} from "./errors.js";

const CFG: SessionVersionConfig = {
  enabled: true,
  pollIntervalMs: 5_000,
  staleThresholdMs: 15_000,
  onStale: "reject",
  serviceToken: "svc-token",
};

function mockResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

function makeCache(cfg: Partial<SessionVersionConfig> = {}) {
  return new SessionVersionCache("https://auth.example.com", "realm_test", { ...CFG, ...cfg });
}

describe("SessionVersionCache", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it("seeds from snapshot and exposes a finite age after start", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockResponse({ realm: "realm_test", current_seq: 7, versions: { "sess-1": 3 } }),
    );
    const cache = makeCache();
    cache.start();
    // allow the non-blocking snapshot fetch to resolve
    await vi.waitFor(() => expect(cache.age()).toBeLessThan(Number.POSITIVE_INFINITY));
    cache.stop();

    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toContain("/oauth/session-versions/snapshot");
    expect(url).toContain("realm=realm_test");
  });

  it("validateSv is a no-op when sv or sessionId is absent (backward compat)", () => {
    const cache = makeCache();
    expect(() => cache.validateSv(undefined, "sess-1")).not.toThrow();
    expect(() => cache.validateSv(5n, undefined)).not.toThrow();
  });

  it("throws SessionVersionRevokedError when sv < cached minSv", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      mockResponse({ realm: "realm_test", current_seq: 1, versions: { "sess-1": 4 } }),
    );
    const cache = makeCache();
    cache.start();
    await vi.waitFor(() => expect(cache.age()).toBeLessThan(Number.POSITIVE_INFINITY));
    cache.stop();

    expect(() => cache.validateSv(3n, "sess-1")).toThrow(SessionVersionRevokedError);
    // sv >= minSv passes
    expect(() => cache.validateSv(4n, "sess-1")).not.toThrow();
    // unknown session defaults to minSv=1 → sv>=1 passes
    expect(() => cache.validateSv(1n, "sess-unknown")).not.toThrow();
  });

  it("throws SessionVersionCacheStaleError when never seeded (age = Infinity)", () => {
    const cache = makeCache();
    // no start() → lastRefreshed=0 → age=Infinity > staleThresholdMs
    expect(() => cache.validateSv(5n, "sess-1")).toThrow(SessionVersionCacheStaleError);
  });

  it("stop() is idempotent and safe before start()", () => {
    const cache = makeCache();
    expect(() => { cache.stop(); cache.stop(); }).not.toThrow();
  });
});
