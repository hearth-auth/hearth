import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createHearth } from "../src/hearth.js";
import { SessionVersionCache } from "../src/session-version-cache.js";
import {
  SessionVersionCacheStaleError,
  SessionVersionRevokedError,
} from "../src/errors.js";
import type { SessionVersionConfig } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Flush all outstanding microtasks (promise chains) without advancing fake
 * timers. Five rounds handle promise chains up to depth 5.
 */
async function flushAsync(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

function forgeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  return `${header}.${body}.fakesig`;
}

const BASE_SV_CONFIG: SessionVersionConfig = {
  enabled: true,
  pollIntervalMs: 5_000,
  staleThresholdMs: 60_000,
  onStale: "reject",
  serviceToken: "svc-token",
};

function mockFetch(body: unknown, status = 200): void {
  // HTTP 204 No Content must have a null body per the Fetch spec.
  const hasBody = status !== 204;
  vi.mocked(fetch).mockResolvedValueOnce(
    new Response(hasBody ? JSON.stringify(body) : null, {
      status,
      headers: hasBody ? { "Content-Type": "application/json" } : {},
    }),
  );
}

function snapshotResponse(versions: Record<string, number>, seq = 10) {
  return { realm: "r1", current_seq: seq, versions };
}

function deltaResponse(deltas: Array<{ session_id: string; min_sv: number }>, nextSeq = 12) {
  return {
    realm: "r1",
    next_seq: nextSeq,
    deltas: deltas.map((d, i) => ({
      seq: 11 + i,
      session_id: d.session_id,
      min_sv: d.min_sv,
      bumped_at: 1700000900,
    })),
  };
}

// ---------------------------------------------------------------------------
// SessionVersionCache — unit tests (no real timers)
// ---------------------------------------------------------------------------

describe("SessionVersionCache", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("fetches snapshot on start() and seeds local versions", async () => {
    mockFetch(snapshotResponse({ sess_01: 1, sess_02: 3 }));

    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    // Let the async snapshot fetch resolve.
    await flushAsync();

    // sess_01 at sv=1 should pass (token sv >= minSv).
    expect(() => cache.validateSv(1n, "sess_01")).not.toThrow();
    // sess_02 bumped to min=3; sv=2 should be rejected.
    expect(() => cache.validateSv(2n, "sess_02")).toThrow(SessionVersionRevokedError);
    // sess_02 at sv=3 should pass.
    expect(() => cache.validateSv(3n, "sess_02")).not.toThrow();
  });

  it("applies delta entries and advances the sequence cursor", async () => {
    // Snapshot seeds sess_01 at min=1.
    mockFetch(snapshotResponse({ sess_01: 1 }));
    // Delta bumps sess_01 to min=4.
    mockFetch(deltaResponse([{ session_id: "sess_01", min_sv: 4 }]));

    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    await flushAsync();

    // Advance time past poll interval, let poll fire.
    vi.advanceTimersByTime(BASE_SV_CONFIG.pollIntervalMs + 1);
    await flushAsync();

    // sv=3 must be rejected now.
    expect(() => cache.validateSv(3n, "sess_01")).toThrow(SessionVersionRevokedError);
    // sv=4 is exactly the new minimum — should pass.
    expect(() => cache.validateSv(4n, "sess_01")).not.toThrow();

    cache.stop();
  });

  it("handles HTTP 204 (no deltas) by updating lastRefreshed", async () => {
    mockFetch(snapshotResponse({}));
    mockFetch(null, 204); // no-content on poll

    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    await flushAsync();

    vi.advanceTimersByTime(BASE_SV_CONFIG.pollIntervalMs + 1);
    await flushAsync();

    // Cache was refreshed → age should be small.
    expect(cache.age()).toBeLessThan(1_000);
    cache.stop();
  });

  it("re-fetches snapshot when poll returns HTTP 400 (sequence too old)", async () => {
    mockFetch(snapshotResponse({ sess_A: 2 }));      // initial snapshot
    mockFetch(null, 400);                             // poll says seq too old
    mockFetch(snapshotResponse({ sess_A: 5 }));      // re-snapshot after 400

    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    await flushAsync();

    vi.advanceTimersByTime(BASE_SV_CONFIG.pollIntervalMs + 1);
    await flushAsync();

    // After re-snapshot, sess_A min=5; sv=4 must be rejected.
    expect(() => cache.validateSv(4n, "sess_A")).toThrow(SessionVersionRevokedError);
    expect(() => cache.validateSv(5n, "sess_A")).not.toThrow();
    cache.stop();
  });

  it("skips validation when sv claim is absent (backward compat, RFC § 8.2)", async () => {
    mockFetch(snapshotResponse({}));
    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    await flushAsync();

    // No sv → no-op, must not throw.
    expect(() => cache.validateSv(undefined, "sess_X")).not.toThrow();
    expect(() => cache.validateSv(1n, undefined)).not.toThrow();
    cache.stop();
  });

  it("defaults unknown sessions to minSv=1 (first bump hasn't arrived yet)", async () => {
    mockFetch(snapshotResponse({})); // empty snapshot
    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    await flushAsync();

    // sv=1 ≥ default minSv=1 → ok.
    expect(() => cache.validateSv(1n, "brand_new_session")).not.toThrow();
    cache.stop();
  });

  it("throws SessionVersionCacheStaleError when cache age exceeds staleThresholdMs", async () => {
    mockFetch(snapshotResponse({ sess_S: 1 }));
    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    await flushAsync();

    // Advance time past the stale threshold.
    vi.advanceTimersByTime(BASE_SV_CONFIG.staleThresholdMs + 1_000);

    const err = (() => {
      try { cache.validateSv(1n, "sess_S"); }
      catch (e) { return e; }
    })();
    expect(err).toBeInstanceOf(SessionVersionCacheStaleError);
    expect((err as SessionVersionCacheStaleError).onStale).toBe("reject");
    cache.stop();
  });

  it("throws SessionVersionCacheStaleError (never seeded) before first snapshot resolves", () => {
    // fetch never resolves
    vi.mocked(fetch).mockReturnValue(new Promise(() => undefined));

    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();

    // age() returns Infinity when lastRefreshed===0.
    expect(cache.age()).toBe(Number.POSITIVE_INFINITY);
    expect(() => cache.validateSv(1n, "sess_never")).toThrow(SessionVersionCacheStaleError);
    cache.stop();
  });

  it("warns when staleThresholdMs <= pollIntervalMs", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    mockFetch(snapshotResponse({}));

    const badCfg: SessionVersionConfig = {
      ...BASE_SV_CONFIG,
      pollIntervalMs: 10_000,
      staleThresholdMs: 5_000,  // less than poll — should warn
    };
    const cache = new SessionVersionCache("https://hearth.example.com", "r1", badCfg);
    cache.start();
    await flushAsync();

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("staleThresholdMs must be > pollIntervalMs"),
    );
    cache.stop();
    warnSpy.mockRestore();
  });

  it("stop() prevents further polls", async () => {
    mockFetch(snapshotResponse({}));
    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    await flushAsync();

    cache.stop();
    // Advance well past two poll intervals — no more fetch calls.
    vi.advanceTimersByTime(BASE_SV_CONFIG.pollIntervalMs * 3);
    await flushAsync();

    // fetch was called exactly once (snapshot).
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it("age() returns Infinity before first successful refresh", () => {
    vi.mocked(fetch).mockReturnValue(new Promise(() => undefined));
    const cache = new SessionVersionCache("https://hearth.example.com", "r1", BASE_SV_CONFIG);
    cache.start();
    expect(cache.age()).toBe(Number.POSITIVE_INFINITY);
    cache.stop();
  });
});

// ---------------------------------------------------------------------------
// createHearth() integration — sv check wired into hasPermission etc.
// ---------------------------------------------------------------------------

describe("createHearth() with sessionVersions", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("hasPermission passes when sv is valid", async () => {
    mockFetch(snapshotResponse({ sess_01: 1 }));

    let token = forgeJwt({ permissions: ["docs.read"], sv: 1, sid: "sess_01" });
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => token,
      sessionVersions: BASE_SV_CONFIG,
    });
    await flushAsync();

    expect(hearth.hasPermission("docs.read")).toBe(true);
    hearth.stop();
  });

  it("hasPermission throws SessionVersionRevokedError when sv < minSv", async () => {
    mockFetch(snapshotResponse({ sess_01: 5 })); // min is 5

    const token = forgeJwt({ permissions: ["docs.read"], sv: 3, sid: "sess_01" });
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => token,
      sessionVersions: BASE_SV_CONFIG,
    });
    await flushAsync();

    expect(() => hearth.hasPermission("docs.read")).toThrow(SessionVersionRevokedError);
    hearth.stop();
  });

  it("hasPermission passes when token has no sv claim (backward compat)", async () => {
    mockFetch(snapshotResponse({ sess_01: 5 }));

    const token = forgeJwt({ permissions: ["docs.read"] }); // no sv
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => token,
      sessionVersions: BASE_SV_CONFIG,
    });
    await flushAsync();

    expect(hearth.hasPermission("docs.read")).toBe(true);
    hearth.stop();
  });

  it("hasPermission throws SessionVersionCacheStaleError when cache is stale", async () => {
    mockFetch(snapshotResponse({ sess_01: 1 }));

    const token = forgeJwt({ permissions: ["docs.read"], sv: 1, sid: "sess_01" });
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => token,
      sessionVersions: BASE_SV_CONFIG,
    });
    await flushAsync();

    vi.advanceTimersByTime(BASE_SV_CONFIG.staleThresholdMs + 1_000);

    expect(() => hearth.hasPermission("docs.read")).toThrow(SessionVersionCacheStaleError);
    hearth.stop();
  });

  it("hasRole, inGroup, inOrg also validate sv", async () => {
    mockFetch(snapshotResponse({ sess_01: 3 }));

    const token = forgeJwt({
      roles: ["admin"],
      groups: ["eng"],
      oid: "org_1",
      sv: 2, // below minSv=3
      sid: "sess_01",
    });
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => token,
      sessionVersions: BASE_SV_CONFIG,
    });
    await flushAsync();

    expect(() => hearth.hasRole("admin")).toThrow(SessionVersionRevokedError);
    expect(() => hearth.inGroup("eng")).toThrow(SessionVersionRevokedError);
    expect(() => hearth.inOrg("org_1")).toThrow(SessionVersionRevokedError);
    hearth.stop();
  });

  it("sessionVersionCacheAge() returns Infinity when sessionVersions not configured", () => {
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => null,
    });
    expect(hearth.sessionVersionCacheAge()).toBe(Number.POSITIVE_INFINITY);
    hearth.stop();
  });

  it("sessionVersionCacheAge() returns a finite value after snapshot is loaded", async () => {
    mockFetch(snapshotResponse({}));
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => null,
      sessionVersions: BASE_SV_CONFIG,
    });
    await flushAsync();

    expect(hearth.sessionVersionCacheAge()).toBeLessThan(1_000);
    hearth.stop();
  });

  it("no sv check when sessionVersions.enabled is false", () => {
    // No fetch mock — any network call would throw.
    const token = forgeJwt({ permissions: ["docs.read"], sv: 99, sid: "sess_X" });
    const hearth = createHearth({
      baseUrl: "https://hearth.example.com",
      realmId: "r1",
      getToken: () => token,
      sessionVersions: { ...BASE_SV_CONFIG, enabled: false },
    });
    expect(hearth.hasPermission("docs.read")).toBe(true);
    hearth.stop();
  });
});
