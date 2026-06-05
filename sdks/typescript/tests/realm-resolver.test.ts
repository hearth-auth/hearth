// Tests for realm slug↔UUID auto-resolution (HEA-1307).
// Written before implementation — confirm red before green.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  _clearRealmCache,
  looksLikeUuid,
  resolveRealm,
  resolveRealmId,
} from "../src/realm-resolver.js";
import { RealmResolutionError } from "../src/errors.js";

const BASE = "http://localhost:8420";
const REALM_UUID = "550e8400-e29b-41d4-a716-446655440000";
const REALM_SLUG = "acme";
const REALM_DOC = { id: REALM_UUID, slug: REALM_SLUG, name: "Acme Corp" };

function mockFetch(status: number, body: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
    }),
  );
}

beforeEach(() => {
  _clearRealmCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── looksLikeUuid ────────────────────────────────────────────────────────────

describe("looksLikeUuid", () => {
  it("returns true for a lowercase UUID v4", () => {
    expect(looksLikeUuid("550e8400-e29b-41d4-a716-446655440000")).toBe(true);
  });

  it("returns true for an uppercase UUID", () => {
    expect(looksLikeUuid("550E8400-E29B-41D4-A716-446655440000")).toBe(true);
  });

  it("returns false for a slug", () => {
    expect(looksLikeUuid("my-realm")).toBe(false);
  });

  it("returns false for an empty string", () => {
    expect(looksLikeUuid("")).toBe(false);
  });

  it("returns false for a UUID with extra characters", () => {
    expect(looksLikeUuid("550e8400-e29b-41d4-a716-446655440000-extra")).toBe(
      false,
    );
  });
});

// ─── resolveRealmId — fast path ───────────────────────────────────────────────

describe("resolveRealmId — UUID fast path", () => {
  it("returns UUID immediately without a fetch call", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const result = await resolveRealmId(BASE, REALM_UUID, 5_000);

    expect(result).toBe(REALM_UUID);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

// ─── resolveRealmId — slug resolution ─────────────────────────────────────────

describe("resolveRealmId — slug resolution", () => {
  it("fetches /v1/realms/{slug} and returns the UUID", async () => {
    mockFetch(200, REALM_DOC);

    const result = await resolveRealmId(BASE, REALM_SLUG, 5_000);

    expect(result).toBe(REALM_UUID);
    const fetchMock = vi.mocked(globalThis.fetch);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0]).toContain(`/v1/realms/${REALM_SLUG}`);
  });

  it("caches the result — second call does not fetch again", async () => {
    mockFetch(200, REALM_DOC);

    await resolveRealmId(BASE, REALM_SLUG, 5_000);
    await resolveRealmId(BASE, REALM_SLUG, 5_000);

    expect(vi.mocked(globalThis.fetch)).toHaveBeenCalledOnce();
  });

  it("cache is keyed per baseUrl — different instances do not share entries", async () => {
    mockFetch(200, REALM_DOC);

    await resolveRealmId(BASE, REALM_SLUG, 5_000);
    await resolveRealmId("http://other:8420", REALM_SLUG, 5_000);

    expect(vi.mocked(globalThis.fetch)).toHaveBeenCalledTimes(2);
  });

  it("after slug→UUID resolution, UUID lookup hits cache without another fetch", async () => {
    mockFetch(200, REALM_DOC);

    // First: resolve by slug
    await resolveRealmId(BASE, REALM_SLUG, 5_000);
    vi.clearAllMocks();

    // Second: resolve by UUID — should be a cache hit
    const result = await resolveRealmId(BASE, REALM_UUID, 5_000);
    expect(result).toBe(REALM_UUID);
    // UUID fast path — no fetch regardless of cache
    expect(vi.mocked(globalThis.fetch)).not.toHaveBeenCalled();
  });
});

// ─── resolveRealm — error cases ───────────────────────────────────────────────

describe("resolveRealm — error cases", () => {
  it("throws RealmResolutionError when the endpoint returns 404", async () => {
    mockFetch(404, { error: "not_found" });

    await expect(
      resolveRealm(BASE, REALM_SLUG, 5_000),
    ).rejects.toBeInstanceOf(RealmResolutionError);
  });

  it("throws RealmResolutionError when the endpoint is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("fetch failed")),
    );

    await expect(
      resolveRealm(BASE, REALM_SLUG, 5_000),
    ).rejects.toBeInstanceOf(RealmResolutionError);
  });

  it("throws RealmResolutionError when the response is missing `id`", async () => {
    mockFetch(200, { slug: REALM_SLUG });

    await expect(
      resolveRealm(BASE, REALM_SLUG, 5_000),
    ).rejects.toBeInstanceOf(RealmResolutionError);
  });

  it("throws RealmResolutionError when the response is missing `slug`", async () => {
    mockFetch(200, { id: REALM_UUID });

    await expect(
      resolveRealm(BASE, REALM_SLUG, 5_000),
    ).rejects.toBeInstanceOf(RealmResolutionError);
  });

  it("throws RealmResolutionError when the response JSON is invalid", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.reject(new SyntaxError("bad json")),
      }),
    );

    await expect(
      resolveRealm(BASE, REALM_SLUG, 5_000),
    ).rejects.toBeInstanceOf(RealmResolutionError);
  });
});

// ─── createHearth integration — realm as string ───────────────────────────────

import { createHearth } from "../src/hearth.js";

describe("createHearth — realm as string (integration smoke)", () => {
  it("accepts realm as a plain UUID string", () => {
    const h = createHearth({ baseUrl: BASE, realm: REALM_UUID });
    expect(h.getToken()).toBeNull();
  });

  it("accepts realm as a plain slug string", () => {
    const h = createHearth({ baseUrl: BASE, realm: REALM_SLUG });
    expect(typeof h.setToken).toBe("function");
  });

  it("accepts realm as HearthRealmConfig with id only", () => {
    const h = createHearth({ baseUrl: BASE, realm: { id: REALM_UUID } });
    expect(h.getToken()).toBeNull();
  });

  it("accepts realm as HearthRealmConfig with slug only", () => {
    const h = createHearth({ baseUrl: BASE, realm: { slug: REALM_SLUG } });
    expect(typeof h.setToken).toBe("function");
  });

  it("realm as slug resolves UUID on first permissions() call", async () => {
    mockFetch(200, REALM_DOC);

    const h = createHearth({ baseUrl: BASE, realm: REALM_SLUG });

    // stub permissions endpoint after realm resolution
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        // first call: realm resolution
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve(REALM_DOC),
        })
        // second call: permissions
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve({ roles: [], groups: [], permissions: [], scope: "" }),
        }),
    );

    h.setToken("dummy-token");
    const perms = await h.client.permissions();
    expect(perms.roles).toEqual([]);
    // Verify the permissions request carried the resolved realm UUID header
    const calls = vi.mocked(globalThis.fetch).mock.calls;
    const permCall = calls.find((c) =>
      String(c[0]).includes("/v1/me/permissions"),
    );
    expect(permCall).toBeDefined();
    const headers = permCall![1]?.headers as Record<string, string>;
    expect(headers["X-Realm-ID"]).toBe(REALM_UUID);
  });
});
