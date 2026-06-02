import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HearthClient } from "../src/hearth-client.js";
import {
  ConfigurationError,
  AuthorizationModeMismatchError,
} from "../src/errors.js";
import { requirePermission } from "../src/middleware.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function forgeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const sig = Buffer.from("not-a-real-signature").toString("base64url");
  return `${header}.${body}.${sig}`;
}

const DISCOVERY_DOC = {
  issuer: "https://auth.example.com",
  jwks_uri: "https://auth.example.com/jwks",
  introspection_endpoint: "https://auth.example.com/introspect",
};

function mockFetch(body: unknown, status = 200): void {
  vi.mocked(fetch).mockResolvedValueOnce(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

// ---------------------------------------------------------------------------
// HearthClient.authorize()
// ---------------------------------------------------------------------------

describe("HearthClient.authorize()", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws ConfigurationError when realmId is absent", async () => {
    const client = new HearthClient({ issuerUrl: "https://auth.example.com" });
    await expect(
      client.authorize("tok", "docs.read"),
    ).rejects.toThrow(ConfigurationError);
  });

  it("calls POST /oauth/authorize with correct headers and body", async () => {
    mockFetch({ allowed: true });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    await client.authorize("my-token", "docs.read");
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      "https://auth.example.com/oauth/authorize",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-Realm-ID": "realm_1",
          Authorization: "Bearer my-token",
        }),
      }),
    );
  });

  it("returns true when the server returns allowed: true", async () => {
    mockFetch({ allowed: true });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    expect(await client.authorize("tok", "docs.read")).toBe(true);
  });

  it("returns false when the server returns allowed: false", async () => {
    mockFetch({ allowed: false });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    expect(await client.authorize("tok", "docs.read")).toBe(false);
  });

  it("is fail-closed: returns false on HTTP 500", async () => {
    mockFetch({ error: "internal" }, 500);
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    expect(await client.authorize("tok", "docs.read")).toBe(false);
  });

  it("is fail-closed: returns false on network error", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    expect(await client.authorize("tok", "docs.read")).toBe(false);
  });

  it("passes organizationId and resource in the request body", async () => {
    mockFetch({ allowed: true });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    await client.authorize("tok", "docs.write", {
      organizationId: "org_42",
      resource: "doc:abc",
    });
    const call = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(call[1]?.body as string);
    expect(body).toMatchObject({
      permission: "docs.write",
      organization_id: "org_42",
      resource: "doc:abc",
    });
  });

  it("omits organizationId/resource when not provided", async () => {
    mockFetch({ allowed: true });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    await client.authorize("tok", "docs.read");
    const call = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(call[1]?.body as string);
    expect(body).not.toHaveProperty("organization_id");
    expect(body).not.toHaveProperty("resource");
  });
});

// ---------------------------------------------------------------------------
// HearthClient.introspect() — mode echo validation
// ---------------------------------------------------------------------------

describe("HearthClient.introspect()", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns the introspection result when no expectedMode is configured", async () => {
    // discovery + introspect
    mockFetch(DISCOVERY_DOC);
    mockFetch({ active: true, sub: "user_1", mode: "embedded" });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
    });
    const result = await client.introspect("tok");
    expect(result.active).toBe(true);
    expect(result.sub).toBe("user_1");
  });

  it("returns the result when mode matches expectedMode", async () => {
    mockFetch(DISCOVERY_DOC);
    mockFetch({ active: true, mode: "introspection", permissions: ["x.read"] });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
      expectedMode: "introspection",
    });
    const result = await client.introspect("tok");
    expect(result.active).toBe(true);
  });

  it("throws AuthorizationModeMismatchError when echoed mode differs from expectedMode", async () => {
    mockFetch(DISCOVERY_DOC);
    mockFetch({ active: true, mode: "embedded" });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
      expectedMode: "introspection",
    });
    await expect(client.introspect("tok")).rejects.toThrow(
      AuthorizationModeMismatchError,
    );
  });

  it("skips mode validation when the response has no mode field", async () => {
    mockFetch(DISCOVERY_DOC);
    mockFetch({ active: true, sub: "user_1" });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
      expectedMode: "introspection",
    });
    const result = await client.introspect("tok");
    expect(result.active).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// requirePermission() — embedded mode
// ---------------------------------------------------------------------------

describe("requirePermission() — embedded mode", () => {
  const client = new HearthClient({ issuerUrl: "https://auth.example.com" });

  it("returns true when JWT permissions claim contains the permission", async () => {
    const token = forgeJwt({ permissions: ["docs.read", "docs.write"] });
    const check = requirePermission("docs.read", { mode: "embedded", client });
    expect(await check(token)).toBe(true);
  });

  it("returns false when permission is absent from claims", async () => {
    const token = forgeJwt({ permissions: ["docs.write"] });
    const check = requirePermission("docs.read", { mode: "embedded", client });
    expect(await check(token)).toBe(false);
  });

  it("returns false when the permissions claim is missing entirely", async () => {
    const token = forgeJwt({ sub: "user_1" });
    const check = requirePermission("docs.read", { mode: "embedded", client });
    expect(await check(token)).toBe(false);
  });

  it("does NOT fall back to network when permissions claim is absent (design constraint)", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const token = forgeJwt({ sub: "user_1" }); // no permissions claim
    const check = requirePermission("docs.read", { mode: "embedded", client });
    await check(token);
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// requirePermission() — decision mode
// ---------------------------------------------------------------------------

describe("requirePermission() — decision mode", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls /oauth/authorize and returns true when allowed", async () => {
    mockFetch({ allowed: true });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    const check = requirePermission("docs.write", { mode: "decision", client });
    expect(await check("my-token")).toBe(true);
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      "https://auth.example.com/oauth/authorize",
      expect.anything(),
    );
  });

  it("returns false when /oauth/authorize returns allowed: false", async () => {
    mockFetch({ allowed: false });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    const check = requirePermission("docs.write", { mode: "decision", client });
    expect(await check("tok")).toBe(false);
  });

  it("is fail-closed on network error", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error("network failure"));
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    const check = requirePermission("docs.write", { mode: "decision", client });
    expect(await check("tok")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// requirePermission() — introspection mode
// ---------------------------------------------------------------------------

describe("requirePermission() — introspection mode", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls /introspect and returns true when permission is in result", async () => {
    mockFetch(DISCOVERY_DOC);
    mockFetch({
      active: true,
      mode: "introspection",
      permissions: ["docs.read"],
    });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
    });
    const check = requirePermission("docs.read", {
      mode: "introspection",
      client,
    });
    expect(await check("tok")).toBe(true);
  });

  it("returns false when permission is absent from introspection result", async () => {
    mockFetch(DISCOVERY_DOC);
    mockFetch({ active: true, mode: "introspection", permissions: ["other"] });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
    });
    const check = requirePermission("docs.read", {
      mode: "introspection",
      client,
    });
    expect(await check("tok")).toBe(false);
  });

  it("returns false when token is inactive", async () => {
    mockFetch(DISCOVERY_DOC);
    mockFetch({ active: false });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
    });
    const check = requirePermission("docs.read", {
      mode: "introspection",
      client,
    });
    expect(await check("tok")).toBe(false);
  });

  it("throws AuthorizationModeMismatchError when server echoes wrong mode", async () => {
    mockFetch(DISCOVERY_DOC);
    // Server returns "embedded" but middleware expects "introspection"
    mockFetch({ active: true, mode: "embedded", permissions: ["docs.read"] });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
    });
    const check = requirePermission("docs.read", {
      mode: "introspection",
      client,
    });
    await expect(check("tok")).rejects.toThrow(AuthorizationModeMismatchError);
  });

  it("accepts result when mode field is absent (server may omit it)", async () => {
    mockFetch(DISCOVERY_DOC);
    mockFetch({ active: true, permissions: ["docs.read"] });
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "cid",
      clientSecret: "csec",
    });
    const check = requirePermission("docs.read", {
      mode: "introspection",
      client,
    });
    expect(await check("tok")).toBe(true);
  });
});
