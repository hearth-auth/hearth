import { describe, it, expect, vi, afterEach } from "vitest";
import { AuthorizeClient } from "./authorize.js";
import type { ResolvedConfig } from "./config.js";

const CONFIG: ResolvedConfig = {
  issuer_url: "https://auth.example.com",
  client_id: "client1",
  client_secret: "secret1",
  audience: [],
  jwks_ttl: 300_000,
  introspection_endpoint: "https://auth.example.com/introspect",
  authorize_endpoint: "https://auth.example.com/oauth/authorize",
  realm_id: "11111111-1111-1111-1111-111111111111",
  http_timeout: 10_000,
  clock_skew_seconds: 60,
};

function makeClient(overrides: Partial<ResolvedConfig> = {}): AuthorizeClient {
  return new AuthorizeClient({ ...CONFIG, ...overrides });
}

describe("AuthorizeClient", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns allowed=true when server grants permission", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true }),
    } as Response);
    const result = await makeClient().decide("tok123", "docs.write");
    expect(result.allowed).toBe(true);
  });

  it("returns allowed=false when server denies permission", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: false }),
    } as Response);
    const result = await makeClient().decide("tok123", "docs.write");
    expect(result.allowed).toBe(false);
  });

  it("sends Authorization header with Bearer token and X-Realm-ID", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true }),
    } as Response);
    await makeClient().decide("mytoken", "files.delete");
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe("https://auth.example.com/oauth/authorize");
    const headers = init?.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer mytoken");
    expect(headers["X-Realm-ID"]).toBe("11111111-1111-1111-1111-111111111111");
  });

  it("sends permission in request body", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: false }),
    } as Response);
    await makeClient().decide("tok", "users.admin");
    const body = JSON.parse(spy.mock.calls[0][1]?.body as string);
    expect(body.permission).toBe("users.admin");
  });

  it("passes optional organization_id and resource", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true }),
    } as Response);
    await makeClient().decide("tok", "docs.read", {
      organization_id: "org_abc",
      resource: "https://api.example.com",
    });
    const body = JSON.parse(spy.mock.calls[0][1]?.body as string);
    expect(body.organization_id).toBe("org_abc");
    expect(body.resource).toBe("https://api.example.com");
  });

  it("fail-closed: returns allowed=false on network error (does not throw)", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await makeClient().decide("tok", "docs.write");
    expect(result.allowed).toBe(false);
  });

  it("fail-closed: returns allowed=false on non-OK HTTP response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 502,
    } as Response);
    const result = await makeClient().decide("tok", "docs.write");
    expect(result.allowed).toBe(false);
  });

  it("falls back to {issuer_url}/oauth/authorize when authorize_endpoint is null", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true }),
    } as Response);
    const client = makeClient({ authorize_endpoint: null });
    await client.decide("tok", "perm");
    expect(spy.mock.calls[0][0]).toBe("https://auth.example.com/oauth/authorize");
  });
});
