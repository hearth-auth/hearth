/** §4.5 — OAuthFlowsClient tests (TDD — written before implementation). */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { OAuthFlowsClient } from "./flows.js";
import { ConfigurationError, OAuthFlowError, TokenExpiredError } from "./errors.js";
import type { ResolvedConfig } from "./config.js";
import type { OidcDiscovery } from "./discovery.js";

const BASE_CONFIG: ResolvedConfig = {
  issuer_url: "https://auth.example.com",
  client_id: "client1",
  client_secret: "secret1",
  audience: [],
  jwks_ttl: 300_000,
  introspection_endpoint: null,
  http_timeout: 10_000,
  clock_skew_seconds: 60,
  realm_id: "test-realm",
  authorize_endpoint: null,
};

const DISCOVERY: OidcDiscovery = {
  issuer: "https://auth.example.com",
  jwks_uri: "https://auth.example.com/.well-known/jwks.json",
  token_endpoint: "https://auth.example.com/token",
  device_authorization_endpoint: "https://auth.example.com/device/authorize",
  userinfo_endpoint: "https://auth.example.com/userinfo",
};

const TOKEN_RESPONSE = {
  access_token: "eyJ.access.token",
  token_type: "Bearer",
  expires_in: 3600,
  scope: "openid",
};

function makeClient(configOverrides?: Partial<ResolvedConfig>) {
  const config = { ...BASE_CONFIG, ...configOverrides };
  const getDiscovery = vi.fn<[], Promise<OidcDiscovery>>().mockResolvedValue(DISCOVERY);
  const client = new OAuthFlowsClient(config, getDiscovery);
  return { client, getDiscovery };
}

function mockResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
    headers: new Headers(),
  } as unknown as Response;
}

// ── exchangeCode ─────────────────────────────────────────────────────────────

describe("OAuthFlowsClient.exchangeCode", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("POSTs to discovered token_endpoint with authorization_code grant", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    await client.exchangeCode("auth-code-123", "https://app.example.com/callback");

    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(DISCOVERY.token_endpoint);
    expect(init.method).toBe("POST");
    const body = new URLSearchParams(init.body as string);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("auth-code-123");
    expect(body.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(body.get("client_id")).toBe("client1");
    expect(body.get("client_secret")).toBe("secret1");
  });

  it("includes code_verifier when provided", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    await client.exchangeCode("code", "https://app.example.com/cb", { codeVerifier: "v3rif1er" });

    const body = new URLSearchParams(vi.mocked(fetch).mock.calls[0][1].body as string);
    expect(body.get("code_verifier")).toBe("v3rif1er");
  });

  it("returns a typed TokenResponse", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    const result = await client.exchangeCode("code", "https://app.example.com/cb");
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
    expect(result.token_type).toBe("Bearer");
    expect(result.expires_in).toBe(3600);
  });

  it("throws OAuthFlowError on non-200 response", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse({ error: "invalid_grant" }, 400));

    await expect(client.exchangeCode("bad-code", "https://app.example.com/cb"))
      .rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── clientCredentials ─────────────────────────────────────────────────────────

describe("OAuthFlowsClient.clientCredentials", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("POSTs client_credentials grant with client_id and client_secret in body", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    await client.clientCredentials();

    const body = new URLSearchParams(vi.mocked(fetch).mock.calls[0][1].body as string);
    expect(body.get("grant_type")).toBe("client_credentials");
    expect(body.get("client_id")).toBe("client1");
    expect(body.get("client_secret")).toBe("secret1");
    // credentials must NOT appear in URL
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).not.toContain("client_secret");
  });

  it("includes scope when provided", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    await client.clientCredentials("read:users");

    const body = new URLSearchParams(vi.mocked(fetch).mock.calls[0][1].body as string);
    expect(body.get("scope")).toBe("read:users");
  });

  it("omits scope when not provided", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    await client.clientCredentials();

    const body = new URLSearchParams(vi.mocked(fetch).mock.calls[0][1].body as string);
    expect(body.get("scope")).toBeNull();
  });

  it("returns TokenResponse", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    const result = await client.clientCredentials("openid");
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
  });

  it("throws OAuthFlowError on non-200", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse({ error: "unauthorized_client" }, 401));

    await expect(client.clientCredentials()).rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── startDeviceFlow ───────────────────────────────────────────────────────────

describe("OAuthFlowsClient.startDeviceFlow", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  const DEVICE_RESPONSE = {
    device_code: "dev-code-abc",
    user_code: "WDJB-MJHT",
    verification_uri: "https://auth.example.com/activate",
    verification_uri_complete: "https://auth.example.com/activate?user_code=WDJB-MJHT",
    expires_in: 600,
    interval: 5,
  };

  it("POSTs to discovered device_authorization_endpoint", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(DEVICE_RESPONSE));

    await client.startDeviceFlow();

    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(DISCOVERY.device_authorization_endpoint);
  });

  it("includes client_id and optional scope", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(DEVICE_RESPONSE));

    await client.startDeviceFlow("openid profile");

    const body = new URLSearchParams(vi.mocked(fetch).mock.calls[0][1].body as string);
    expect(body.get("client_id")).toBe("client1");
    expect(body.get("scope")).toBe("openid profile");
  });

  it("returns DeviceAuthorizationResponse", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(DEVICE_RESPONSE));

    const result = await client.startDeviceFlow();
    expect(result.device_code).toBe("dev-code-abc");
    expect(result.user_code).toBe("WDJB-MJHT");
    expect(result.interval).toBe(5);
  });

  it("throws when device_authorization_endpoint not in discovery", async () => {
    const getDiscovery = vi.fn().mockResolvedValue({ ...DISCOVERY, device_authorization_endpoint: undefined });
    const client = new OAuthFlowsClient(BASE_CONFIG, getDiscovery);

    await expect(client.startDeviceFlow()).rejects.toBeInstanceOf(ConfigurationError);
  });
});

// ── pollDeviceToken ───────────────────────────────────────────────────────────

describe("OAuthFlowsClient.pollDeviceToken", () => {
  beforeEach(() => { vi.useFakeTimers(); vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("resolves with TokenResponse when user approves immediately", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValue(mockResponse(TOKEN_RESPONSE));

    const p = client.pollDeviceToken("dev-code-abc", 1);
    await vi.runAllTimersAsync();
    const result = await p;
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
  });

  it("polls again on authorization_pending without surfacing error", async () => {
    const { client } = makeClient();
    vi.mocked(fetch)
      .mockResolvedValueOnce(mockResponse({ error: "authorization_pending" }, 400))
      .mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    const p = client.pollDeviceToken("dev-code-abc", 1);
    await vi.runAllTimersAsync();
    const result = await p;
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
  });

  it("increases interval by 5 s on slow_down", async () => {
    const { client } = makeClient();
    vi.mocked(fetch)
      .mockResolvedValueOnce(mockResponse({ error: "slow_down" }, 400))
      .mockResolvedValueOnce(mockResponse(TOKEN_RESPONSE));

    const p = client.pollDeviceToken("dev-code-abc", 5);
    await vi.runAllTimersAsync();
    await p;
    // Two fetches: slow_down + success
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
  });

  it("throws TokenExpiredError when device code expires", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValue(mockResponse({ error: "expired_token" }, 400));

    // Attach rejection handler BEFORE running timers to avoid unhandled rejection warning.
    const p = client.pollDeviceToken("dev-code-abc", 1);
    const rejection = expect(p).rejects.toBeInstanceOf(TokenExpiredError);
    await vi.runAllTimersAsync();
    await rejection;
  });

  it("sends device_code grant to token endpoint", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValue(mockResponse(TOKEN_RESPONSE));

    const p = client.pollDeviceToken("dev-code-abc", 1);
    await vi.runAllTimersAsync();
    await p;

    const body = new URLSearchParams(vi.mocked(fetch).mock.calls[0][1].body as string);
    expect(body.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:device_code");
    expect(body.get("device_code")).toBe("dev-code-abc");
    expect(body.get("client_id")).toBe("client1");
  });
});

// ── requestMagicLink ──────────────────────────────────────────────────────────

describe("OAuthFlowsClient.requestMagicLink", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("POSTs to /v1/{realm_id}/auth/magic-link with JSON body", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce({ ok: true, status: 202 } as Response);

    await client.requestMagicLink("user@example.com");

    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/v1/test-realm/auth/magic-link");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ email: "user@example.com" });
  });

  it("succeeds silently on 202 (enumeration resistance)", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce({ ok: true, status: 202 } as Response);

    await expect(client.requestMagicLink("notexist@example.com")).resolves.toBeUndefined();
  });

  it("throws OAuthFlowError on HTTP 429 (rate limit)", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce({ ok: false, status: 429 } as Response);

    const err = await client.requestMagicLink("user@example.com").catch((e) => e);
    expect(err).toBeInstanceOf(OAuthFlowError);
    expect((err as OAuthFlowError).statusCode).toBe(429);
  });

  it("throws ConfigurationError when realm_id is not set", async () => {
    const { client } = makeClient({ realm_id: null });

    await expect(client.requestMagicLink("user@example.com"))
      .rejects.toBeInstanceOf(ConfigurationError);
  });
});

// ── userinfo ──────────────────────────────────────────────────────────────────

describe("OAuthFlowsClient.userinfo", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("GETs the discovered userinfo_endpoint with Bearer token", async () => {
    const { client } = makeClient();
    const uiResponse = { sub: "user123", email: "user@example.com" };
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(uiResponse));

    const result = await client.userinfo("access-token-xyz");

    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(DISCOVERY.userinfo_endpoint);
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer access-token-xyz");
    expect(result.sub).toBe("user123");
  });

  it("throws OAuthFlowError on non-200", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse({ error: "invalid_token" }, 401));

    await expect(client.userinfo("bad-token")).rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── mePermissions ─────────────────────────────────────────────────────────────

describe("OAuthFlowsClient.mePermissions", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("GETs /v1/me/permissions with Bearer token", async () => {
    const { client } = makeClient();
    const permResponse = { roles: ["admin"], groups: ["eng"], permissions: ["docs.write"], scope: "openid" };
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(permResponse));

    const result = await client.mePermissions("access-token-xyz");

    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/v1/me/permissions");
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer access-token-xyz");
    expect(result.roles).toEqual(["admin"]);
    expect(result.permissions).toEqual(["docs.write"]);
  });
});

// ── svSnapshot ────────────────────────────────────────────────────────────────

describe("OAuthFlowsClient.svSnapshot", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("GETs /oauth/session-versions/snapshot with Bearer token", async () => {
    const { client } = makeClient();
    const snap = { realm: "test-realm", current_seq: 42, versions: { "sess-1": 3 } };
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(snap));

    const result = await client.svSnapshot("service-token");

    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/oauth/session-versions/snapshot");
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer service-token");
    expect(result.current_seq).toBe(42);
  });
});

// ── svDelta ───────────────────────────────────────────────────────────────────

describe("OAuthFlowsClient.svDelta", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("GETs /oauth/session-versions with since param", async () => {
    const { client } = makeClient();
    const delta = { realm: "test-realm", next_seq: 10, deltas: [] };
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(delta));

    await client.svDelta("service-token", 5);

    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("since=5");
  });

  it("includes limit param when provided", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse({ realm: "r", next_seq: 1, deltas: [] }));

    await client.svDelta("tok", 0, 100);

    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toContain("limit=100");
  });

  it("returns null on 204 No Content", async () => {
    const { client } = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce({ ok: true, status: 204, json: () => Promise.resolve(null) } as unknown as Response);

    const result = await client.svDelta("tok", 5);
    expect(result).toBeNull();
  });
});
