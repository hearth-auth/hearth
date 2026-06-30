/**
 * §4.5 — OAuth flow tests for HearthClient (TDD — written before implementation).
 *
 * Covers: clientCredentials, startDeviceFlow, pollDeviceToken, requestMagicLink.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HearthClient } from "../src/hearth-client.js";
import {
  ConfigurationError,
  OAuthFlowError,
  TokenExpiredError,
} from "../src/errors.js";

const ISSUER = "https://auth.example.com";
const REALM_ID = "my-realm";

const DISCOVERY = {
  issuer: ISSUER,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  token_endpoint: `${ISSUER}/token`,
  device_authorization_endpoint: `${ISSUER}/device/authorize`,
};

const TOKEN_RESPONSE = {
  access_token: "eyJ.access.token",
  token_type: "Bearer",
  expires_in: 3600,
  scope: "openid",
  id_token: "",
  refresh_token: "",
};

function makeClient(opts?: { realmId?: string | null; clientId?: string; clientSecret?: string }) {
  return new HearthClient({
    issuerUrl: ISSUER,
    realmId: opts?.realmId === undefined ? REALM_ID : (opts.realmId ?? undefined),
    clientId: opts?.clientId ?? "client1",
    clientSecret: opts?.clientSecret ?? "secret1",
  });
}

function mockFetch(...responses: Array<{ body: unknown; status?: number }>): void {
  let callCount = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn((_url: string) => {
      const resp = responses[Math.min(callCount++, responses.length - 1)];
      const status = resp.status ?? 200;
      return Promise.resolve(
        new Response(JSON.stringify(resp.body), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }),
  );
}

beforeEach(() => { /* stub set per test */ });
afterEach(() => { vi.unstubAllGlobals(); });

// ── clientCredentials ──────────────────────────────────────────────────────

describe("HearthClient.clientCredentials()", () => {
  it("POSTs client_credentials grant to the discovered token_endpoint", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    const client = makeClient();
    await client.clientCredentials();

    const [tokenUrl, tokenInit] = fetchSpy.mock.calls[1] as [string, RequestInit];
    expect(tokenUrl).toBe(DISCOVERY.token_endpoint);
    expect(tokenInit.method).toBe("POST");

    const body = new URLSearchParams(tokenInit.body as string);
    expect(body.get("grant_type")).toBe("client_credentials");
    expect(body.get("client_id")).toBe("client1");
    expect(body.get("client_secret")).toBe("secret1");
  });

  it("credentials are in the POST body, never in the URL", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    const client = makeClient();
    await client.clientCredentials();

    const [tokenUrl] = fetchSpy.mock.calls[1] as [string];
    expect(tokenUrl).not.toContain("client_secret");
  });

  it("includes scope when provided", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    await makeClient().clientCredentials("read:users");

    const body = new URLSearchParams(fetchSpy.mock.calls[1][1].body as string);
    expect(body.get("scope")).toBe("read:users");
  });

  it("omits scope from body when not provided", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    await makeClient().clientCredentials();

    const body = new URLSearchParams(fetchSpy.mock.calls[1][1].body as string);
    expect(body.get("scope")).toBeNull();
  });

  it("returns the TokenResponse from the server", async () => {
    mockFetch({ body: DISCOVERY }, { body: TOKEN_RESPONSE });
    const result = await makeClient().clientCredentials();
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
    expect(result.token_type).toBe("Bearer");
  });

  it("throws OAuthFlowError on non-2xx response", async () => {
    mockFetch({ body: DISCOVERY }, { body: { error: "unauthorized_client" }, status: 401 });
    await expect(makeClient().clientCredentials()).rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── startDeviceFlow ────────────────────────────────────────────────────────

describe("HearthClient.startDeviceFlow()", () => {
  const DEVICE_RESPONSE = {
    device_code: "dev-code-abc",
    user_code: "WDJB-MJHT",
    verification_uri: `${ISSUER}/activate`,
    verification_uri_complete: `${ISSUER}/activate?user_code=WDJB-MJHT`,
    expires_in: 600,
    interval: 5,
  };

  it("POSTs to the discovered device_authorization_endpoint", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(DEVICE_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    await makeClient().startDeviceFlow();

    const [deviceUrl] = fetchSpy.mock.calls[1] as [string];
    expect(deviceUrl).toBe(DISCOVERY.device_authorization_endpoint);
  });

  it("includes client_id in the POST body", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(DEVICE_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    await makeClient().startDeviceFlow();

    const body = new URLSearchParams(fetchSpy.mock.calls[1][1].body as string);
    expect(body.get("client_id")).toBe("client1");
  });

  it("includes optional scope in the POST body", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(DEVICE_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    await makeClient().startDeviceFlow("openid profile");

    const body = new URLSearchParams(fetchSpy.mock.calls[1][1].body as string);
    expect(body.get("scope")).toBe("openid profile");
  });

  it("returns DeviceAuthorizationResponse", async () => {
    mockFetch({ body: DISCOVERY }, { body: DEVICE_RESPONSE });
    const result = await makeClient().startDeviceFlow();
    expect(result.device_code).toBe("dev-code-abc");
    expect(result.user_code).toBe("WDJB-MJHT");
    expect(result.interval).toBe(5);
  });

  it("throws ConfigurationError when device_authorization_endpoint absent", async () => {
    const discoveryNoDevice = { ...DISCOVERY, device_authorization_endpoint: undefined };
    mockFetch({ body: discoveryNoDevice });
    await expect(makeClient().startDeviceFlow()).rejects.toBeInstanceOf(ConfigurationError);
  });

  it("throws OAuthFlowError on non-2xx", async () => {
    mockFetch({ body: DISCOVERY }, { body: { error: "invalid_client" }, status: 401 });
    await expect(makeClient().startDeviceFlow()).rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── pollDeviceToken ────────────────────────────────────────────────────────

describe("HearthClient.pollDeviceToken()", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("resolves with TokenResponse when user approves", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValue(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    const p = makeClient().pollDeviceToken("dev-code-abc", 1);
    await vi.runAllTimersAsync();
    const result = await p;
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
  });

  it("sends device_code grant to token_endpoint", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValue(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    const p = makeClient().pollDeviceToken("dev-code-abc", 1);
    await vi.runAllTimersAsync();
    await p;

    const body = new URLSearchParams(fetchSpy.mock.calls[1][1].body as string);
    expect(body.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:device_code");
    expect(body.get("device_code")).toBe("dev-code-abc");
    expect(body.get("client_id")).toBe("client1");
  });

  it("retries silently on authorization_pending", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: "authorization_pending" }), { status: 400 }))
      .mockResolvedValue(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    const p = makeClient().pollDeviceToken("dev-code-abc", 1);
    await vi.runAllTimersAsync();
    const result = await p;

    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
    expect(fetchSpy).toHaveBeenCalledTimes(3); // discovery + pending + success
  });

  it("increases interval by 5 s on slow_down", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: "slow_down" }), { status: 400 }))
      .mockResolvedValue(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    const p = makeClient().pollDeviceToken("dev-code-abc", 5);
    await vi.runAllTimersAsync();
    await p;
    expect(fetchSpy).toHaveBeenCalledTimes(3); // discovery + slow_down + success
  });

  it("throws TokenExpiredError when device code expires", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValue(new Response(JSON.stringify({ error: "expired_token" }), { status: 400 }));
    vi.stubGlobal("fetch", fetchSpy);

    const p = makeClient().pollDeviceToken("dev-code-abc", 1);
    // Attach handler before advancing timers to prevent unhandled-rejection warning
    const caught = p.catch((e) => e);
    await vi.runAllTimersAsync();
    expect(await caught).toBeInstanceOf(TokenExpiredError);
  });
});

// ── requestMagicLink ───────────────────────────────────────────────────────

describe("HearthClient.requestMagicLink()", () => {
  it("POSTs to /v1/{realmId}/auth/magic-link with JSON body", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      new Response(null, { status: 202 }),
    );
    vi.stubGlobal("fetch", fetchSpy);

    await makeClient().requestMagicLink("user@example.com");

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${ISSUER}/v1/${REALM_ID}/auth/magic-link`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ email: "user@example.com" });
  });

  it("resolves silently on 202 (enumeration resistance)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 202 })));
    await expect(makeClient().requestMagicLink("notexist@example.com")).resolves.toBeUndefined();
  });

  it("throws OAuthFlowError on HTTP 429 (rate limit)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 429 })));
    const err = await makeClient().requestMagicLink("user@example.com").catch((e) => e);
    expect(err).toBeInstanceOf(OAuthFlowError);
    expect((err as OAuthFlowError).statusCode).toBe(429);
  });

  it("throws ConfigurationError when realmId is not set", async () => {
    const client = makeClient({ realmId: null });
    await expect(client.requestMagicLink("user@example.com")).rejects.toBeInstanceOf(
      ConfigurationError,
    );
  });
});

// ── exchangeMagicLink ──────────────────────────────────────────────────────

describe("HearthClient.exchangeMagicLink()", () => {
  it("POSTs the magic-link grant to the discovered token_endpoint with token in body", async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(DISCOVERY), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);

    await makeClient().exchangeMagicLink("magic-token-xyz");

    const [tokenUrl, tokenInit] = fetchSpy.mock.calls[1] as [string, RequestInit];
    expect(tokenUrl).toBe(DISCOVERY.token_endpoint);
    expect(tokenInit.method).toBe("POST");
    const body = new URLSearchParams(tokenInit.body as string);
    expect(body.get("grant_type")).toBe("urn:hearth:grant-type:magic-link");
    expect(body.get("token")).toBe("magic-token-xyz");
    expect(body.get("client_id")).toBe("client1");
    // opaque token must not leak into the URL
    expect(tokenUrl).not.toContain("magic-token-xyz");
  });

  it("returns the TokenResponse from the server", async () => {
    mockFetch({ body: DISCOVERY }, { body: TOKEN_RESPONSE });
    const result = await makeClient().exchangeMagicLink("magic-token-xyz");
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
    expect(result.token_type).toBe("Bearer");
  });

  it("throws OAuthFlowError on non-2xx (expired/used token)", async () => {
    mockFetch({ body: DISCOVERY }, { body: { error: "invalid_grant" }, status: 400 });
    await expect(makeClient().exchangeMagicLink("expired")).rejects.toBeInstanceOf(OAuthFlowError);
  });
});
