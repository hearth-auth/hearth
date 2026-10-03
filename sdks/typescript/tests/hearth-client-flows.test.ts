/**
 * HearthClient — authorization-code, refresh, userinfo, live-permission and
 * session-version-feed calls (ported from the Node SDK's flows/client tests).
 */

import { createHash } from "node:crypto";
import { describe, it, expect, vi, afterEach } from "vitest";
import { HearthClient } from "../src/hearth-client.js";
import { ConfigurationError, DiscoveryError, OAuthFlowError } from "../src/errors.js";

const ISSUER = "https://auth.example.com";
const REALM_ID = "11111111-1111-1111-1111-111111111111";

const DISCOVERY = {
  issuer: ISSUER,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  token_endpoint: `${ISSUER}/token`,
  authorization_endpoint: `${ISSUER}/authorize`,
  userinfo_endpoint: `${ISSUER}/userinfo`,
};

const TOKEN_RESPONSE = {
  access_token: "access-token-value",
  token_type: "Bearer",
  expires_in: 3600,
  scope: "openid",
};

function json(body: unknown, status = 200): Response {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Stub fetch: discovery requests answer `discovery`; every other request is
 * answered by the next entry in `responses` (the last one repeats).
 */
function stubFetch(responses: Array<Response | Error>, discovery: unknown = DISCOVERY) {
  let i = 0;
  const spy = vi.fn((url: string | URL, _init?: RequestInit) => {
    if (String(url).endsWith("/.well-known/openid-configuration")) {
      return Promise.resolve(json(discovery));
    }
    const next = responses[Math.min(i++, responses.length - 1)];
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next.clone());
  });
  vi.stubGlobal("fetch", spy);
  return spy;
}

/** The calls made to anything other than the discovery endpoint. */
function apiCalls(spy: ReturnType<typeof stubFetch>): Array<[string, RequestInit]> {
  return spy.mock.calls
    .map(([url, init]) => [String(url), (init ?? {}) as RequestInit] as [string, RequestInit])
    .filter(([url]) => !url.endsWith("/.well-known/openid-configuration"));
}

function headersOf(init: RequestInit): Headers {
  return new Headers(init.headers);
}

function makeClient(overrides: Partial<ConstructorParameters<typeof HearthClient>[0]> = {}) {
  return new HearthClient({
    issuerUrl: ISSUER,
    clientId: "client1",
    clientSecret: "secret1",
    realmId: REALM_ID,
    ...overrides,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── exchangeCode ───────────────────────────────────────────────────────────

describe("HearthClient.exchangeCode()", () => {
  it("POSTs an authorization_code grant to the discovered token_endpoint", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    await makeClient().exchangeCode("auth-code-123", "https://app.example.com/callback");

    const [[url, init]] = apiCalls(spy);
    expect(url).toBe(DISCOVERY.token_endpoint);
    expect(init.method).toBe("POST");
    expect(headersOf(init).get("Content-Type")).toBe("application/x-www-form-urlencoded");
    const body = new URLSearchParams(init.body as string);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("auth-code-123");
    expect(body.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(body.get("client_id")).toBe("client1");
    expect(body.get("client_secret")).toBe("secret1");
    expect(url).not.toContain("auth-code-123");
  });

  it("includes code_verifier when provided", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    await makeClient().exchangeCode("code", "https://app.example.com/cb", {
      codeVerifier: "v3rif1er",
    });
    const body = new URLSearchParams(apiCalls(spy)[0][1].body as string);
    expect(body.get("code_verifier")).toBe("v3rif1er");
  });

  it("omits client_secret for a public client", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    await makeClient({ clientSecret: undefined }).exchangeCode("code", "https://app/cb", {
      codeVerifier: "v",
    });
    const body = new URLSearchParams(apiCalls(spy)[0][1].body as string);
    expect(body.get("client_id")).toBe("client1");
    expect(body.has("client_secret")).toBe(false);
  });

  it("returns the TokenResponse from the server", async () => {
    stubFetch([json(TOKEN_RESPONSE)]);
    const result = await makeClient().exchangeCode("code", "https://app.example.com/cb");
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
    expect(result.token_type).toBe("Bearer");
    expect(result.expires_in).toBe(3600);
  });

  it("throws OAuthFlowError carrying the status and OAuth error code on non-2xx", async () => {
    stubFetch([json({ error: "invalid_grant", error_description: "code already used" }, 400)]);
    const err = await makeClient()
      .exchangeCode("bad-code", "https://app.example.com/cb")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthFlowError);
    expect((err as OAuthFlowError).statusCode).toBe(400);
    expect((err as OAuthFlowError).errorCode).toBe("invalid_grant");
    expect((err as OAuthFlowError).message).toContain("code already used");
  });

  it("maps a network failure to OAuthFlowError with statusCode 0", async () => {
    stubFetch([new TypeError("fetch failed")]);
    const err = await makeClient()
      .exchangeCode("code", "https://app.example.com/cb")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthFlowError);
    expect((err as OAuthFlowError).statusCode).toBe(0);
  });

  it("sends an abort signal so the httpTimeout applies", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    await makeClient({ httpTimeout: 1234 }).exchangeCode("code", "https://app/cb");
    expect(apiCalls(spy)[0][1].signal).toBeInstanceOf(AbortSignal);
  });

  it("throws ConfigurationError when clientId is not configured", async () => {
    stubFetch([json(TOKEN_RESPONSE)]);
    await expect(
      makeClient({ clientId: undefined }).exchangeCode("code", "https://app/cb"),
    ).rejects.toBeInstanceOf(ConfigurationError);
  });
});

// ── refreshTokens ──────────────────────────────────────────────────────────

describe("HearthClient.refreshTokens()", () => {
  it("POSTs a refresh_token grant with credentials in the body, never the URL", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    await makeClient().refreshTokens("refresh-token-abc");

    const [[url, init]] = apiCalls(spy);
    expect(url).toBe(DISCOVERY.token_endpoint);
    expect(init.method).toBe("POST");
    const body = new URLSearchParams(init.body as string);
    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("refresh_token")).toBe("refresh-token-abc");
    expect(body.get("client_id")).toBe("client1");
    expect(body.get("client_secret")).toBe("secret1");
    expect(url).not.toContain("refresh-token-abc");
  });

  it("includes scope when provided", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    await makeClient().refreshTokens("rt", "openid profile");
    const body = new URLSearchParams(apiCalls(spy)[0][1].body as string);
    expect(body.get("scope")).toBe("openid profile");
  });

  it("omits scope when not provided", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    await makeClient().refreshTokens("rt");
    const body = new URLSearchParams(apiCalls(spy)[0][1].body as string);
    expect(body.get("scope")).toBeNull();
  });

  it("returns the rotated refresh_token", async () => {
    stubFetch([json({ ...TOKEN_RESPONSE, refresh_token: "rotated-rt" })]);
    const result = await makeClient().refreshTokens("rt");
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
    expect(result.refresh_token).toBe("rotated-rt");
  });

  it("throws OAuthFlowError on non-2xx (revoked or expired refresh token)", async () => {
    stubFetch([json({ error: "invalid_grant" }, 400)]);
    await expect(makeClient().refreshTokens("revoked")).rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── beginLogin / completeLogin ─────────────────────────────────────────────

describe("HearthClient.beginLogin()", () => {
  it("returns an authorizationUrl whose code_challenge is S256(codeVerifier)", async () => {
    stubFetch([]);
    const result = await makeClient().beginLogin("https://app.example.com/callback");
    const url = new URL(result.authorizationUrl);
    const expected = createHash("sha256").update(result.codeVerifier).digest("base64url");
    expect(url.searchParams.get("code_challenge")).toBe(expected);
  });

  it("returns a non-empty state that appears in the URL", async () => {
    stubFetch([]);
    const result = await makeClient().beginLogin("https://app.example.com/callback");
    expect(result.state.length).toBeGreaterThanOrEqual(16);
    expect(new URL(result.authorizationUrl).searchParams.get("state")).toBe(result.state);
  });

  it("targets the discovered authorization_endpoint with PKCE and client params", async () => {
    stubFetch([]);
    const result = await makeClient().beginLogin(
      "https://app.example.com/callback",
      "openid profile",
    );
    const url = new URL(result.authorizationUrl);
    expect(`${url.origin}${url.pathname}`).toBe(DISCOVERY.authorization_endpoint);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("client1");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(url.searchParams.get("scope")).toBe("openid profile");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("defaults scope to openid", async () => {
    stubFetch([]);
    const result = await makeClient().beginLogin("https://app.example.com/callback");
    expect(new URL(result.authorizationUrl).searchParams.get("scope")).toBe("openid");
  });

  it("generates a fresh verifier and state per call", async () => {
    stubFetch([]);
    const client = makeClient();
    const a = await client.beginLogin("https://app/cb");
    const b = await client.beginLogin("https://app/cb");
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.state).not.toBe(b.state);
  });

  it("throws ConfigurationError when authorization_endpoint is absent from discovery", async () => {
    stubFetch([], { ...DISCOVERY, authorization_endpoint: undefined });
    await expect(makeClient().beginLogin("https://app/cb")).rejects.toBeInstanceOf(
      ConfigurationError,
    );
  });
});

describe("HearthClient.completeLogin()", () => {
  it("exchanges the code with the supplied codeVerifier", async () => {
    const spy = stubFetch([json(TOKEN_RESPONSE)]);
    const result = await makeClient().completeLogin(
      "auth-code-xyz",
      "my-verifier-abc",
      "https://app.example.com/callback",
    );
    const body = new URLSearchParams(apiCalls(spy)[0][1].body as string);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("auth-code-xyz");
    expect(body.get("code_verifier")).toBe("my-verifier-abc");
    expect(body.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(result.access_token).toBe(TOKEN_RESPONSE.access_token);
  });
});

// ── userinfo ───────────────────────────────────────────────────────────────

describe("HearthClient.userinfo()", () => {
  it("GETs the discovered userinfo_endpoint with the bearer token", async () => {
    const spy = stubFetch([json({ sub: "user123", email: "user@example.com", locale: "en" })]);
    const result = await makeClient().userinfo("access-token-xyz");

    const [[url, init]] = apiCalls(spy);
    expect(url).toBe(DISCOVERY.userinfo_endpoint);
    expect(headersOf(init).get("Authorization")).toBe("Bearer access-token-xyz");
    expect(result.sub).toBe("user123");
    expect(result["locale"]).toBe("en");
  });

  it("throws OAuthFlowError on non-2xx", async () => {
    stubFetch([json({ error: "invalid_token" }, 401)]);
    const err = await makeClient()
      .userinfo("bad-token")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthFlowError);
    expect((err as OAuthFlowError).statusCode).toBe(401);
  });

  it("throws ConfigurationError when userinfo_endpoint is absent from discovery", async () => {
    stubFetch([], { ...DISCOVERY, userinfo_endpoint: undefined });
    await expect(makeClient().userinfo("tok")).rejects.toBeInstanceOf(ConfigurationError);
  });
});

// ── mePermissions ──────────────────────────────────────────────────────────

describe("HearthClient.mePermissions()", () => {
  it("GETs /v1/me/permissions with the bearer token and X-Realm-ID", async () => {
    const perms = { roles: ["admin"], groups: ["eng"], permissions: ["docs.write"], scope: "x" };
    const spy = stubFetch([json(perms)]);
    const result = await makeClient().mePermissions("access-token-xyz");

    const [[url, init]] = apiCalls(spy);
    expect(url).toBe(`${ISSUER}/v1/me/permissions`);
    expect(headersOf(init).get("Authorization")).toBe("Bearer access-token-xyz");
    expect(headersOf(init).get("X-Realm-ID")).toBe(REALM_ID);
    expect(result.roles).toEqual(["admin"]);
    expect(result.permissions).toEqual(["docs.write"]);
  });

  it("throws ConfigurationError when realmId is not configured", async () => {
    stubFetch([json({})]);
    await expect(makeClient({ realmId: undefined }).mePermissions("tok")).rejects.toBeInstanceOf(
      ConfigurationError,
    );
  });

  it("throws OAuthFlowError on non-2xx", async () => {
    stubFetch([json({ error: "invalid_token" }, 401)]);
    await expect(makeClient().mePermissions("tok")).rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── session-version feed ───────────────────────────────────────────────────

describe("HearthClient.svSnapshot()", () => {
  it("GETs /oauth/session-versions/snapshot with the bearer token and X-Realm-ID", async () => {
    const snap = { realm: "test-realm", current_seq: 42, versions: { "sess-1": 3 } };
    const spy = stubFetch([json(snap)]);
    const result = await makeClient().svSnapshot("service-token");

    const [[url, init]] = apiCalls(spy);
    expect(url).toBe(`${ISSUER}/oauth/session-versions/snapshot`);
    expect(headersOf(init).get("Authorization")).toBe("Bearer service-token");
    expect(headersOf(init).get("X-Realm-ID")).toBe(REALM_ID);
    expect(result.current_seq).toBe(42);
    expect(result.versions["sess-1"]).toBe(3);
  });

  it("throws ConfigurationError when realmId is not configured", async () => {
    stubFetch([json({})]);
    await expect(makeClient({ realmId: undefined }).svSnapshot("tok")).rejects.toBeInstanceOf(
      ConfigurationError,
    );
  });
});

describe("HearthClient.svDelta()", () => {
  it("GETs /oauth/session-versions with the since param", async () => {
    const spy = stubFetch([json({ realm: "r", next_seq: 10, deltas: [] })]);
    const result = await makeClient().svDelta("service-token", 5);

    const [[url, init]] = apiCalls(spy);
    const parsed = new URL(url);
    expect(`${parsed.origin}${parsed.pathname}`).toBe(`${ISSUER}/oauth/session-versions`);
    expect(parsed.searchParams.get("since")).toBe("5");
    expect(parsed.searchParams.has("limit")).toBe(false);
    expect(headersOf(init).get("X-Realm-ID")).toBe(REALM_ID);
    expect(result?.next_seq).toBe(10);
  });

  it("includes the limit param when provided", async () => {
    const spy = stubFetch([json({ realm: "r", next_seq: 1, deltas: [] })]);
    await makeClient().svDelta("tok", 0, 100);
    expect(new URL(apiCalls(spy)[0][0]).searchParams.get("limit")).toBe("100");
  });

  it("returns null on 204 No Content", async () => {
    stubFetch([new Response(null, { status: 204 })]);
    expect(await makeClient().svDelta("tok", 5)).toBeNull();
  });

  it("throws OAuthFlowError on non-2xx", async () => {
    stubFetch([json({ error: "insufficient_scope" }, 403)]);
    await expect(makeClient().svDelta("tok", 5)).rejects.toBeInstanceOf(OAuthFlowError);
  });
});

// ── discovery caching ──────────────────────────────────────────────────────

describe("HearthClient discovery cache", () => {
  it("deduplicates concurrent discover() calls into one request", async () => {
    const spy = stubFetch([]);
    const client = makeClient();
    const [a, b] = await Promise.all([client.discover(), client.discover()]);
    expect(a).toBe(b);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("retries discovery after a failed attempt instead of caching the failure", async () => {
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        ++calls === 1 ? Promise.reject(new Error("down")) : Promise.resolve(json(DISCOVERY)),
      ),
    );
    const client = makeClient();
    await expect(client.discover()).rejects.toBeInstanceOf(DiscoveryError);
    await expect(client.discover()).resolves.toMatchObject({ issuer: ISSUER });
  });

  it("invalidateCache() forces discovery to be fetched again", async () => {
    const spy = stubFetch([]);
    const client = makeClient();
    await client.discover();
    client.invalidateCache();
    await client.discover();
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("invalidateCache() drops the cached JwksClient and IntrospectionClient", async () => {
    stubFetch([], { ...DISCOVERY, introspection_endpoint: `${ISSUER}/introspect` });
    const client = makeClient();
    const jwks = await client.jwksClient();
    const ic = await client.introspectionClient();
    client.invalidateCache();
    expect(await client.jwksClient()).not.toBe(jwks);
    expect(await client.introspectionClient()).not.toBe(ic);
  });
});
