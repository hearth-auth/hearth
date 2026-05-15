import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateCodeVerifier, generateCodeChallenge, generateState } from "./pkce.js";
import { isExpired, parseJwtPayload } from "./tokens.js";
import { memoryStorageAdapter } from "./storage.js";
import { HearthClient } from "./client.js";
import { createAccountConsoleRoute } from "./account-console-route.js";
import {
  HearthError,
  ConfigurationError,
  DiscoveryError,
  TokenExpiredError,
  MiddlewareError,
} from "./errors.js";
import { VerifiedToken } from "./verified-token.js";

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

describe("PKCE helpers", () => {
  it("generates a verifier of correct length", async () => {
    const v = await generateCodeVerifier();
    expect(v.length).toBeGreaterThanOrEqual(40);
    expect(v).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("challenge is base64url-encoded SHA-256 of verifier", async () => {
    const verifier = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(challenge.length).toBe(43);
  });

  it("generates unique states", () => {
    const s1 = generateState();
    const s2 = generateState();
    expect(s1).not.toBe(s2);
  });
});

// ---------------------------------------------------------------------------
// Token utilities
// ---------------------------------------------------------------------------

describe("isExpired", () => {
  it("returns true when token is past expiry minus buffer", () => {
    expect(isExpired({ accessToken: "x", expiresAt: Date.now() - 1 })).toBe(true);
  });

  it("returns false when token has plenty of time remaining", () => {
    expect(isExpired({ accessToken: "x", expiresAt: Date.now() + 3_600_000 })).toBe(false);
  });
});

describe("parseJwtPayload", () => {
  it("decodes a JWT payload", () => {
    const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.sig";
    const payload = parseJwtPayload(jwt);
    expect(payload.sub).toBe("1234567890");
    expect(payload.name).toBe("John Doe");
  });

  it("throws on invalid JWT (no payload segment)", () => {
    expect(() => parseJwtPayload("notajwt")).toThrow("Invalid JWT");
  });
});

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

describe("error taxonomy", () => {
  it("ConfigurationError is a HearthError", () => {
    const e = new ConfigurationError("bad config");
    expect(e).toBeInstanceOf(HearthError);
    expect(e).toBeInstanceOf(ConfigurationError);
    expect(e.name).toBe("ConfigurationError");
    expect(e.message).toBe("bad config");
  });

  it("TokenExpiredError carries expiry date", () => {
    const d = new Date(2020, 0, 1);
    const e = new TokenExpiredError(d);
    expect(e).toBeInstanceOf(HearthError);
    expect(e.message).toContain("2020");
  });

  it("supports cause chaining", () => {
    const inner = new Error("inner");
    const e = new DiscoveryError("outer", { cause: inner });
    expect(e.cause).toBe(inner);
  });

  it("sanitizes JWT-like strings from messages", () => {
    const e = new MiddlewareError("token=aa.bb.cc failed");
    expect(e.message).not.toContain("aa.bb.cc");
    expect(e.message).toContain("[redacted]");
  });
});

// ---------------------------------------------------------------------------
// VerifiedToken claims API
// ---------------------------------------------------------------------------

describe("VerifiedToken", () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: "user-1",
    iss: "https://auth.example.com",
    aud: ["app", "api"],
    iat: now - 10,
    exp: now + 3600,
    nbf: now - 5,
    scope: "openid profile email",
  };
  const vt = new VerifiedToken(payload, { alg: "RS256" });

  it("subject()", () => expect(vt.subject()).toBe("user-1"));
  it("issuer()", () => expect(vt.issuer()).toBe("https://auth.example.com"));
  it("audience()", () => expect(vt.audience()).toEqual(["app", "api"]));
  it("issuedAt()", () => expect(vt.issuedAt()).toBeInstanceOf(Date));
  it("expiresAt()", () => expect(vt.expiresAt()).toBeInstanceOf(Date));
  it("notBefore()", () => expect(vt.notBefore()).toBeInstanceOf(Date));
  it("scope()", () => expect(vt.scope()).toBe("openid profile email"));
  it("scopes()", () => expect(vt.scopes()).toEqual(["openid", "profile", "email"]));
  it("get(key)", () => expect(vt.get("sub")).toBe("user-1"));
  it("raw() is frozen", () => {
    const r = vt.raw();
    expect(Object.isFrozen(r)).toBe(true);
    expect(r.sub).toBe("user-1");
  });
  it("hasScope() returns true for present scope", async () => {
    expect(await vt.hasScope("profile")).toBe(true);
  });
  it("hasScope() returns false for absent scope", async () => {
    expect(await vt.hasScope("offline_access")).toBe(false);
  });

  it("returns null for absent optional claims", () => {
    const minimal = new VerifiedToken({}, {});
    expect(minimal.subject()).toBe("");
    expect(minimal.issuedAt()).toBeNull();
    expect(minimal.expiresAt()).toBeNull();
    expect(minimal.notBefore()).toBeNull();
    expect(minimal.scope()).toBe("");
    expect(minimal.scopes()).toEqual([]);
    expect(minimal.issuer()).toBe("");
    expect(minimal.audience()).toEqual([]);
    expect(minimal.get("nonexistent")).toBeUndefined();
  });

  it("scopes() uses scopes array if present", () => {
    const vt2 = new VerifiedToken({ sub: "u", scopes: ["read", "write"] }, {});
    expect(vt2.scopes()).toEqual(["read", "write"]);
  });

  it("audience() normalizes string to array", () => {
    const vt2 = new VerifiedToken({ sub: "u", aud: "single-app" }, {});
    expect(vt2.audience()).toEqual(["single-app"]);
  });
});

// ---------------------------------------------------------------------------
// HearthClient
// ---------------------------------------------------------------------------

describe("HearthClient", () => {
  const storage = memoryStorageAdapter();
  const fetchMock = vi.fn();

  const baseConfig = {
    issuer_url: "https://auth.example.com",
    client_id: "app",
    redirectUri: "https://app.example.com/callback",
    storage,
  };

  const discovery = {
    issuer: "https://auth.example.com",
    authorization_endpoint: "https://auth.example.com/authorize",
    token_endpoint: "https://auth.example.com/token",
    jwks_uri: "https://auth.example.com/.well-known/jwks.json",
    end_session_endpoint: "https://auth.example.com/logout",
  };

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    storage.remove("hearth:tokens");
    storage.remove("hearth:pkce_verifier");
    storage.remove("hearth:state");
    fetchMock.mockReset();
  });

  it("throws ConfigurationError on missing issuer_url", () => {
    expect(() => new HearthClient({ ...baseConfig, issuer_url: "" })).toThrow(ConfigurationError);
  });

  it("fetches and caches discovery document", async () => {
    fetchMock.mockResolvedValueOnce({ ok: true, json: async () => discovery });
    const client = new HearthClient(baseConfig);
    const d1 = await client.getDiscovery();
    const d2 = await client.getDiscovery();
    expect(d1).toBe(d2);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("throws DiscoveryError when discovery fails", async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 500 });
    const client = new HearthClient(baseConfig);
    await expect(client.getDiscovery()).rejects.toThrow(DiscoveryError);
  });

  it("returns null tokens when storage is empty", async () => {
    const client = new HearthClient(baseConfig);
    expect(await client.getTokens()).toBeNull();
  });

  it("handles callback and stores tokens, returns VerifiedToken", async () => {
    const now = Math.floor(Date.now() / 1000);
    // id_token payload: sub=user1, iss=https://auth.example.com, aud=app, exp=far future
    const idPayload = { sub: "user1", iss: "https://auth.example.com", aud: "app", iat: now, exp: now + 3600 };
    const idToken = `eyJhbGciOiJub25lIn0.${btoa(JSON.stringify(idPayload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")}.`;
    const tokenResponse = {
      access_token: "at",
      refresh_token: "rt",
      id_token: idToken,
      expires_in: 3600,
    };

    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => discovery })
      .mockResolvedValueOnce({ ok: true, json: async () => tokenResponse });

    storage.set("hearth:pkce_verifier", "test-verifier");
    storage.set("hearth:state", "test-state");

    // Provide a mock JWK set factory that always succeeds to avoid JWKS fetch
    const { createLocalJWKSet, exportJWK, generateKeyPair } = await import("jose");
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "test-key";
    jwk.use = "sig";

    // Re-sign a real token
    const { SignJWT } = await import("jose");
    const signedToken = await new SignJWT(idPayload)
      .setProtectedHeader({ alg: "RS256", kid: "test-key" })
      .sign(privateKey);

    const tokenResponse2 = { ...tokenResponse, id_token: signedToken };
    fetchMock.mockReset();
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => discovery })
      .mockResolvedValueOnce({ ok: true, json: async () => tokenResponse2 });

    storage.set("hearth:pkce_verifier", "test-verifier");
    storage.set("hearth:state", "test-state");

    // Use a client where JWKS is unavailable so we exercise the raw-payload fallback
    const client2 = new HearthClient({
      ...baseConfig,
      _jwkSetFactory: (_uri: string, _ttl: number) => { throw new Error("no jwks"); },
    });

    storage.set("hearth:pkce_verifier", "test-verifier");
    storage.set("hearth:state", "test-state");
    fetchMock.mockReset();
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => discovery })
      .mockResolvedValueOnce({ ok: true, json: async () => tokenResponse });

    const result = await client2.handleCallback(
      "https://app.example.com/callback?code=auth-code&state=test-state"
    );
    expect(result).toBeInstanceOf(VerifiedToken);
    expect(storage.get("hearth:pkce_verifier")).toBeNull();
  });

  it("throws MiddlewareError on state mismatch", async () => {
    fetchMock.mockResolvedValueOnce({ ok: true, json: async () => discovery });
    storage.set("hearth:pkce_verifier", "verifier");
    storage.set("hearth:state", "expected-state");

    const client = new HearthClient(baseConfig);
    await expect(
      client.handleCallback("https://app.example.com/callback?code=code&state=tampered")
    ).rejects.toThrow(MiddlewareError);
  });

  it("silentRefresh throws TokenExpiredError when no refresh token", async () => {
    storage.set("hearth:tokens", JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3600_000 }));
    const client = new HearthClient(baseConfig);
    await expect(client.silentRefresh()).rejects.toThrow(TokenExpiredError);
  });

  it("calls profile endpoint with bearer token", async () => {
    storage.set(
      "hearth:tokens",
      JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3_600_000 })
    );
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ sub: "user-1", email: "u@example.com" }),
    });

    const client = new HearthClient(baseConfig);
    const profile = await client.getProfile();

    expect(profile.sub).toBe("user-1");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://auth.example.com/account/profile",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ Authorization: "Bearer at" }),
      })
    );
  });

  it("supports custom account endpoint templates", async () => {
    storage.set(
      "hearth:tokens",
      JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3_600_000 })
    );
    fetchMock.mockResolvedValueOnce({ ok: true, status: 204, json: async () => ({}) });

    const client = new HearthClient({
      ...baseConfig,
      accountApiBaseUrl: "https://api.example.com",
      accountEndpoints: {
        mfaDeviceById: "/v2/security/mfa/{deviceId}",
      },
    });
    await client.removeMfaDevice("totp#1");

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/v2/security/mfa/totp%231",
      expect.objectContaining({ method: "DELETE" })
    );
  });

  it("throws when path params are missing for endpoint templates", async () => {
    storage.set(
      "hearth:tokens",
      JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3_600_000 })
    );
    fetchMock.mockResolvedValueOnce({ ok: true, status: 204, json: async () => ({}) });

    const client = new HearthClient({
      ...baseConfig,
      accountEndpoints: {
        sessionById: "/account/sessions/{sessionId}/{region}",
      },
    });

    await expect(client.revokeSession("s1")).rejects.toThrow("Missing path params");
  });

  it("downloads data export blobs", async () => {
    storage.set(
      "hearth:tokens",
      JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3_600_000 })
    );
    const blob = new Blob(["data"], { type: "application/json" });
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      blob: async () => blob,
    });

    const client = new HearthClient(baseConfig);
    const result = await client.downloadDataExport("export-1");
    expect(result).toBe(blob);
  });

  it("throws when account endpoint returns an error", async () => {
    storage.set(
      "hearth:tokens",
      JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3_600_000 })
    );
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: async () => ({ error: "forbidden" }),
    });

    const client = new HearthClient(baseConfig);
    await expect(client.listSessions()).rejects.toThrow("Account request failed: forbidden");
  });

  it("uses custom storageKeyPrefix", () => {
    const store = memoryStorageAdapter();
    const client = new HearthClient({
      ...baseConfig,
      storage: store,
      storageKeyPrefix: "myapp",
    });
    // @ts-expect-error accessing private
    expect(client.key("tokens")).toBe("myapp:tokens");
  });
});

// ---------------------------------------------------------------------------
// §9 — JWKS key rotation integration test
// ---------------------------------------------------------------------------

describe("JWKS key rotation", () => {
  it("re-fetches JWKS after key miss", async () => {
    const { JwksVerifier } = await import("./jwks.js");
    const { createLocalJWKSet, exportJWK, generateKeyPair } = await import("jose");

    const { privateKey: key1, publicKey: pub1 } = await generateKeyPair("RS256");
    const { privateKey: key2, publicKey: pub2 } = await generateKeyPair("RS256");
    const jwk1 = { ...(await exportJWK(pub1)), kid: "k1", use: "sig", alg: "RS256" };
    const jwk2 = { ...(await exportJWK(pub2)), kid: "k2", use: "sig", alg: "RS256" };

    const { SignJWT } = await import("jose");
    const now = Math.floor(Date.now() / 1000);
    const token2 = await new SignJWT({ sub: "u", iss: "https://auth.example.com", aud: "app", exp: now + 3600, iat: now })
      .setProtectedHeader({ alg: "RS256", kid: "k2" })
      .sign(key2);

    let callCount = 0;
    // First call returns set with only k1; second returns set with k1+k2
    const jwkFactory = () => {
      callCount++;
      const set = callCount === 1
        ? createLocalJWKSet({ keys: [jwk1] })
        : createLocalJWKSet({ keys: [jwk1, jwk2] });
      return set as ReturnType<typeof createLocalJWKSet>;
    };

    const verifier = new JwksVerifier(
      { issuer_url: "https://auth.example.com", audience: "app" },
      async () => ({
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/auth",
        token_endpoint: "https://auth.example.com/token",
        jwks_uri: "https://auth.example.com/jwks",
      }),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      jwkFactory as any,
    );

    const vt = await verifier.verifyToken(token2);
    expect(vt.subject()).toBe("u");
    expect(callCount).toBe(2); // first miss → re-fetch
  });

  it("throws TokenClaimsError on claim validation failure (wrong issuer)", async () => {
    const { JwksVerifier } = await import("./jwks.js");
    const { TokenClaimsError } = await import("./errors.js");
    const { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } = await import("jose");

    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "c1", use: "sig", alg: "RS256" };
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ sub: "u", iss: "https://evil.example.com", aud: "app", exp: now + 3600, iat: now })
      .setProtectedHeader({ alg: "RS256", kid: "c1" })
      .sign(privateKey);

    const localSet = createLocalJWKSet({ keys: [jwk] });
    const verifier = new JwksVerifier(
      { issuer_url: "https://auth.example.com", audience: "app" },
      async () => ({
        issuer: "https://auth.example.com",
        authorization_endpoint: "a",
        token_endpoint: "t",
        jwks_uri: "j",
      }),
      (() => localSet) as any,
    );

    await expect(verifier.verifyToken(token)).rejects.toThrow(TokenClaimsError);
  });

  it("throws TokenVerificationError on unexpected jwtVerify errors", async () => {
    const { JwksVerifier } = await import("./jwks.js");
    const { TokenVerificationError } = await import("./errors.js");

    // Return a key resolver that throws a generic (non-jose) error when called
    const throwingKeyResolver = async () => { throw new Error("unexpected key resolver error"); };
    const verifier = new JwksVerifier(
      { issuer_url: "https://auth.example.com" },
      async () => ({
        issuer: "https://auth.example.com",
        authorization_endpoint: "a",
        token_endpoint: "t",
        jwks_uri: "j",
      }),
      (() => throwingKeyResolver) as any,
    );

    await expect(verifier.verifyToken("some.token.here")).rejects.toThrow(TokenVerificationError);
  });

  it("invalidateCache evicts the cached JWK set", async () => {
    const { JwksVerifier } = await import("./jwks.js");
    const { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } = await import("jose");

    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "inv1", use: "sig", alg: "RS256" };
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ sub: "u", iss: "https://auth.example.com", aud: "app", exp: now + 3600, iat: now })
      .setProtectedHeader({ alg: "RS256", kid: "inv1" })
      .sign(privateKey);

    let calls = 0;
    const verifier = new JwksVerifier(
      { issuer_url: "https://auth.example.com", audience: "app" },
      async () => ({
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/auth",
        token_endpoint: "https://auth.example.com/token",
        jwks_uri: "https://auth.example.com/jwks",
      }),
      (() => { calls++; return createLocalJWKSet({ keys: [jwk] }); }) as any,
    );

    await verifier.verifyToken(token);
    expect(calls).toBe(1);
    verifier.invalidateCache();
    await verifier.verifyToken(token);
    expect(calls).toBe(2); // re-fetch after invalidation
  });
});

// ---------------------------------------------------------------------------
// §9 — Clock skew boundary test
// ---------------------------------------------------------------------------

describe("clock skew boundary", () => {
  it("accepts a token that is exactly within clock skew tolerance", async () => {
    const { JwksVerifier } = await import("./jwks.js");
    const { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } = await import("jose");

    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "ck1", use: "sig", alg: "RS256" };

    const clockSkewSeconds = 60;
    const now = Math.floor(Date.now() / 1000);
    // Token expired 5s ago (well within 60s tolerance) — should PASS
    const expiredJustWithinSkew = await new SignJWT({
      sub: "u",
      iss: "https://auth.example.com",
      aud: "app",
      iat: now - 65,
      exp: now - 5,
    })
      .setProtectedHeader({ alg: "RS256", kid: "ck1" })
      .sign(privateKey);

    // Token expired 120s ago (beyond 60s tolerance) — should FAIL
    const expiredBeyondSkew = await new SignJWT({
      sub: "u",
      iss: "https://auth.example.com",
      aud: "app",
      iat: now - 180,
      exp: now - 120,
    })
      .setProtectedHeader({ alg: "RS256", kid: "ck1" })
      .sign(privateKey);

    const localJwkSet = createLocalJWKSet({ keys: [jwk] });
    const verifier = new JwksVerifier(
      { issuer_url: "https://auth.example.com", audience: "app", clock_skew_seconds: clockSkewSeconds },
      async () => ({
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/auth",
        token_endpoint: "https://auth.example.com/token",
        jwks_uri: "https://auth.example.com/jwks",
      }),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (() => localJwkSet) as any,
    );

    await expect(verifier.verifyToken(expiredJustWithinSkew)).resolves.toBeInstanceOf(VerifiedToken);
    await expect(verifier.verifyToken(expiredBeyondSkew)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Account console route
// ---------------------------------------------------------------------------

describe("createAccountConsoleRoute", () => {
  it("loads profile, sessions, and mfa devices", async () => {
    const client = {
      getProfile: vi.fn(async () => ({ sub: "user-1", email: "u@example.com" })),
      updateProfile: vi.fn(),
      changePassword: vi.fn(),
      listSessions: vi.fn(async () => [{ id: "s1", createdAt: "a", lastSeenAt: "b", current: true }]),
      revokeSession: vi.fn(),
      revokeOtherSessions: vi.fn(),
      listMfaDevices: vi.fn(async () => [{ id: "d1", type: "totp" }]),
      removeMfaDevice: vi.fn(),
      createDataExport: vi.fn(),
      getDataExport: vi.fn(async () => ({ id: "e1", status: "queued", createdAt: "now" })),
      downloadDataExport: vi.fn(),
    };

    const route = createAccountConsoleRoute(client as unknown as HearthClient);
    const data = await route.load();

    expect(data.profile.sub).toBe("user-1");
    expect(data.sessions).toHaveLength(1);
    expect(data.mfaDevices).toHaveLength(1);
    expect(data.dataExport).toBeNull();
    expect(client.getDataExport).not.toHaveBeenCalled();
  });

  it("loads specific data export when export id is provided", async () => {
    const client = {
      getProfile: vi.fn(async () => ({ sub: "user-1" })),
      updateProfile: vi.fn(),
      changePassword: vi.fn(),
      listSessions: vi.fn(async () => []),
      revokeSession: vi.fn(),
      revokeOtherSessions: vi.fn(),
      listMfaDevices: vi.fn(async () => []),
      removeMfaDevice: vi.fn(),
      createDataExport: vi.fn(),
      getDataExport: vi.fn(async () => ({ id: "e9", status: "ready", createdAt: "now" })),
      downloadDataExport: vi.fn(),
    };

    const route = createAccountConsoleRoute(client as unknown as HearthClient);
    const data = await route.load({ dataExportId: "e9" });

    expect(client.getDataExport).toHaveBeenCalledWith("e9");
    expect(data.dataExport?.id).toBe("e9");
  });
});

// ---------------------------------------------------------------------------
// §3 — IntrospectionClient
// ---------------------------------------------------------------------------

describe("IntrospectionClient", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
  });

  const discovery = {
    issuer: "https://auth.example.com",
    authorization_endpoint: "https://auth.example.com/auth",
    token_endpoint: "https://auth.example.com/token",
    jwks_uri: "https://auth.example.com/jwks",
    introspection_endpoint: "https://auth.example.com/introspect",
  };

  it("returns active introspection result", async () => {
    const { IntrospectionClient } = await import("./introspect.js");
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        active: true,
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "app",
        exp: 9999999999,
        iat: 1000000000,
        scope: "openid profile",
        custom_claim: "hello",
      }),
    });

    const client = new IntrospectionClient("app", async () => discovery);
    const result = await client.introspect("some-token");

    expect(result.active).toBe(true);
    expect(result.sub).toBe("user-1");
    expect(result.aud).toBe("app");
    expect(result.scope).toBe("openid profile");
    expect(result.extra.custom_claim).toBe("hello");
  });

  it("returns inactive for token not recognized", async () => {
    const { IntrospectionClient } = await import("./introspect.js");
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: false }),
    });

    const client = new IntrospectionClient("app", async () => discovery);
    const result = await client.introspect("bad-token");
    expect(result.active).toBe(false);
  });

  it("throws IntrospectionError on HTTP error", async () => {
    const { IntrospectionClient } = await import("./introspect.js");
    const { IntrospectionError } = await import("./errors.js");
    fetchMock.mockResolvedValueOnce({ ok: false, status: 401 });

    const client = new IntrospectionClient("app", async () => discovery);
    await expect(client.introspect("t")).rejects.toThrow(IntrospectionError);
  });

  it("throws IntrospectionError when endpoint not in discovery", async () => {
    const { IntrospectionClient } = await import("./introspect.js");
    const { IntrospectionError } = await import("./errors.js");
    const noEndpoint = { ...discovery, introspection_endpoint: undefined };

    const client = new IntrospectionClient("app", async () => noEndpoint as typeof discovery);
    await expect(client.introspect("t")).rejects.toThrow(IntrospectionError);
  });

  it("throws IntrospectionError on network failure", async () => {
    const { IntrospectionClient } = await import("./introspect.js");
    const { IntrospectionError } = await import("./errors.js");
    fetchMock.mockRejectedValueOnce(new Error("network down"));

    const client = new IntrospectionClient("app", async () => discovery);
    await expect(client.introspect("t")).rejects.toThrow(IntrospectionError);
  });

  it("throws IntrospectionError on invalid JSON response", async () => {
    const { IntrospectionClient } = await import("./introspect.js");
    const { IntrospectionError } = await import("./errors.js");
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => { throw new SyntaxError("bad json"); },
    });

    const client = new IntrospectionClient("app", async () => discovery);
    await expect(client.introspect("t")).rejects.toThrow(IntrospectionError);
  });
});

// ---------------------------------------------------------------------------
// Additional HearthClient coverage: introspect delegation and logout
// ---------------------------------------------------------------------------

describe("HearthClient introspect + logout", () => {
  const fetchMock = vi.fn();
  const storage = memoryStorageAdapter();

  const baseConfig = {
    issuer_url: "https://auth.example.com",
    client_id: "app",
    redirectUri: "https://app.example.com/callback",
    storage,
  };

  const discovery = {
    issuer: "https://auth.example.com",
    authorization_endpoint: "https://auth.example.com/auth",
    token_endpoint: "https://auth.example.com/token",
    jwks_uri: "https://auth.example.com/jwks",
    introspection_endpoint: "https://auth.example.com/introspect",
    end_session_endpoint: "https://auth.example.com/logout",
  };

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    storage.remove("hearth:tokens");
    fetchMock.mockReset();
  });

  it("delegates introspect to IntrospectionClient", async () => {
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => discovery })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ active: true, sub: "u" }) });

    const client = new HearthClient(baseConfig);
    const result = await client.introspect("access-token");
    expect(result.active).toBe(true);
  });

  it("invalidateJwksCache does not throw", () => {
    const client = new HearthClient(baseConfig);
    expect(() => client.invalidateJwksCache()).not.toThrow();
  });

  it("getIdTokenClaims returns null when no tokens stored", () => {
    const client = new HearthClient(baseConfig);
    expect(client.getIdTokenClaims()).toBeNull();
  });

  it("createDataExport and getDataExport", async () => {
    storage.set("hearth:tokens", JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3600_000 }));
    fetchMock
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ id: "e1", status: "queued", createdAt: "now" }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ id: "e1", status: "ready", createdAt: "now" }) });

    const client = new HearthClient(baseConfig);
    const job = await client.createDataExport();
    expect(job.id).toBe("e1");

    const status = await client.getDataExport("e1");
    expect(status.status).toBe("ready");
  });

  it("getIdTokenClaims returns null when no idToken in stored tokens", () => {
    storage.set("hearth:tokens", JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3600_000 }));
    const client = new HearthClient(baseConfig);
    expect(client.getIdTokenClaims()).toBeNull();
  });

  it("refresh() (deprecated) returns null when no tokens", async () => {
    const client = new HearthClient(baseConfig);
    const result = await client.refresh();
    expect(result).toBeNull();
  });

  it("getTokens() returns null when tokens are expired and refresh fails", async () => {
    storage.set("hearth:tokens", JSON.stringify({
      accessToken: "at",
      refreshToken: "rt",
      expiresAt: Date.now() - 1,
    }));
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => discovery })
      .mockResolvedValueOnce({ ok: false, status: 401 });

    const client = new HearthClient(baseConfig);
    const result = await client.getTokens();
    expect(result).toBeNull();
  });

  it("onTokenChange is called on token update", async () => {
    const onTokenChange = vi.fn();
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => discovery })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          active: true,
          sub: "u",
        }),
      });

    storage.set("hearth:tokens", JSON.stringify({ accessToken: "at", expiresAt: Date.now() + 3600_000 }));

    const client = new HearthClient({ ...baseConfig, onTokenChange });
    await client.introspect("token");
    // onTokenChange is not triggered by introspect but by token store
    expect(onTokenChange).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Storage adapters
// ---------------------------------------------------------------------------

describe("storage adapters", () => {
  it("memoryStorageAdapter get/set/remove", () => {
    const store = memoryStorageAdapter();
    expect(store.get("k")).toBeNull();
    store.set("k", "v");
    expect(store.get("k")).toBe("v");
    store.remove("k");
    expect(store.get("k")).toBeNull();
  });

  it("localStorageAdapter delegates to localStorage", async () => {
    const mockStorage = { getItem: vi.fn(() => "v"), setItem: vi.fn(), removeItem: vi.fn() };
    vi.stubGlobal("localStorage", mockStorage);

    const { localStorageAdapter } = await import("./storage.js");
    expect(localStorageAdapter.get("k")).toBe("v");
    localStorageAdapter.set("k", "v2");
    localStorageAdapter.remove("k");
    expect(mockStorage.getItem).toHaveBeenCalledWith("k");
    expect(mockStorage.setItem).toHaveBeenCalledWith("k", "v2");
    expect(mockStorage.removeItem).toHaveBeenCalledWith("k");
  });
});
