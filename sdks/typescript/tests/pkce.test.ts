import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  generateCodeVerifier,
  generateCodeChallenge,
  buildAuthorizationUrl,
  startLogin,
} from "../src/pkce.js";
import { HearthApiClient } from "../src/client.js";

// RFC 7636 Appendix B test vector.
const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const BASE64URL_RE = /^[A-Za-z0-9\-_]+$/;

// ---------------------------------------------------------------------------
// generateCodeVerifier
// ---------------------------------------------------------------------------

describe("generateCodeVerifier", () => {
  it("returns a 43-character base64url string (32 bytes of entropy)", () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(43);
    expect(verifier).toMatch(BASE64URL_RE);
  });

  it("contains no padding characters", () => {
    const verifier = generateCodeVerifier();
    expect(verifier).not.toContain("=");
    expect(verifier).not.toContain("+");
    expect(verifier).not.toContain("/");
  });

  it("produces unique values (entropy check)", () => {
    const values = new Set(Array.from({ length: 20 }, () => generateCodeVerifier()));
    expect(values.size).toBe(20);
  });
});

// ---------------------------------------------------------------------------
// generateCodeChallenge
// ---------------------------------------------------------------------------

describe("generateCodeChallenge", () => {
  it("derives the correct S256 challenge from the RFC 7636 Appendix B vector", async () => {
    const challenge = await generateCodeChallenge(RFC_VERIFIER);
    expect(challenge).toBe(RFC_CHALLENGE);
  });

  it("produces a 43-character base64url string (SHA-256 = 32 bytes)", async () => {
    const challenge = await generateCodeChallenge(generateCodeVerifier());
    expect(challenge).toHaveLength(43);
    expect(challenge).toMatch(BASE64URL_RE);
  });

  it("produces distinct challenges for distinct verifiers", async () => {
    const a = await generateCodeChallenge("verifier-a");
    const b = await generateCodeChallenge("verifier-b");
    expect(a).not.toBe(b);
  });
});

// ---------------------------------------------------------------------------
// buildAuthorizationUrl
// ---------------------------------------------------------------------------

describe("buildAuthorizationUrl", () => {
  const BASE_OPTS = {
    authorizationEndpoint: "https://auth.example.com/oauth/authorize",
    clientId: "my-client",
    redirectUri: "https://app.example.com/callback",
    codeChallenge: RFC_CHALLENGE,
  };

  it("includes all required PKCE and OIDC parameters", () => {
    const { url } = buildAuthorizationUrl(BASE_OPTS);
    const p = new URL(url).searchParams;
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe("my-client");
    expect(p.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(p.get("code_challenge")).toBe(RFC_CHALLENGE);
    expect(p.get("code_challenge_method")).toBe("S256");
  });

  it("defaults scope to 'openid profile email' when omitted", () => {
    const { url } = buildAuthorizationUrl(BASE_OPTS);
    expect(new URL(url).searchParams.get("scope")).toBe("openid profile email");
  });

  it("uses the caller-supplied scope", () => {
    const { url } = buildAuthorizationUrl({ ...BASE_OPTS, scope: "openid offline_access" });
    expect(new URL(url).searchParams.get("scope")).toBe("openid offline_access");
  });

  it("auto-generates a non-empty state when not provided", () => {
    const { url, state } = buildAuthorizationUrl(BASE_OPTS);
    expect(state).toBeTruthy();
    expect(state).toMatch(BASE64URL_RE);
    expect(new URL(url).searchParams.get("state")).toBe(state);
  });

  it("auto-generates unique states on successive calls", () => {
    const states = new Set(
      Array.from({ length: 10 }, () => buildAuthorizationUrl(BASE_OPTS).state),
    );
    expect(states.size).toBe(10);
  });

  it("echoes back a provided state value", () => {
    const { url, state } = buildAuthorizationUrl({ ...BASE_OPTS, state: "csrf-token-xyz" });
    expect(state).toBe("csrf-token-xyz");
    expect(new URL(url).searchParams.get("state")).toBe("csrf-token-xyz");
  });

  it("uses the authorization endpoint as the URL base", () => {
    const { url } = buildAuthorizationUrl(BASE_OPTS);
    const parsed = new URL(url);
    expect(`${parsed.origin}${parsed.pathname}`).toBe(
      "https://auth.example.com/oauth/authorize",
    );
  });
});

// ---------------------------------------------------------------------------
// startLogin — integration (mocked discovery doc)
// ---------------------------------------------------------------------------

describe("startLogin", () => {
  const DISCOVERY_DOC = {
    issuer: "https://auth.example.com",
    authorization_endpoint: "https://auth.example.com/oauth/authorize",
    jwks_uri: "https://auth.example.com/jwks",
    token_endpoint: "https://auth.example.com/token",
  };

  function mockFetch(body: unknown, status = 200): void {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
    );
  }

  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it("returns a valid redirect URL with all required PKCE parameters", async () => {
    mockFetch(DISCOVERY_DOC);
    const client = new HearthApiClient({
      baseUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    const result = await startLogin(client, {
      clientId: "my-spa",
      redirectUri: "https://app.example.com/callback",
    });

    const p = new URL(result.url).searchParams;
    expect(new URL(result.url).origin + new URL(result.url).pathname).toBe(
      "https://auth.example.com/oauth/authorize",
    );
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe("my-spa");
    expect(p.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(p.get("code_challenge_method")).toBe("S256");
    expect(p.get("code_challenge")).toBeTruthy();
    expect(p.get("state")).toBe(result.state);
  });

  it("returns a 43-char codeVerifier the caller can store for token exchange", async () => {
    mockFetch(DISCOVERY_DOC);
    const client = new HearthApiClient({
      baseUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    const result = await startLogin(client, {
      clientId: "my-spa",
      redirectUri: "https://app.example.com/callback",
    });
    expect(result.codeVerifier).toHaveLength(43);
    expect(result.codeVerifier).toMatch(BASE64URL_RE);
  });

  it("propagates a caller-supplied state to the URL", async () => {
    mockFetch(DISCOVERY_DOC);
    const client = new HearthApiClient({
      baseUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    const result = await startLogin(client, {
      clientId: "my-spa",
      redirectUri: "https://app.example.com/callback",
      state: "custom-csrf-state",
    });
    expect(result.state).toBe("custom-csrf-state");
    expect(new URL(result.url).searchParams.get("state")).toBe("custom-csrf-state");
  });

  it("throws when authorization_endpoint is absent from the discovery doc", async () => {
    mockFetch({ issuer: "https://auth.example.com", jwks_uri: "https://auth.example.com/jwks" });
    const client = new HearthApiClient({
      baseUrl: "https://auth.example.com",
      realmId: "realm_1",
    });
    await expect(
      startLogin(client, { clientId: "spa", redirectUri: "https://app.example.com/cb" }),
    ).rejects.toThrow("authorization_endpoint not found");
  });
});
