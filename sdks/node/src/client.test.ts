import { describe, it, expect, vi, afterEach } from "vitest";
import { HearthClient } from "./client.js";
import { JwksVerifier } from "./jwks.js";
import { IntrospectionClient } from "./introspect.js";
import { AuthorizeClient } from "./authorize.js";
import { OAuthFlowsClient } from "./flows.js";
import { VerifiedToken } from "./token.js";
import type { JWTPayload } from "jose";

const CONFIG = {
  issuer_url: "https://auth.example.com",
  client_id: "client1",
  client_secret: "secret1",
};

function makeToken(): VerifiedToken {
  const payload: JWTPayload = {
    sub: "user123",
    iss: "https://auth.example.com",
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  };
  return new VerifiedToken(payload, { alg: "RS256" });
}

describe("HearthClient", () => {
  afterEach(() => vi.restoreAllMocks());

  it("delegates verifyToken to JwksVerifier", async () => {
    const token = makeToken();
    const spy = vi.spyOn(JwksVerifier.prototype, "verifyToken").mockResolvedValue(token);
    const client = new HearthClient(CONFIG);
    const result = await client.verifyToken("some.jwt.token");
    expect(spy).toHaveBeenCalledWith("some.jwt.token");
    expect(result).toBe(token);
  });

  it("delegates introspect to IntrospectionClient", async () => {
    const introspectResult = { active: true, sub: "user123", extra: {} };
    const spy = vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue(introspectResult);
    const client = new HearthClient(CONFIG);
    const result = await client.introspect("tok");
    expect(spy).toHaveBeenCalledWith("tok", undefined);
    expect(result).toBe(introspectResult);
  });

  it("delegates introspect with tokenTypeHint", async () => {
    const spy = vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({ active: false, extra: {} });
    const client = new HearthClient(CONFIG);
    await client.introspect("tok", "refresh_token");
    expect(spy).toHaveBeenCalledWith("tok", "refresh_token");
  });

  it("delegates authorize to AuthorizeClient", async () => {
    const authResult = { allowed: true };
    const spy = vi.spyOn(AuthorizeClient.prototype, "decide").mockResolvedValue(authResult);
    const client = new HearthClient(CONFIG);
    const result = await client.authorize("tok", "docs.read");
    expect(spy).toHaveBeenCalledWith("tok", "docs.read", undefined);
    expect(result).toBe(authResult);
  });

  it("invalidateCache clears JWKS and discovery caches", () => {
    const spy = vi.spyOn(JwksVerifier.prototype, "invalidateCache").mockImplementation(() => undefined);
    const client = new HearthClient(CONFIG);
    client.invalidateCache();
    expect(spy).toHaveBeenCalledOnce();
  });
});

// ── OAuth flow delegation ─────────────────────────────────────────────────────

const TOKEN_RESPONSE = {
  access_token: "eyJ.at",
  token_type: "Bearer",
  expires_in: 3600,
};

const DEVICE_RESPONSE = {
  device_code: "dev-code",
  user_code: "WXYZ-1234",
  verification_uri: "https://auth.example.com/activate",
  expires_in: 600,
  interval: 5,
};

describe("HearthClient — OAuth flow delegation", () => {
  afterEach(() => vi.restoreAllMocks());

  it("delegates exchangeCode to OAuthFlowsClient", async () => {
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "exchangeCode").mockResolvedValue(TOKEN_RESPONSE);
    const client = new HearthClient(CONFIG);
    const result = await client.exchangeCode("code-abc", "https://app.local/cb", { codeVerifier: "v3r" });
    expect(spy).toHaveBeenCalledWith("code-abc", "https://app.local/cb", { codeVerifier: "v3r" });
    expect(result).toBe(TOKEN_RESPONSE);
  });

  it("delegates clientCredentials to OAuthFlowsClient", async () => {
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "clientCredentials").mockResolvedValue(TOKEN_RESPONSE);
    const client = new HearthClient(CONFIG);
    const result = await client.clientCredentials("openid profile");
    expect(spy).toHaveBeenCalledWith("openid profile");
    expect(result).toBe(TOKEN_RESPONSE);
  });

  it("delegates startDeviceFlow to OAuthFlowsClient", async () => {
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "startDeviceFlow").mockResolvedValue(DEVICE_RESPONSE);
    const client = new HearthClient(CONFIG);
    const result = await client.startDeviceFlow("openid");
    expect(spy).toHaveBeenCalledWith("openid");
    expect(result).toBe(DEVICE_RESPONSE);
  });

  it("delegates pollDeviceToken to OAuthFlowsClient", async () => {
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "pollDeviceToken").mockResolvedValue(TOKEN_RESPONSE);
    const client = new HearthClient(CONFIG);
    const result = await client.pollDeviceToken("dev-code", 5);
    expect(spy).toHaveBeenCalledWith("dev-code", 5);
    expect(result).toBe(TOKEN_RESPONSE);
  });

  it("delegates requestMagicLink to OAuthFlowsClient", async () => {
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "requestMagicLink").mockResolvedValue(undefined);
    const client = new HearthClient({ ...CONFIG, realm_id: "realm1" });
    await client.requestMagicLink("user@example.com");
    expect(spy).toHaveBeenCalledWith("user@example.com");
  });

  it("delegates userinfo to OAuthFlowsClient", async () => {
    const uiResp = { sub: "user1", email: "user@example.com" };
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "userinfo").mockResolvedValue(uiResp);
    const client = new HearthClient(CONFIG);
    const result = await client.userinfo("access-tok");
    expect(spy).toHaveBeenCalledWith("access-tok");
    expect(result).toBe(uiResp);
  });

  it("delegates mePermissions to OAuthFlowsClient", async () => {
    const permResp = { roles: ["admin"], groups: [], permissions: ["docs.write"] };
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "mePermissions").mockResolvedValue(permResp);
    const client = new HearthClient(CONFIG);
    const result = await client.mePermissions("access-tok");
    expect(spy).toHaveBeenCalledWith("access-tok");
    expect(result).toBe(permResp);
  });

  it("delegates svSnapshot to OAuthFlowsClient", async () => {
    const snap = { realm: "r", current_seq: 10, versions: {} };
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "svSnapshot").mockResolvedValue(snap);
    const client = new HearthClient(CONFIG);
    const result = await client.svSnapshot("svc-tok");
    expect(spy).toHaveBeenCalledWith("svc-tok");
    expect(result).toBe(snap);
  });

  it("delegates svDelta to OAuthFlowsClient", async () => {
    const delta = { realm: "r", next_seq: 5, deltas: [] };
    const spy = vi.spyOn(OAuthFlowsClient.prototype, "svDelta").mockResolvedValue(delta);
    const client = new HearthClient(CONFIG);
    const result = await client.svDelta("svc-tok", 3, 50);
    expect(spy).toHaveBeenCalledWith("svc-tok", 3, 50);
    expect(result).toBe(delta);
  });
});
