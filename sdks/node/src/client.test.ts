import { describe, it, expect, vi, afterEach } from "vitest";
import { HearthClient } from "./client.js";
import { JwksVerifier } from "./jwks.js";
import { IntrospectionClient } from "./introspect.js";
import { AuthorizeClient } from "./authorize.js";
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
