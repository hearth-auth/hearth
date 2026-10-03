/**
 * verifyToken() — clock-skew boundaries, key rotation and cache invalidation
 * (ported from the Node SDK's jwks tests).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import type { JWK, KeyLike } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { TokenExpiredError } from "../src/errors.js";

const ISSUER = "https://auth.example.com";
const SKEW = 60; // JwksClient default clock tolerance, seconds

let kidCounter = 0;

async function keyPair(): Promise<{ privateKey: KeyLike; jwk: JWK; kid: string }> {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const kid = `key-${++kidCounter}`;
  return { privateKey, kid, jwk: { ...(await exportJWK(publicKey)), kid, alg: "EdDSA" } };
}

async function sign(
  kp: { privateKey: KeyLike; kid: string },
  payload: Record<string, unknown>,
): Promise<string> {
  return new SignJWT({ sub: "u1", iss: ISSUER, ...payload })
    .setProtectedHeader({ alg: "EdDSA", kid: kp.kid })
    .sign(kp.privateKey);
}

/** Serve discovery, and the JWKS returned by `keysFor(n)` on the n-th JWKS fetch (1-based). */
function stubIssuer(keysFor: (n: number) => JWK[]) {
  let jwksFetches = 0;
  const spy = vi.fn((url: string) => {
    const body = String(url).includes("openid-configuration")
      ? { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` }
      : { keys: keysFor(++jwksFetches) };
    return Promise.resolve(new Response(JSON.stringify(body)));
  });
  vi.stubGlobal("fetch", spy);
  return { jwksFetches: () => jwksFetches };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("verifyToken() — clock skew boundaries", () => {
  const NOW = 1_700_000_000;

  it("accepts exp = now + skew and rejects exp = now - skew - 1", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW * 1000);
    const kp = await keyPair();
    stubIssuer(() => [kp.jwk]);
    const client = new HearthClient({ issuerUrl: ISSUER });

    const atBoundary = await sign(kp, { exp: NOW + SKEW, iat: NOW - 10 });
    expect((await client.verifyToken(atBoundary)).subject()).toBe("u1");

    const outside = await sign(kp, { exp: NOW - SKEW - 1, iat: NOW - 200 });
    await expect(client.verifyToken(outside)).rejects.toBeInstanceOf(TokenExpiredError);
  });

  it("accepts an iat up to skew seconds in the future", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW * 1000);
    const kp = await keyPair();
    stubIssuer(() => [kp.jwk]);
    const token = await sign(kp, { iat: NOW + SKEW, exp: NOW + 3600 });
    expect((await new HearthClient({ issuerUrl: ISSUER }).verifyToken(token)).subject()).toBe("u1");
  });
});

describe("verifyToken() — key rotation", () => {
  it("re-fetches the JWKS once on an unknown kid and accepts the rotated key", async () => {
    const oldKey = await keyPair();
    const newKey = await keyPair();
    const issuer = stubIssuer((n) => (n === 1 ? [oldKey.jwk] : [newKey.jwk]));
    const now = Math.floor(Date.now() / 1000);
    const token = await sign(newKey, { iat: now, exp: now + 3600 });

    const claims = await new HearthClient({ issuerUrl: ISSUER }).verifyToken(token);
    expect(claims.subject()).toBe("u1");
    expect(issuer.jwksFetches()).toBe(2);
  });

  it("invalidateCache() makes the next verifyToken fetch the JWKS again", async () => {
    const kp = await keyPair();
    const issuer = stubIssuer(() => [kp.jwk]);
    const now = Math.floor(Date.now() / 1000);
    const token = await sign(kp, { iat: now, exp: now + 3600 });
    const client = new HearthClient({ issuerUrl: ISSUER });

    await client.verifyToken(token);
    await client.verifyToken(token);
    expect(issuer.jwksFetches()).toBe(1);

    client.invalidateCache();
    await client.verifyToken(token);
    expect(issuer.jwksFetches()).toBe(2);
  });
});
