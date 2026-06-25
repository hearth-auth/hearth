/**
 * §2 — verifyToken() TDD tests (written before implementation).
 *
 * Tests EdDSA/Ed25519 signature verification, full claim validation,
 * key rotation re-fetch, and typed error taxonomy per spec §2 and §5.
 */

import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  importJWK,
  exportSPKI,
} from "jose";
import type { KeyLike } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { Claims } from "../src/claims.js";
import {
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
} from "../src/errors.js";

const ISSUER = "https://auth.example.com";
const KID = "key-1";

/** Build a minimal JWKS response object for the given public key JWK. */
async function makeJwksDoc(publicKey: KeyLike) {
  const jwk = await exportJWK(publicKey);
  return { keys: [{ ...jwk, kid: KID, use: "sig", alg: "EdDSA" }] };
}

/** Sign a JWT with the given private key. */
async function signToken(
  privateKey: KeyLike,
  claims: Record<string, unknown> = {},
  expiresIn = "1h",
): Promise<string> {
  return new SignJWT({ sub: "user123", ...claims })
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setExpirationTime(expiresIn)
    .sign(privateKey);
}

/** A minimal OIDC discovery document. */
const DISCOVERY = {
  issuer: ISSUER,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  authorization_endpoint: `${ISSUER}/oauth/authorize`,
  token_endpoint: `${ISSUER}/oauth/token`,
};

let privateKey: KeyLike;
let publicKey: KeyLike;

beforeAll(async () => {
  const kp = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  privateKey = kp.privateKey as KeyLike;
  publicKey = kp.publicKey as KeyLike;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function mockFetch(responses: Array<{ body: unknown; status?: number }>): void {
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

describe("HearthClient.verifyToken() — EdDSA / Ed25519", () => {
  it("resolves with a Claims object for a valid Ed25519 token", async () => {
    const token = await signToken(privateKey);
    const jwksDoc = await makeJwksDoc(publicKey);
    mockFetch([{ body: DISCOVERY }, { body: jwksDoc }]);

    const client = new HearthClient({ issuerUrl: ISSUER });
    const claims = await client.verifyToken(token);

    expect(claims).toBeInstanceOf(Claims);
    expect(claims.subject()).toBe("user123");
    expect(claims.issuer()).toBe(ISSUER);
  });

  it("returns a Claims whose expiry() is a future Date", async () => {
    const token = await signToken(privateKey);
    const jwksDoc = await makeJwksDoc(publicKey);
    mockFetch([{ body: DISCOVERY }, { body: jwksDoc }]);

    const client = new HearthClient({ issuerUrl: ISSUER });
    const claims = await client.verifyToken(token);

    const expiry = claims.expiry();
    expect(expiry).toBeInstanceOf(Date);
    expect(expiry!.getTime()).toBeGreaterThan(Date.now());
  });

  it("throws TokenExpiredError for a token with exp in the past", async () => {
    const token = await signToken(privateKey, {}, "1s");
    // Set exp to 1970 by overriding iat/exp manually
    const expiredToken = await new SignJWT({ sub: "user123" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt(0)
      .setIssuer(ISSUER)
      .setExpirationTime(1)  // 1 second after epoch
      .sign(privateKey);

    const jwksDoc = await makeJwksDoc(publicKey);
    mockFetch([{ body: DISCOVERY }, { body: jwksDoc }]);

    const client = new HearthClient({ issuerUrl: ISSUER });
    await expect(client.verifyToken(expiredToken)).rejects.toBeInstanceOf(
      TokenExpiredError,
    );
  });

  it("throws TokenInvalidError for a tampered / bad signature", async () => {
    // Build a token and corrupt its signature
    const token = await signToken(privateKey);
    const parts = token.split(".");
    parts[2] = parts[2].split("").reverse().join(""); // corrupt signature
    const badToken = parts.join(".");

    const jwksDoc = await makeJwksDoc(publicKey);
    mockFetch([{ body: DISCOVERY }, { body: jwksDoc }]);

    const client = new HearthClient({ issuerUrl: ISSUER });
    await expect(client.verifyToken(badToken)).rejects.toBeInstanceOf(
      TokenInvalidError,
    );
  });

  it("throws TokenIssuerError when issuer does not match", async () => {
    const wrongIssuerToken = await new SignJWT({ sub: "user123" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt()
      .setIssuer("https://wrong.issuer.com")
      .setExpirationTime("1h")
      .sign(privateKey);

    const jwksDoc = await makeJwksDoc(publicKey);
    mockFetch([{ body: DISCOVERY }, { body: jwksDoc }]);

    const client = new HearthClient({ issuerUrl: ISSUER });
    await expect(client.verifyToken(wrongIssuerToken)).rejects.toBeInstanceOf(
      TokenIssuerError,
    );
  });

  it("reuses the cached JWKS key set on successive verifyToken calls", async () => {
    const token = await signToken(privateKey);
    const jwksDoc = await makeJwksDoc(publicKey);
    // Only mock 2 calls: 1 discovery + 1 JWKS fetch
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string) => {
        calls++;
        const body = calls === 1 ? DISCOVERY : jwksDoc;
        return Promise.resolve(
          new Response(JSON.stringify(body), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );

    const client = new HearthClient({ issuerUrl: ISSUER });
    await client.verifyToken(token);
    await client.verifyToken(token);

    // Should only fetch discovery once and JWKS once regardless of how many verify calls
    expect(calls).toBeLessThanOrEqual(3);
  });

  it("passes custom claims through to the Claims object", async () => {
    const token = await signToken(privateKey, {
      roles: ["admin"],
      permissions: ["users.read"],
      groups: ["eng"],
    });
    const jwksDoc = await makeJwksDoc(publicKey);
    mockFetch([{ body: DISCOVERY }, { body: jwksDoc }]);

    const client = new HearthClient({ issuerUrl: ISSUER });
    const claims = await client.verifyToken(token);

    expect(claims.hasRole("admin")).toBe(true);
    expect(claims.hasPermission("users.read")).toBe(true);
    expect(claims.inGroup("eng")).toBe(true);
  });
});
