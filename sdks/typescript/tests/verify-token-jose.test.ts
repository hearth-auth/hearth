/**
 * sdk-standard-libraries 2.1 — the `jose` library performs every signature,
 * algorithm, key and registered-claim check. These tests pin the outcomes the
 * `sdk-support-contract` capability requires, and the SDK error taxonomy the
 * jose errors map onto (docs/specs/SDK.md §2 and §5).
 */

import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, base64url } from "jose";
import type { KeyLike } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { JwksClient } from "../src/jwks-client.js";
import { TokenInvalidError, TokenIssuerError, TokenNotYetValidError } from "../src/errors.js";

const ISSUER = "https://auth.example.com";
const KID = "key-1";

const DISCOVERY = {
  issuer: ISSUER,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  authorization_endpoint: `${ISSUER}/oauth/authorize`,
  token_endpoint: `${ISSUER}/oauth/token`,
};

let privateKey: KeyLike;
let jwksDoc: { keys: Record<string, unknown>[] };

beforeAll(async () => {
  const kp = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  privateKey = kp.privateKey as KeyLike;
  const jwk = await exportJWK(kp.publicKey);
  jwksDoc = { keys: [{ ...jwk, kid: KID, use: "sig", alg: "EdDSA" }] };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Serve the discovery document first, then the JWKS for every later fetch. */
function mockFetch(): void {
  let calls = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      const body = calls++ === 0 ? DISCOVERY : jwksDoc;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }),
  );
}

function sign(claims: Record<string, unknown> = {}, kid = KID): Promise<string> {
  return new SignJWT({ sub: "user123", ...claims })
    .setProtectedHeader({ alg: "EdDSA", kid })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setExpirationTime("1h")
    .sign(privateKey);
}

function encodeSegment(value: Record<string, unknown>): string {
  return base64url.encode(JSON.stringify(value));
}

describe("verifyToken() through jose — capability scenarios", () => {
  it("returns the claims of a valid Ed25519 token", async () => {
    mockFetch();
    const claims = await new HearthClient({ issuerUrl: ISSUER }).verifyToken(await sign());
    expect(claims.subject()).toBe("user123");
  });

  it("refuses a token whose payload was changed after signing", async () => {
    const [header, , signature] = (await sign()).split(".");
    const forged = encodeSegment({
      sub: "admin",
      iss: ISSUER,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    mockFetch();
    await expect(
      new HearthClient({ issuerUrl: ISSUER }).verifyToken(`${header}.${forged}.${signature}`),
    ).rejects.toBeInstanceOf(TokenInvalidError);
  });

  it("refuses an unsigned token whose header says alg: none", async () => {
    const header = encodeSegment({ alg: "none", kid: KID });
    const payload = encodeSegment({
      sub: "user123",
      iss: ISSUER,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    mockFetch();
    await expect(
      new HearthClient({ issuerUrl: ISSUER }).verifyToken(`${header}.${payload}.`),
    ).rejects.toBeInstanceOf(TokenInvalidError);
  });

  it("refuses a token signed under a kid the JWKS does not publish", async () => {
    mockFetch();
    await expect(
      new HearthClient({ issuerUrl: ISSUER }).verifyToken(await sign({}, "unknown-kid")),
    ).rejects.toBeInstanceOf(TokenInvalidError);
  });

  it("refuses a token with no exp claim", async () => {
    const token = await new SignJWT({ sub: "user123" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .sign(privateKey);
    mockFetch();
    await expect(new HearthClient({ issuerUrl: ISSUER }).verifyToken(token)).rejects.toBeInstanceOf(
      TokenInvalidError,
    );
  });
});

describe("jose error → SDK error taxonomy", () => {
  it("maps a future nbf to TokenNotYetValidError", async () => {
    const nbf = Math.floor(Date.now() / 1000) + 3600;
    mockFetch();
    const err = await new HearthClient({ issuerUrl: ISSUER })
      .verifyToken(await sign({ nbf }))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TokenNotYetValidError);
    expect((err as TokenNotYetValidError).notBefore.getTime()).toBe(nbf * 1000);
  });

  it("reports the configured issuer as expected when only the client config pins it", async () => {
    const token = await new SignJWT({ sub: "user123" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt()
      .setIssuer("https://wrong.issuer.com")
      .setExpirationTime("1h")
      .sign(privateKey);
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify(jwksDoc), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
      ),
    );
    const jc = new JwksClient({ jwksUri: DISCOVERY.jwks_uri, issuer: ISSUER });
    const err = await jc.verify(token).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TokenIssuerError);
    expect((err as TokenIssuerError).expected).toBe(ISSUER);
    expect((err as TokenIssuerError).actual).toBe("https://wrong.issuer.com");
  });
});
