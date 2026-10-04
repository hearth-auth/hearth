/**
 * sdk-standard-libraries 2.1 — the `jose` library performs every signature,
 * algorithm, key and registered-claim check. These tests pin the outcomes the
 * `sdk-support-contract` capability requires, and the SDK error taxonomy the
 * jose errors map onto (openspec/specs/sdk-support-contract/spec.md and §5).
 */

import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, base64url } from "jose";
import type { KeyLike } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { JwksClient } from "../src/jwks-client.js";
import {
  TokenAudienceError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  TokenNotYetValidError,
} from "../src/errors.js";

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
  return new SignJWT({ sub: "user123", aud: "hearth", ...claims })
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
    const token = await new SignJWT({ sub: "user123", aud: "hearth" })
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
    const token = await new SignJWT({ sub: "user123", aud: "hearth" })
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

/** Sign a token that expired `secondsAgo` seconds ago. */
function signExpired(secondsAgo: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: "user123", aud: "hearth" })
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .setIssuedAt(now - 3600)
    .setIssuer(ISSUER)
    .setExpirationTime(now - secondsAgo)
    .sign(privateKey);
}

describe("default clock skew (5 s, shared by all four SDKs)", () => {
  it("rejects a token that expired 10 s ago under the default options", async () => {
    mockFetch();
    await expect(
      new HearthClient({ issuerUrl: ISSUER }).verifyToken(await signExpired(10)),
    ).rejects.toBeInstanceOf(TokenExpiredError);
  });

  it("accepts that token when the caller widens clockSkewSeconds", async () => {
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
    const claims = await jc.verify(await signExpired(10), { clockSkewSeconds: 60 });
    expect(claims.subject()).toBe("user123");
  });
});

/** Serve only the JWKS (for a bare JwksClient). */
function mockJwksOnly(): void {
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
}

describe("audience check (on by default, RFC 9068 §4)", () => {
  it("rejects a token for another API when no audience is configured", async () => {
    mockFetch();
    const err = await new HearthClient({ issuerUrl: ISSUER })
      .verifyToken(await sign({ aud: "other-api" }))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TokenAudienceError);
    expect((err as TokenAudienceError).expected).toBe("hearth");
  });

  it("rejects a token with no aud claim under the default audience", async () => {
    const token = await new SignJWT({ sub: "user123" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setExpirationTime("1h")
      .sign(privateKey);
    mockFetch();
    await expect(new HearthClient({ issuerUrl: ISSUER }).verifyToken(token)).rejects.toBeInstanceOf(
      TokenAudienceError,
    );
  });

  it("accepts a token for the configured protected-resource audience", async () => {
    mockFetch();
    const claims = await new HearthClient({
      issuerUrl: ISSUER,
      audience: "https://api.example.com",
    }).verifyToken(await sign({ aud: "https://api.example.com" }));
    expect(claims.subject()).toBe("user123");
  });

  it("checks the configured audience, not the client ID", async () => {
    mockFetch();
    const claims = await new HearthClient({ issuerUrl: ISSUER, clientId: "my-client" }).verifyToken(
      await sign({ aud: "hearth" }),
    );
    expect(claims.subject()).toBe("user123");

    mockFetch();
    await expect(
      new HearthClient({ issuerUrl: ISSUER, clientId: "my-client" }).verifyToken(
        await sign({ aud: "my-client" }),
      ),
    ).rejects.toBeInstanceOf(TokenAudienceError);
  });

  it("JwksClient defaults its audience to hearth", async () => {
    mockJwksOnly();
    const jc = new JwksClient({ jwksUri: DISCOVERY.jwks_uri, issuer: ISSUER });
    expect(jc.audience).toBe("hearth");
    await expect(jc.verify(await sign({ aud: "other-api" }))).rejects.toBeInstanceOf(
      TokenAudienceError,
    );
  });
});

describe("iat in the future", () => {
  it("throws TokenNotYetValidError for a token whose iat is 60 s in the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ sub: "user123", aud: "hearth" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt(now + 60)
      .setIssuer(ISSUER)
      .setExpirationTime(now + 3600)
      .sign(privateKey);
    mockFetch();
    const err = await new HearthClient({ issuerUrl: ISSUER })
      .verifyToken(token)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TokenNotYetValidError);
    expect((err as TokenNotYetValidError).notBefore.getTime()).toBe((now + 60) * 1000);
  });

  it("accepts an iat within the clock skew", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ sub: "user123", aud: "hearth" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt(now + 3)
      .setIssuer(ISSUER)
      .setExpirationTime(now + 3600)
      .sign(privateKey);
    mockFetch();
    const claims = await new HearthClient({ issuerUrl: ISSUER }).verifyToken(token);
    expect(claims.subject()).toBe("user123");
  });
});
