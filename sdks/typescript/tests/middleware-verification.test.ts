/**
 * 25.1 / 25.3 — the authorization gate must verify a token before trusting it.
 *
 * `requirePermission({ mode: "embedded" })` reads the `permissions` claim to
 * decide whether a request proceeds. Reading that claim out of an unverified
 * JWT lets an unauthenticated attacker mint `{"alg":"none"}` carrying
 * `permissions: ["admin.write"]` and be admitted, so the gate is exercised
 * against exactly that forgery as well as against a properly signed token.
 *
 * `JwksClient.verify` is exported from the package root, so a caller who
 * constructs it directly must not get a signature-only check.
 */

import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import type { KeyLike } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { JwksClient } from "../src/jwks-client.js";
import { requirePermission } from "../src/middleware.js";
import { ConfigurationError, TokenIssuerError } from "../src/errors.js";

const ISSUER = "https://auth.example.com";
const KID = "key-1";

let privateKey: KeyLike;
let publicKey: KeyLike;
let foreignPrivateKey: KeyLike;

beforeAll(async () => {
  const kp = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  privateKey = kp.privateKey as KeyLike;
  publicKey = kp.publicKey as KeyLike;
  const other = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  foreignPrivateKey = other.privateKey as KeyLike;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function jwksDoc() {
  const jwk = await exportJWK(publicKey);
  return { keys: [{ ...jwk, kid: KID, use: "sig", alg: "EdDSA" }] };
}

const DISCOVERY = {
  issuer: ISSUER,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  token_endpoint: `${ISSUER}/oauth/token`,
};

/** Answer discovery and JWKS from the in-memory key pair; 404 anything else. */
async function stubIssuer(): Promise<void> {
  const keys = await jwksDoc();
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const body = String(url).includes("openid-configuration") ? DISCOVERY : keys;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }),
  );
}

async function signWith(
  key: KeyLike,
  claims: Record<string, unknown>,
  issuer = ISSUER,
): Promise<string> {
  return new SignJWT({ sub: "user123", ...claims })
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .setIssuedAt()
    .setIssuer(issuer)
    .setExpirationTime("1h")
    .sign(key);
}

/** An `alg: none` forgery claiming admin.write. Costs the attacker nothing. */
function unsignedAdminToken(): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "none", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(
    JSON.stringify({
      sub: "attacker",
      iss: ISSUER,
      exp: Math.floor(Date.now() / 1000) + 3600,
      permissions: ["admin.write"],
    }),
    "utf8",
  ).toString("base64url");
  return `${header}.${body}.`;
}

function client(): HearthClient {
  return new HearthClient({ issuerUrl: ISSUER });
}

describe("requirePermission — embedded mode", () => {
  it("refuses an alg:none forgery that claims the permission", async () => {
    await stubIssuer();
    const gate = requirePermission("admin.write", {
      mode: "embedded",
      client: client(),
    });
    expect(await gate(unsignedAdminToken())).toBe(false);
  });

  it("refuses a token signed by a key outside the JWKS", async () => {
    await stubIssuer();
    const token = await signWith(foreignPrivateKey, {
      permissions: ["admin.write"],
    });
    const gate = requirePermission("admin.write", {
      mode: "embedded",
      client: client(),
    });
    expect(await gate(token)).toBe(false);
  });

  it("refuses a token minted for a different issuer", async () => {
    await stubIssuer();
    const token = await signWith(
      privateKey,
      { permissions: ["admin.write"] },
      "https://evil.example.com",
    );
    const gate = requirePermission("admin.write", {
      mode: "embedded",
      client: client(),
    });
    expect(await gate(token)).toBe(false);
  });

  it("admits a properly signed token that carries the permission", async () => {
    await stubIssuer();
    const token = await signWith(privateKey, {
      permissions: ["admin.write", "docs.read"],
    });
    const gate = requirePermission("admin.write", {
      mode: "embedded",
      client: client(),
    });
    expect(await gate(token)).toBe(true);
  });

  it("denies a properly signed token that lacks the permission", async () => {
    await stubIssuer();
    const token = await signWith(privateKey, { permissions: ["docs.read"] });
    const gate = requirePermission("admin.write", {
      mode: "embedded",
      client: client(),
    });
    expect(await gate(token)).toBe(false);
  });
});

describe("JwksClient.verify — issuer and audience pinning (25.3)", () => {
  it("refuses to verify when no issuer is pinned", async () => {
    await stubIssuer();
    const jc = new JwksClient({ jwksUri: DISCOVERY.jwks_uri });
    const token = await signWith(privateKey, {});
    await expect(jc.verify(token)).rejects.toBeInstanceOf(ConfigurationError);
  });

  it("pins the issuer from its own config when the caller passes no options", async () => {
    await stubIssuer();
    const jc = new JwksClient({ jwksUri: DISCOVERY.jwks_uri, issuer: ISSUER });
    const foreign = await signWith(privateKey, {}, "https://evil.example.com");
    await expect(jc.verify(foreign)).rejects.toBeInstanceOf(TokenIssuerError);

    const ours = await signWith(privateKey, {});
    expect((await jc.verify(ours)).subject()).toBe("user123");
  });

  it("pins the audience from its own config when the caller passes no options", async () => {
    await stubIssuer();
    const jc = new JwksClient({
      jwksUri: DISCOVERY.jwks_uri,
      issuer: ISSUER,
      audience: "client-a",
    });

    const forOtherApp = await new SignJWT({ sub: "user123", aud: "client-b" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setExpirationTime("1h")
      .sign(privateKey);
    await expect(jc.verify(forOtherApp)).rejects.toThrow();

    const forUs = await new SignJWT({ sub: "user123", aud: "client-a" })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setExpirationTime("1h")
      .sign(privateKey);
    expect((await jc.verify(forUs)).subject()).toBe("user123");
  });
});
