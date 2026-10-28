/**
 * Regression #635: every JWKS fetch failure surfaces as `JWKSFetchError`, with
 * the underlying error as its `cause`, never as a raw `fetch`, JSON or `jose`
 * error (openspec/specs/sdk-support-contract/spec.md, "JWKS cache rules" and
 * "Error messages and causes").
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer, type AddressInfo } from "node:net";
import { generateKeyPair, SignJWT } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { JwksClient } from "../src/jwks-client.js";
import { JWKSFetchError } from "../src/errors.js";

const ISSUER = "https://auth.example.com";

/** A loopback port nothing listens on: a connection to it is refused at once. */
async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

async function token(): Promise<string> {
  const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  return new SignJWT({ sub: "u1", aud: "hearth" })
    .setProtectedHeader({ alg: "EdDSA", kid: "k1" })
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

/** The error `promise` rejects with; fails the test when it resolves. */
async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the promise to reject");
}

/** A JwksClient whose JWKS request `fetch` answers with `answer`. */
function clientAnswering(answer: () => Promise<Response>): JwksClient {
  vi.stubGlobal("fetch", vi.fn(answer));
  return new JwksClient({ jwksUri: `${ISSUER}/.well-known/jwks.json`, issuer: ISSUER });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("JWKS fetch failures surface as JWKSFetchError (#635)", () => {
  it("JwksClient.verify: the JWKS endpoint refuses the connection", async () => {
    const jwksUri = `http://127.0.0.1:${await closedPort()}/.well-known/jwks.json`;
    const client = new JwksClient({ jwksUri, issuer: ISSUER });

    const err = await rejection(client.verify(await token()));

    expect(err).toBeInstanceOf(JWKSFetchError);
    // undici reports a refused connection as `TypeError: fetch failed`.
    expect((err as JWKSFetchError).cause).toBeInstanceOf(TypeError);
  });

  it("HearthClient.verifyToken: the discovered JWKS endpoint refuses the connection", async () => {
    const jwksUri = `http://127.0.0.1:${await closedPort()}/.well-known/jwks.json`;
    const realFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) =>
        String(url).endsWith("/.well-known/openid-configuration")
          ? Promise.resolve(new Response(JSON.stringify({ issuer: ISSUER, jwks_uri: jwksUri })))
          : realFetch(url, init),
      ),
    );
    const client = new HearthClient({ issuerUrl: ISSUER });

    const err = await rejection(client.verifyToken(await token()));

    expect(err).toBeInstanceOf(JWKSFetchError);
    expect((err as JWKSFetchError).cause).toBeInstanceOf(TypeError);
  });

  it("the JWKS request times out", async () => {
    const timeout = new DOMException("The operation was aborted due to timeout", "TimeoutError");
    const client = clientAnswering(() => Promise.reject(timeout));

    const err = await rejection(client.verify(await token()));

    expect(err).toBeInstanceOf(JWKSFetchError);
    expect((err as JWKSFetchError).cause).toBe(timeout);
  });

  it("the JWKS body is not JSON", async () => {
    const client = clientAnswering(() =>
      Promise.resolve(new Response("<html>Bad gateway</html>", { status: 200 })),
    );

    const err = await rejection(client.verify(await token()));

    expect(err).toBeInstanceOf(JWKSFetchError);
    expect((err as JWKSFetchError).cause).toBeInstanceOf(SyntaxError);
  });

  it("the JWKS document has no keys array", async () => {
    const client = clientAnswering(() =>
      Promise.resolve(new Response(JSON.stringify({ error: "not a key set" }), { status: 200 })),
    );

    const err = await rejection(client.verify(await token()));

    expect(err).toBeInstanceOf(JWKSFetchError);
  });
});
