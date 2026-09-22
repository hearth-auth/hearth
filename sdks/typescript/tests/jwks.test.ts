import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as jose from "jose";
import { ensureBinary, startServer, stopServer, type TestServer } from "./helpers.js";

describe("TypeScript SDK: JWKS Validation", () => {
  let server: TestServer;

  beforeAll(async () => {
    ensureBinary();
    server = await startServer();
  });

  afterAll(() => {
    if (server) stopServer(server);
  });

  it("verifies token signatures using JWKS-fetched public keys", async () => {
    const { client, bootstrap } = server;

    // 1. Fetch the JWKS document
    const jwks = await client.jwks();
    expect(jwks.keys).toBeTruthy();
    expect(jwks.keys.length).toBeGreaterThan(0);

    // Verify the key is an Ed25519 (OKP) key
    const key = jwks.keys[0];
    expect(key.kty).toBe("OKP");
    expect(key.crv).toBe("Ed25519");
    expect(key.x).toBeTruthy();
    expect(key.alg).toBe("EdDSA");
    expect(key.use).toBe("sig");
    expect(key.kid).toBeTruthy();

    // 2. The token's own header names the key that signed it.
    const header = jose.decodeProtectedHeader(bootstrap.access_token);
    expect(header.alg).toBe("EdDSA");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBeTruthy();

    // 3. That key is the *realm's*, not the global one. Each realm holds its
    //    own Ed25519 signing key, and `/jwks` publishes only the global key —
    //    so a realm-issued token never verifies against it. This test used to
    //    assume otherwise and verify against `jwks.keys[0]`.
    //
    //    The realm's JWKS is keyed by realm *name*, not id, which is why the
    //    name is looked up first.
    const realmResp = await fetch(
      `${server.baseUrl}/admin/realms/${bootstrap.realm_id}`,
      {
        headers: {
          Authorization: `Bearer ${bootstrap.access_token}`,
          "X-Realm-ID": bootstrap.realm_id,
        },
      },
    );
    expect(realmResp.ok).toBe(true);
    const realmName = ((await realmResp.json()) as { name: string }).name;

    const realmJwksResp = await fetch(
      `${server.baseUrl}/realms/${realmName}/.well-known/jwks.json`,
    );
    expect(realmJwksResp.ok).toBe(true);
    const realmJwks = (await realmJwksResp.json()) as { keys: jose.JWK[] };
    const realmKey = realmJwks.keys.find((k) => k.kid === header.kid);
    expect(realmKey).toBeTruthy();

    const publicKey = await jose.importJWK(realmKey as jose.JWK, "EdDSA");
    const { payload: accessPayload } = await jose.jwtVerify(
      bootstrap.access_token,
      publicKey,
    );
    expect(accessPayload.sub).toBeTruthy();
    expect(accessPayload.exp).toBeTruthy();

    // 4. Verify the OIDC discovery document references the JWKS endpoint
    const discovery = await client.discovery();
    expect(discovery.jwks_uri).toBeTruthy();

    // 6. Verify a tampered token fails verification
    const tampered = bootstrap.access_token.slice(0, -4) + "XXXX";
    await expect(
      jose.jwtVerify(tampered, publicKey),
    ).rejects.toThrow();
  });
});
