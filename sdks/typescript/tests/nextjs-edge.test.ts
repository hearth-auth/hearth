/**
 * Next.js Edge Runtime middleware (ported from the Node SDK's nextjs/edge
 * tests). Tokens are really signed and really verified; only fetch is stubbed.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import type { KeyLike } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { hearthEdgeMiddleware } from "../src/nextjs/edge.js";

const ISSUER = "https://auth.example.com";
const KID = "edge-key";

let privateKey: KeyLike;
let jwks: { keys: unknown[] };

beforeAll(async () => {
  const kp = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  privateKey = kp.privateKey as KeyLike;
  jwks = { keys: [{ ...(await exportJWK(kp.publicKey)), kid: KID, alg: "EdDSA" }] };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubIssuer(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            String(url).includes("openid-configuration")
              ? { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` }
              : jwks,
          ),
        ),
      ),
    ),
  );
}

async function sign(claims: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ sub: "user1", aud: "hearth", ...claims })
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

function request(authHeader?: string): Request {
  const headers = new Headers();
  if (authHeader) headers.set("Authorization", authHeader);
  return new Request("https://app.example.com/api/thing", { headers });
}

function guard(opts: Partial<Parameters<typeof hearthEdgeMiddleware>[0]> = {}) {
  stubIssuer();
  return hearthEdgeMiddleware({ client: new HearthClient({ issuerUrl: ISSUER }), ...opts });
}

describe("hearthEdgeMiddleware — missing token", () => {
  it("returns a 401 JSON Response with WWW-Authenticate (required by default)", async () => {
    const res = await guard()(request());
    expect(res).toBeInstanceOf(Response);
    expect(res!.status).toBe(401);
    expect(res!.headers.get("WWW-Authenticate")).toBe('Bearer realm="hearth"');
    expect(res!.headers.get("Content-Type")).toBe("application/json");
    expect(await res!.json()).toMatchObject({ error: "unauthorized" });
  });

  it("returns 401 for a non-Bearer Authorization header", async () => {
    const res = await guard()(request("Basic dXNlcjpwYXNz"));
    expect(res!.status).toBe(401);
  });

  it("returns undefined when no token is sent and required is false", async () => {
    expect(await guard({ required: false })(request())).toBeUndefined();
  });
});

describe("hearthEdgeMiddleware — invalid token", () => {
  it("returns 401 for a tampered signature", async () => {
    const token = await sign();
    const [h, p, s] = token.split(".");
    const tampered = `${h}.${p}.${s.split("").reverse().join("")}`;
    const res = await guard()(request(`Bearer ${tampered}`));
    expect(res!.status).toBe(401);
  });

  it("returns undefined for an invalid token when required is false", async () => {
    expect(await guard({ required: false })(request("Bearer not-a-jwt"))).toBeUndefined();
  });

  it("returns 401 for a required_action token, even when required is false", async () => {
    const token = await sign({ token_type: "required_action" });
    const res = await guard({ required: false })(request(`Bearer ${token}`));
    expect(res!.status).toBe(401);
    expect(((await res!.json()) as Record<string, string>).error_description).toContain(
      "required actions",
    );
  });
});

describe("hearthEdgeMiddleware — guards", () => {
  it("passes a valid token through when no guard is configured", async () => {
    expect(await guard()(request(`Bearer ${await sign()}`))).toBeUndefined();
  });

  it("returns 403 when the required scope is missing, and passes when present", async () => {
    const g = guard({ requiredScope: "admin" });
    const denied = await g(request(`Bearer ${await sign({ scope: "openid profile" })}`));
    expect(denied!.status).toBe(403);
    expect(((await denied!.json()) as Record<string, string>).error).toBe("forbidden");
    expect(await g(request(`Bearer ${await sign({ scope: "openid admin" })}`))).toBeUndefined();
  });

  it("returns 403 when the required role is missing, and passes when present", async () => {
    const g = guard({ requiredRole: "admin" });
    expect((await g(request(`Bearer ${await sign({ roles: ["viewer"] })}`)))!.status).toBe(403);
    expect(
      await g(request(`Bearer ${await sign({ roles: ["admin", "viewer"] })}`)),
    ).toBeUndefined();
  });

  it("returns 403 when the required permission is missing, and passes when present", async () => {
    const g = guard({ requiredPermission: "users:write" });
    expect(
      (await g(request(`Bearer ${await sign({ permissions: ["users:read"] })}`)))!.status,
    ).toBe(403);
    expect(
      await g(request(`Bearer ${await sign({ permissions: ["users:read", "users:write"] })}`)),
    ).toBeUndefined();
  });
});

describe("nextjs/edge import graph", () => {
  it("never imports a node: built-in, directly or transitively", () => {
    const srcDir = resolve(dirname(fileURLToPath(import.meta.url)), "../src");
    const seen = new Set<string>();
    const nodeImports: string[] = [];
    const visit = (file: string) => {
      if (seen.has(file)) return;
      seen.add(file);
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(/(?:import|export)[^"']*?from\s+["']([^"']+)["']/g)) {
        const spec = m[1];
        if (spec.startsWith("node:")) nodeImports.push(`${file}: ${spec}`);
        if (spec.startsWith(".")) visit(resolve(dirname(file), spec.replace(/\.js$/, ".ts")));
      }
    };
    visit(resolve(srcDir, "nextjs/edge.ts"));
    expect(seen.size).toBeGreaterThan(3);
    expect(nodeImports).toEqual([]);
  });
});
