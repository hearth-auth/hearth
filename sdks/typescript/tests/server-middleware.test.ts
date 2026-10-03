/**
 * Express / Fastify middleware (ported from the Node SDK's middleware and
 * middleware.mode tests).
 *
 * Design constraint (HEA-923): the absence of a `permissions` claim MUST NOT
 * switch the authorization mode. Only the configured mode decides which check
 * runs.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { HearthClient } from "../src/hearth-client.js";
import { IntrospectionClient } from "../src/introspection-client.js";
import { Claims } from "../src/claims.js";
import { ConfigurationError, TokenExpiredError } from "../src/errors.js";
import { hearthMiddleware, hearthFastifyHook } from "../src/middleware.js";

const ISSUER = "https://auth.example.com";
const REALM_ID = "11111111-1111-1111-1111-111111111111";

function makeClient(overrides: Partial<ConstructorParameters<typeof HearthClient>[0]> = {}) {
  return new HearthClient({
    issuerUrl: ISSUER,
    clientId: "app",
    clientSecret: "secret",
    realmId: REALM_ID,
    introspectionEndpoint: `${ISSUER}/introspect`,
    ...overrides,
  });
}

function claims(payload: Record<string, unknown> = {}): Claims {
  return new Claims({ sub: "user1", iss: ISSUER, exp: 9_999_999_999, ...payload });
}

function verifiesAs(payload: Record<string, unknown> = {}): Claims {
  const c = claims(payload);
  vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(c);
  return c;
}

function makeReqRes(authHeader?: string) {
  const req = {
    headers: { authorization: authHeader } as Record<string, string | undefined>,
    hearthClaims: undefined as Claims | undefined,
  };
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value;
      return this;
    },
  };
  return { req, res, next: vi.fn() };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── authentication ─────────────────────────────────────────────────────────

describe("hearthMiddleware — authentication", () => {
  it("calls next() with req.hearthClaims set when the token verifies", async () => {
    const c = verifiesAs();
    const mw = hearthMiddleware({ client: makeClient() });
    const { req, res, next } = makeReqRes("Bearer valid-token");
    await mw(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.hearthClaims).toBe(c);
  });

  it("returns 401 with WWW-Authenticate when no token is sent (required by default)", async () => {
    const mw = hearthMiddleware({ client: makeClient() });
    const { req, res, next } = makeReqRes();
    await mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
    expect(res.body).toMatchObject({ error: "unauthorized" });
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 401 for a non-Bearer Authorization header", async () => {
    const mw = hearthMiddleware({ client: makeClient() });
    const { req, res, next } = makeReqRes("Basic dXNlcjpwYXNz");
    await mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("calls next() without claims when no token is sent and required is false", async () => {
    const mw = hearthMiddleware({ client: makeClient(), required: false });
    const { req, res, next } = makeReqRes();
    await mw(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.hearthClaims).toBeUndefined();
  });

  it("returns 401 with WWW-Authenticate when verification fails", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockRejectedValue(
      new TokenExpiredError(new Date("2024-01-01T00:00:00Z")),
    );
    const mw = hearthMiddleware({ client: makeClient() });
    const { req, res, next } = makeReqRes("Bearer bad-token");
    await mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
    expect(res.body).toMatchObject({ error_description: expect.stringContaining("expired") });
    expect(next).not.toHaveBeenCalled();
  });

  it("does not echo the text of an unexpected verification error", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockRejectedValue(new Error("internal detail"));
    const mw = hearthMiddleware({ client: makeClient() });
    const { req, res, next } = makeReqRes("Bearer bad-token");
    await mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(JSON.stringify(res.body)).not.toContain("internal detail");
  });

  it("returns 401 for a required_action token, even when required is false", async () => {
    verifiesAs({ token_type: "required_action", required_actions: ["VERIFY_EMAIL"] });
    const mw = hearthMiddleware({ client: makeClient(), required: false });
    const { req, res, next } = makeReqRes("Bearer required-action-token");
    await mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({
      error_description: expect.stringContaining("required actions"),
    });
    expect(next).not.toHaveBeenCalled();
    expect(req.hearthClaims).toBeUndefined();
  });

  it("refuses an alg:none forgery end to end (real verification)", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "EdDSA" };
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) =>
        Promise.resolve(
          new Response(
            JSON.stringify(
              String(url).includes("openid-configuration")
                ? { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` }
                : { keys: [jwk] },
            ),
          ),
        ),
      ),
    );
    const mw = hearthMiddleware({
      client: new HearthClient({ issuerUrl: ISSUER }),
      requiredPermission: "admin.write",
    });

    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const forged = `${b64({ alg: "none" })}.${b64({ sub: "x", iss: ISSUER, permissions: ["admin.write"] })}.`;
    const forgedCall = makeReqRes(`Bearer ${forged}`);
    await mw(forgedCall.req, forgedCall.res, forgedCall.next);
    expect(forgedCall.res.statusCode).toBe(401);
    expect(forgedCall.next).not.toHaveBeenCalled();

    const signed = await new SignJWT({ sub: "u1", permissions: ["admin.write"] })
      .setProtectedHeader({ alg: "EdDSA", kid: "k1" })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
    const goodCall = makeReqRes(`Bearer ${signed}`);
    await mw(goodCall.req, goodCall.res, goodCall.next);
    expect(goodCall.next).toHaveBeenCalledWith();
    expect(goodCall.req.hearthClaims?.subject()).toBe("u1");
  });
});

// ── scope / role / permission guards ───────────────────────────────────────

describe("hearthMiddleware — guards", () => {
  it("returns 403 when the required scope is missing", async () => {
    verifiesAs({ scope: "openid" });
    const mw = hearthMiddleware({ client: makeClient(), requiredScope: "admin" });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ error: "forbidden" });
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 when the required role is missing", async () => {
    verifiesAs({ roles: ["viewer"] });
    const mw = hearthMiddleware({ client: makeClient(), requiredRole: "admin" });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
  });

  it("returns 403 when the required permission is missing", async () => {
    verifiesAs({ permissions: ["read"] });
    const mw = hearthMiddleware({ client: makeClient(), requiredPermission: "delete" });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
  });

  it("allows a token that carries the scope, role and permission", async () => {
    verifiesAs({ scope: "openid admin", roles: ["superuser"], permissions: ["delete"] });
    const mw = hearthMiddleware({
      client: makeClient(),
      requiredScope: "admin",
      requiredRole: "superuser",
      requiredPermission: "delete",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalledWith();
  });
});

// ── embedded mode ──────────────────────────────────────────────────────────

describe("hearthMiddleware — embedded mode", () => {
  it("is the default when neither the options nor the client set a mode", async () => {
    verifiesAs({ permissions: ["x.read"] });
    const authorize = vi.spyOn(HearthClient.prototype, "authorize");
    const mw = hearthMiddleware({ client: makeClient(), requiredPermission: "x.read" });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(authorize).not.toHaveBeenCalled();
  });

  it("returns 403 without calling the server when the claim lacks the permission", async () => {
    verifiesAs({ permissions: [] });
    const authorize = vi.spyOn(HearthClient.prototype, "authorize");
    const introspect = vi.spyOn(IntrospectionClient.prototype, "introspect");
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "embedded",
      requiredPermission: "docs.write",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(authorize).not.toHaveBeenCalled();
    expect(introspect).not.toHaveBeenCalled();
  });

  it("treats an absent permissions claim as no permission, not as a mode switch", async () => {
    verifiesAs({});
    const authorize = vi.spyOn(HearthClient.prototype, "authorize");
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "embedded",
      requiredPermission: "admin.read",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(authorize).not.toHaveBeenCalled();
  });
});

// ── introspection mode ─────────────────────────────────────────────────────

describe("hearthMiddleware — introspection mode", () => {
  it("allows when the live permission is present", async () => {
    verifiesAs();
    const introspect = vi
      .spyOn(IntrospectionClient.prototype, "introspect")
      .mockResolvedValue({ active: true, mode: "introspection", permissions: ["docs.write"] });
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "introspection",
      requiredPermission: "docs.write",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(introspect).toHaveBeenCalledWith("t", "access_token");
  });

  it("returns 403 when the live permission is absent, even if the JWT has it", async () => {
    verifiesAs({ permissions: ["docs.write"] });
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({
      active: true,
      mode: "introspection",
      permissions: ["docs.read"],
    });
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "introspection",
      requiredPermission: "docs.write",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 401 when the token is no longer active", async () => {
    verifiesAs();
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({ active: false });
    const mw = hearthMiddleware({ client: makeClient(), mode: "introspection" });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 when the server echoes a different mode", async () => {
    verifiesAs();
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({
      active: true,
      mode: "embedded",
      permissions: ["docs.write"],
    });
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "introspection",
      requiredPermission: "docs.write",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("fails closed with 403 when introspection throws", async () => {
    verifiesAs();
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockRejectedValue(new Error("network"));
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "introspection",
      requiredPermission: "perm",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("takes the mode from the client's expectedMode when the options omit it", async () => {
    verifiesAs();
    const introspect = vi
      .spyOn(IntrospectionClient.prototype, "introspect")
      .mockResolvedValue({ active: false });
    const mw = hearthMiddleware({ client: makeClient({ expectedMode: "introspection" }) });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(introspect).toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it("throws ConfigurationError at construction when the client has no secret", () => {
    expect(() =>
      hearthMiddleware({ client: makeClient({ clientSecret: undefined }), mode: "introspection" }),
    ).toThrow(ConfigurationError);
  });
});

// ── decision mode ──────────────────────────────────────────────────────────

describe("hearthMiddleware — decision mode", () => {
  it("calls POST /oauth/authorize and allows when the server grants", async () => {
    verifiesAs();
    const authorize = vi.spyOn(HearthClient.prototype, "authorize").mockResolvedValue(true);
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "decision",
      requiredPermission: "docs.write",
      organizationId: "org-1",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(authorize).toHaveBeenCalledWith("t", "docs.write", {
      organizationId: "org-1",
      resource: undefined,
    });
  });

  it("returns 403 when the server denies (including fail-closed network errors)", async () => {
    verifiesAs();
    vi.spyOn(HearthClient.prototype, "authorize").mockResolvedValue(false);
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "decision",
      requiredPermission: "docs.write",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("uses only the server's answer, not the JWT permissions claim", async () => {
    verifiesAs({ permissions: ["docs.write"] });
    const authorize = vi.spyOn(HearthClient.prototype, "authorize").mockResolvedValue(false);
    const mw = hearthMiddleware({
      client: makeClient(),
      mode: "decision",
      requiredPermission: "docs.write",
    });
    const { req, res, next } = makeReqRes("Bearer t");
    await mw(req, res, next);
    expect(authorize).toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it("throws ConfigurationError at construction when the client has no realmId", () => {
    expect(() =>
      hearthMiddleware({
        client: makeClient({ realmId: undefined }),
        mode: "decision",
        requiredPermission: "docs.write",
      }),
    ).toThrow(ConfigurationError);
  });
});

// ── Fastify ────────────────────────────────────────────────────────────────

function makeFastify(authHeader?: string) {
  const request = {
    headers: { authorization: authHeader } as Record<string, string | undefined>,
    hearthClaims: undefined as Claims | undefined,
  };
  const reply = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    body: undefined as unknown,
    code(c: number) {
      this.statusCode = c;
      return this;
    },
    header(n: string, v: string) {
      this.headers[n] = v;
      return this;
    },
    send(b: unknown) {
      this.body = b;
      return this;
    },
  };
  return { request, reply };
}

describe("hearthFastifyHook", () => {
  it("sets request.hearthClaims when the token verifies", async () => {
    const c = verifiesAs();
    const hook = hearthFastifyHook({ client: makeClient() });
    const { request, reply } = makeFastify("Bearer t");
    await hook(request, reply);
    expect(request.hearthClaims).toBe(c);
    expect(reply.body).toBeUndefined();
  });

  it("replies 401 with WWW-Authenticate when no token is sent", async () => {
    const hook = hearthFastifyHook({ client: makeClient() });
    const { request, reply } = makeFastify();
    await hook(request, reply);
    expect(reply.statusCode).toBe(401);
    expect(reply.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
    expect(reply.body).toMatchObject({ error: "unauthorized" });
  });

  it("replies 403 when the required permission is missing", async () => {
    verifiesAs({ permissions: [] });
    const hook = hearthFastifyHook({ client: makeClient(), requiredPermission: "docs.write" });
    const { request, reply } = makeFastify("Bearer t");
    await hook(request, reply);
    expect(reply.statusCode).toBe(403);
    expect(request.hearthClaims).toBeUndefined();
  });

  it("decision mode: allows when the server grants", async () => {
    verifiesAs();
    vi.spyOn(HearthClient.prototype, "authorize").mockResolvedValue(true);
    const hook = hearthFastifyHook({
      client: makeClient(),
      mode: "decision",
      requiredPermission: "docs.write",
    });
    const { request, reply } = makeFastify("Bearer t");
    await hook(request, reply);
    expect(reply.statusCode).toBe(200);
    expect(request.hearthClaims).toBeDefined();
  });
});
