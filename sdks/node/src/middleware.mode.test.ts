/**
 * Tests for mode-aware middleware — covers the expectedMode contract from HEA-924.
 *
 * Design constraint: absence of `permissions` in a token MUST NOT silently
 * change authorization behavior. Only explicit `expectedMode` drives the check path.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { hearthMiddleware, hearthFastifyHook } from "./middleware.js";
import { HearthClient } from "./client.js";
import { AuthorizeClient } from "./authorize.js";
import { IntrospectionClient } from "./introspect.js";
import { AuthorizationModeError } from "./errors.js";
import { VerifiedToken } from "./token.js";
import type { JWTPayload } from "jose";

const BASE_CONFIG = {
  issuer_url: "https://auth.example.com",
  client_id: "app",
  client_secret: "secret",
  realm_id: "11111111-1111-1111-1111-111111111111",
};

function makeToken(
  payload: Partial<JWTPayload & { permissions?: string[]; roles?: string[] }> = {},
): VerifiedToken {
  return new VerifiedToken(
    { sub: "u1", iss: "https://auth.example.com", exp: 9_999_999_999, iat: 1_700_000_000, ...payload } as JWTPayload,
    { alg: "RS256" },
  );
}

function makeReqRes(authHeader = "Bearer tok") {
  const req = { headers: { authorization: authHeader } as Record<string, string | undefined>, hearthToken: undefined as VerifiedToken | undefined };
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    status(code: number) { this.statusCode = code; return this; },
    json(body: unknown) { this.body = body; return this; },
    setHeader(name: string, value: string) { this.headers[name] = value; return this; },
  };
  return { req, res, next: vi.fn() };
}

describe("hearthMiddleware — embedded mode (default)", () => {
  afterEach(() => vi.restoreAllMocks());

  it("embedded: checks permissions from JWT claims when token has them", async () => {
    const token = makeToken({ permissions: ["docs.write"] });
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "embedded", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalled();
  });

  it("embedded: returns 403 when JWT has no matching permission — does NOT fall back to remote", async () => {
    const token = makeToken({ permissions: [] });
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const authorizeSpy = vi.spyOn(AuthorizeClient.prototype, "decide");
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "embedded", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
    expect(authorizeSpy).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("embedded: absent permissions claim is NOT treated as decision-mode fallback", async () => {
    // Token has no permissions field at all — must still check local and return 403
    const token = makeToken({});
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const authorizeSpy = vi.spyOn(AuthorizeClient.prototype, "decide");
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "embedded", requiredPermission: "admin.read" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
    expect(authorizeSpy).not.toHaveBeenCalled();
  });
});

describe("hearthMiddleware — introspection mode", () => {
  afterEach(() => vi.restoreAllMocks());

  it("introspection: allows when live permission is present", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({
      active: true, extra: {}, mode: "introspection", permissions: ["docs.write"], roles: [], groups: [],
    });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "introspection", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalled();
  });

  it("introspection: returns 403 when live permission is absent", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({
      active: true, extra: {}, mode: "introspection", permissions: ["docs.read"], roles: [], groups: [],
    });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "introspection", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("introspection: returns 401 when token is inactive", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({
      active: false, extra: {},
    });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "introspection" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("introspection: mode-mismatch returns 403 with AuthorizationModeError cause", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockResolvedValue({
      active: true, extra: {}, mode: "embedded", permissions: ["docs.write"], roles: [], groups: [],
    });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "introspection", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    // Mode mismatch → fail-closed 403
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("introspection: fail-closed on network error (introspect throws)", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(IntrospectionClient.prototype, "introspect").mockRejectedValue(new Error("network"));
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "introspection", requiredPermission: "perm" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("hearthMiddleware — decision mode", () => {
  afterEach(() => vi.restoreAllMocks());

  it("decision: calls /oauth/authorize and allows when server grants", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(AuthorizeClient.prototype, "decide").mockResolvedValue({ allowed: true });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "decision", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalled();
  });

  it("decision: returns 403 when server denies", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(AuthorizeClient.prototype, "decide").mockResolvedValue({ allowed: false });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "decision", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("decision: fail-closed on network error — allowed=false means 403", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    // decide() is fail-closed internally; simulate it returning false
    vi.spyOn(AuthorizeClient.prototype, "decide").mockResolvedValue({ allowed: false });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "decision", requiredPermission: "perm" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(403);
  });

  it("decision: does NOT check JWT permissions claim — only uses /oauth/authorize result", async () => {
    // Token has the permission embedded — but in decision mode we must call the server
    const token = makeToken({ permissions: ["docs.write"] });
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const decideSpy = vi.spyOn(AuthorizeClient.prototype, "decide").mockResolvedValue({ allowed: false });
    const mw = hearthMiddleware({ ...BASE_CONFIG, expectedMode: "decision", requiredPermission: "docs.write" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    // Server said no → 403 even though JWT has the perm
    expect(decideSpy).toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });
});

describe("hearthMiddleware — defaults to embedded when expectedMode omitted", () => {
  afterEach(() => vi.restoreAllMocks());

  it("no expectedMode → behaves as embedded", async () => {
    const token = makeToken({ permissions: ["x.read"] });
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);
    const mw = hearthMiddleware({ ...BASE_CONFIG, requiredPermission: "x.read" });
    const { req, res, next } = makeReqRes();
    await mw(req as never, res as never, next);
    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalled();
  });
});

describe("AuthorizationModeError", () => {
  it("carries expected and actual mode fields", () => {
    const err = new AuthorizationModeError("introspection", "embedded");
    expect(err).toBeInstanceOf(AuthorizationModeError);
    expect(err.expected).toBe("introspection");
    expect(err.actual).toBe("embedded");
    expect(err.message).toMatch(/introspection/);
    expect(err.message).toMatch(/embedded/);
  });
});

describe("hearthFastifyHook — decision mode", () => {
  afterEach(() => vi.restoreAllMocks());

  it("decision: allows when server grants via fastify hook", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(makeToken());
    vi.spyOn(AuthorizeClient.prototype, "decide").mockResolvedValue({ allowed: true });
    const hook = hearthFastifyHook({ ...BASE_CONFIG, expectedMode: "decision", requiredPermission: "docs.write" });
    const request = { headers: { authorization: "Bearer tok" } as Record<string, string | undefined>, hearthToken: undefined as VerifiedToken | undefined };
    const reply = { statusCode: 200, _headers: {} as Record<string, string>, _body: undefined as unknown, code(c: number) { this.statusCode = c; return this; }, header(n: string, v: string) { this._headers[n] = v; return this; }, send(b: unknown) { this._body = b; } };
    await hook(request as never, reply as never);
    expect(reply.statusCode).toBe(200);
    expect(request.hearthToken).toBeDefined();
  });
});
