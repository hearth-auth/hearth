/**
 * Next.js Node-runtime helpers (ported from the Node SDK's nextjs tests).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { HearthClient } from "../src/hearth-client.js";
import { Claims } from "../src/claims.js";
import { withHearthAuth, getHearthClaims } from "../src/nextjs/index.js";

const ISSUER = "https://auth.example.com";

function makeClient(): HearthClient {
  return new HearthClient({ issuerUrl: ISSUER, clientId: "app" });
}

function verifiesAs(payload: Record<string, unknown> = {}): Claims {
  const c = new Claims({ sub: "user1", iss: ISSUER, exp: 9_999_999_999, ...payload });
  vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(c);
  return c;
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ── withHearthAuth — Pages Router ──────────────────────────────────────────

function makeReqRes(authHeader?: string) {
  const req = {
    headers: { authorization: authHeader } as Record<string, string | undefined>,
    hearthClaims: undefined as Claims | undefined,
  };
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string | string[]>,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
    },
    setHeader(name: string, value: string | string[]) {
      this.headers[name] = value;
    },
  };
  return { req, res };
}

describe("withHearthAuth", () => {
  it("sets req.hearthClaims and calls the handler when the token verifies", async () => {
    const c = verifiesAs();
    const handler = vi.fn();
    const { req, res } = makeReqRes("Bearer valid-token");
    await withHearthAuth(handler, { client: makeClient() })(req, res);
    expect(handler).toHaveBeenCalledWith(req, res);
    expect(req.hearthClaims).toBe(c);
  });

  it("answers 401 without calling the handler when no Bearer token is sent", async () => {
    const handler = vi.fn();
    const { req, res } = makeReqRes();
    await withHearthAuth(handler, { client: makeClient() })(req, res);
    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
  });

  it("answers 401 without calling the handler when verification fails", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockRejectedValue(new Error("bad token"));
    const handler = vi.fn();
    const { req, res } = makeReqRes("Bearer bad");
    await withHearthAuth(handler, { client: makeClient() })(req, res);
    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it("answers 403 without calling the handler when the permission is missing", async () => {
    verifiesAs({ permissions: ["users:read"] });
    const handler = vi.fn();
    const { req, res } = makeReqRes("Bearer t");
    await withHearthAuth(handler, { client: makeClient(), requiredPermission: "users:write" })(
      req,
      res,
    );
    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it("answers 403 without calling the handler when the role is missing", async () => {
    verifiesAs({ roles: ["viewer"] });
    const handler = vi.fn();
    const { req, res } = makeReqRes("Bearer t");
    await withHearthAuth(handler, { client: makeClient(), requiredRole: "admin" })(req, res);
    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it("propagates an error thrown by the handler", async () => {
    verifiesAs();
    const handler = vi.fn().mockRejectedValue(new Error("handler failed"));
    const { req, res } = makeReqRes("Bearer t");
    await expect(withHearthAuth(handler, { client: makeClient() })(req, res)).rejects.toThrow(
      "handler failed",
    );
  });
});

// ── getHearthClaims — App Router Route Handlers ────────────────────────────

function makeRequest(authHeader?: string) {
  return {
    headers: {
      get: (n: string) => (n.toLowerCase() === "authorization" ? (authHeader ?? null) : null),
    },
  };
}

describe("getHearthClaims", () => {
  it("returns the Claims when the Bearer token verifies", async () => {
    const c = verifiesAs({ sub: "user-42" });
    const result = await getHearthClaims(makeRequest("Bearer good-token"), makeClient());
    expect(result).toBe(c);
    expect(result?.subject()).toBe("user-42");
  });

  it("returns null when no Authorization header is present", async () => {
    expect(await getHearthClaims(makeRequest(), makeClient())).toBeNull();
  });

  it("returns null when Authorization is not a Bearer token", async () => {
    expect(await getHearthClaims(makeRequest("Basic dXNlcjpwYXNz"), makeClient())).toBeNull();
  });

  it("returns null when verification throws", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockRejectedValue(new Error("expired"));
    expect(await getHearthClaims(makeRequest("Bearer expired"), makeClient())).toBeNull();
  });

  it("returns null for a required_action token", async () => {
    verifiesAs({ token_type: "required_action", required_actions: ["VERIFY_EMAIL"] });
    expect(await getHearthClaims(makeRequest("Bearer t"), makeClient())).toBeNull();
  });
});
