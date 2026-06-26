import { describe, it, expect, vi, beforeEach } from "vitest";
import { withHearthAuth, getHearthToken } from "./index.js";
import { HearthClient } from "../client.js";
import { VerifiedToken } from "../token.js";
import type { JWTPayload } from "jose";

// ── Helpers ───────────────────────────────────────────────────────────────────

const BASE_CONFIG = {
  issuer_url: "https://auth.example.com",
  client_id: "app",
  client_secret: "secret",
};

function makeVerifiedToken(
  extra: Partial<JWTPayload & { scope?: string; permissions?: string[]; roles?: string[] }> = {},
): VerifiedToken {
  return new VerifiedToken(
    {
      sub: "user1",
      iss: "https://auth.example.com",
      exp: 9_999_999_999,
      iat: 1_700_000_000,
      ...extra,
    } as JWTPayload,
    { alg: "EdDSA" },
  );
}

// ── withHearthAuth — Pages Router wrapper ─────────────────────────────────────

describe("withHearthAuth", () => {
  beforeEach(() => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockReset();
  });

  function makeReqRes(authHeader?: string) {
    const req = {
      headers: { authorization: authHeader } as Record<string, string | undefined>,
      hearthToken: undefined as VerifiedToken | undefined,
    };
    const res = {
      statusCode: 200,
      body: undefined as unknown,
      headers: {} as Record<string, string>,
      writableEnded: false,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json(body: unknown) {
        this.body = body;
        this.writableEnded = true;
        return this;
      },
      setHeader(name: string, value: string) {
        this.headers[name] = value;
        return this;
      },
    };
    return { req, res };
  }

  it("attaches hearthToken to req and calls handler when token is valid", async () => {
    const token = makeVerifiedToken();
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);

    const handler = vi.fn();
    const wrapped = withHearthAuth(handler, BASE_CONFIG);
    const { req, res } = makeReqRes("Bearer valid-token");

    await wrapped(req as never, res as never);

    expect(handler).toHaveBeenCalled();
    expect(req.hearthToken).toBe(token);
  });

  it("returns 401 and does not call handler when Bearer token is absent", async () => {
    const handler = vi.fn();
    const wrapped = withHearthAuth(handler, BASE_CONFIG);
    const { req, res } = makeReqRes();

    await wrapped(req as never, res as never);

    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.headers["WWW-Authenticate"]).toBe('Bearer realm="hearth"');
  });

  it("returns 401 and does not call handler when token verification fails", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockRejectedValue(new Error("bad token"));
    const handler = vi.fn();
    const wrapped = withHearthAuth(handler, BASE_CONFIG);
    const { req, res } = makeReqRes("Bearer bad");

    await wrapped(req as never, res as never);

    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it("returns 403 and does not call handler when token lacks required permission", async () => {
    const token = makeVerifiedToken({ permissions: ["users:read"] });
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);

    const handler = vi.fn();
    const wrapped = withHearthAuth(handler, { ...BASE_CONFIG, requiredPermission: "users:write" });
    const { req, res } = makeReqRes("Bearer token");

    await wrapped(req as never, res as never);

    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it("returns 403 and does not call handler when token lacks required role", async () => {
    const token = makeVerifiedToken({ roles: ["viewer"] });
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);

    const handler = vi.fn();
    const wrapped = withHearthAuth(handler, { ...BASE_CONFIG, requiredRole: "admin" });
    const { req, res } = makeReqRes("Bearer token");

    await wrapped(req as never, res as never);

    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });
});

// ── getHearthToken — App Router Route Handler helper ──────────────────────────

describe("getHearthToken", () => {
  beforeEach(() => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockReset();
  });

  function makeRequest(authHeader?: string) {
    return {
      headers: {
        get: (n: string) => (n.toLowerCase() === "authorization" ? (authHeader ?? null) : null),
      },
    };
  }

  it("returns a VerifiedToken when the Bearer token is valid", async () => {
    const token = makeVerifiedToken();
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);

    const req = makeRequest("Bearer good-token");
    const result = await getHearthToken(req, BASE_CONFIG);

    expect(result).toBe(token);
  });

  it("returns null when no Authorization header is present", async () => {
    const req = makeRequest();
    const result = await getHearthToken(req, BASE_CONFIG);
    expect(result).toBeNull();
  });

  it("returns null when Authorization is not a Bearer token", async () => {
    const req = makeRequest("Basic dXNlcjpwYXNz");
    const result = await getHearthToken(req, BASE_CONFIG);
    expect(result).toBeNull();
  });

  it("returns null when token verification throws", async () => {
    vi.spyOn(HearthClient.prototype, "verifyToken").mockRejectedValue(new Error("expired"));
    const req = makeRequest("Bearer expired-token");
    const result = await getHearthToken(req, BASE_CONFIG);
    expect(result).toBeNull();
  });

  it("returns a token with correct subject claim", async () => {
    const token = makeVerifiedToken({ sub: "user-42" });
    vi.spyOn(HearthClient.prototype, "verifyToken").mockResolvedValue(token);

    const req = makeRequest("Bearer some-token");
    const result = await getHearthToken(req, BASE_CONFIG);

    expect(result?.subject()).toBe("user-42");
  });
});
