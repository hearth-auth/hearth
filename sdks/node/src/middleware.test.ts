import { describe, it, expect, vi, beforeEach } from "vitest";
import { hearthMiddleware } from "./middleware.js";
import * as jwksModule from "./jwks.js";

describe("hearthMiddleware", () => {
  const mockVerify = vi.fn();

  beforeEach(() => {
    vi.spyOn(jwksModule.JwksClient.prototype, "verify").mockImplementation(mockVerify);
    mockVerify.mockReset();
  });

  function makeReqRes(authHeader?: string) {
    const req = { headers: { authorization: authHeader }, auth: undefined } as any;
    const res = {
      statusCode: 200,
      body: undefined as unknown,
      status(code: number) { this.statusCode = code; return this; },
      json(body: unknown) { this.body = body; return this; },
    };
    const next = vi.fn();
    return { req, res, next };
  }

  it("calls next with req.auth populated when token is valid", async () => {
    const payload = { sub: "user1", iss: "https://auth.example.com", exp: 9999999999, iat: 1 };
    mockVerify.mockResolvedValue({ payload });

    const middleware = hearthMiddleware({ issuer: "https://auth.example.com", clientId: "app" });
    const { req, res, next } = makeReqRes("Bearer valid-token");

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(req.auth).toEqual(payload);
  });

  it("returns 401 when no token provided (required=true default)", async () => {
    const middleware = hearthMiddleware({ issuer: "https://auth.example.com", clientId: "app" });
    const { req, res, next } = makeReqRes();

    await middleware(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("calls next without auth when token missing and required=false", async () => {
    const middleware = hearthMiddleware({ issuer: "https://auth.example.com", clientId: "app", required: false });
    const { req, res, next } = makeReqRes();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.auth).toBeUndefined();
  });

  it("returns 401 when token verification fails", async () => {
    mockVerify.mockRejectedValue(new Error("expired"));
    const middleware = hearthMiddleware({ issuer: "https://auth.example.com", clientId: "app" });
    const { req, res, next } = makeReqRes("Bearer bad-token");

    await middleware(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  // -----------------------------------------------------------------------
  // §HEA-591 — cookie token delivery
  // -----------------------------------------------------------------------

  describe("acceptCookieToken", () => {
    function makeReqWithCookie(cookieHeader?: string, authHeader?: string) {
      const headers: Record<string, string | undefined> = {};
      if (authHeader) headers.authorization = authHeader;
      if (cookieHeader) headers.cookie = cookieHeader;
      const req = { headers, auth: undefined } as any;
      const res = {
        statusCode: 200,
        body: undefined as unknown,
        status(code: number) { this.statusCode = code; return this; },
        json(body: unknown) { this.body = body; return this; },
      };
      const next = vi.fn();
      return { req, res, next };
    }

    it("returns 401 when no bearer and cookie extraction is disabled", async () => {
      const middleware = hearthMiddleware({
        issuer: "https://auth.example.com",
        clientId: "app",
      });
      const { req, res, next } = makeReqWithCookie("hearth_access_token=mytoken");

      await middleware(req, res, next);

      expect(res.statusCode).toBe(401);
      expect(next).not.toHaveBeenCalled();
    });

    it("extracts token from hearth_access_token cookie when acceptCookieToken=true", async () => {
      const payload = { sub: "cookie-user", iss: "https://auth.example.com", exp: 9999999999, iat: 1 };
      mockVerify.mockResolvedValue({ payload });

      const middleware = hearthMiddleware({
        issuer: "https://auth.example.com",
        clientId: "app",
        acceptCookieToken: true,
      });
      const { req, res, next } = makeReqWithCookie("hearth_access_token=mytoken; other=val");

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.auth).toEqual(payload);
      expect(mockVerify).toHaveBeenCalledWith("mytoken");
    });

    it("prefers Authorization: Bearer over cookie when both present", async () => {
      const payload = { sub: "bearer-user", iss: "https://auth.example.com", exp: 9999999999, iat: 1 };
      mockVerify.mockResolvedValue({ payload });

      const middleware = hearthMiddleware({
        issuer: "https://auth.example.com",
        clientId: "app",
        acceptCookieToken: true,
      });
      const { req, res, next } = makeReqWithCookie(
        "hearth_access_token=cookie-token",
        "Bearer bearer-token",
      );

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(mockVerify).toHaveBeenCalledWith("bearer-token");
    });

    it("returns 401 when cookie token is invalid", async () => {
      mockVerify.mockRejectedValue(new Error("invalid"));

      const middleware = hearthMiddleware({
        issuer: "https://auth.example.com",
        clientId: "app",
        acceptCookieToken: true,
      });
      const { req, res, next } = makeReqWithCookie("hearth_access_token=bad");

      await middleware(req, res, next);

      expect(res.statusCode).toBe(401);
      expect(next).not.toHaveBeenCalled();
    });

    it("handles URL-encoded cookie values", async () => {
      const payload = { sub: "u", iss: "https://auth.example.com", exp: 9999999999, iat: 1 };
      mockVerify.mockResolvedValue({ payload });

      const middleware = hearthMiddleware({
        issuer: "https://auth.example.com",
        clientId: "app",
        acceptCookieToken: true,
      });
      // Simulate a token with URL-encoded characters (e.g. base64url padding edge cases)
      const encoded = encodeURIComponent("tok%en=value");
      const { req, res, next } = makeReqWithCookie(`hearth_access_token=${encoded}`);

      await middleware(req, res, next);

      expect(mockVerify).toHaveBeenCalledWith("tok%en=value");
    });
  });
});
