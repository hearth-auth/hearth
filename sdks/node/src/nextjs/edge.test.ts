import { describe, it, expect, vi, beforeEach } from "vitest";
import { EdgeToken, hearthEdgeMiddleware, requirePermission } from "./edge.js";
import type { JWTPayload } from "jose";

// ── jose mock ─────────────────────────────────────────────────────────────────

// Mock jose so JWKS fetches never hit the network.
vi.mock("jose", () => {
  const mockJwkSet = vi.fn();
  return {
    createRemoteJWKSet: () => mockJwkSet,
    jwtVerify: vi.fn(),
  };
});

import { jwtVerify } from "jose";
const mockJwtVerify = jwtVerify as ReturnType<typeof vi.fn>;

// ── helpers ───────────────────────────────────────────────────────────────────

const BASE_OPTIONS = {
  issuerUrl: "https://auth.example.com",
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
};

function makeRequest(authHeader?: string): { headers: { get(n: string): string | null; entries(): IterableIterator<[string, string]> } } {
  const map: Record<string, string> = {};
  if (authHeader) map["authorization"] = authHeader;
  return {
    headers: {
      get: (n: string) => map[n.toLowerCase()] ?? null,
      entries: () => Object.entries(map)[Symbol.iterator]() as IterableIterator<[string, string]>,
    },
  };
}

function makePayload(extra: Partial<JWTPayload & {
  scope?: string;
  roles?: string[];
  permissions?: string[];
  token_type?: string;
}> = {}): JWTPayload {
  return {
    sub: "user1",
    iss: "https://auth.example.com",
    exp: 9_999_999_999,
    iat: 1_700_000_000,
    ...extra,
  };
}

function resolveJwtVerify(payload: JWTPayload): void {
  mockJwtVerify.mockResolvedValue({ payload, protectedHeader: { alg: "EdDSA" } });
}

function rejectJwtVerify(err: Error = new Error("invalid token")): void {
  mockJwtVerify.mockRejectedValue(err);
}

// ── EdgeToken ─────────────────────────────────────────────────────────────────

describe("EdgeToken", () => {
  it("returns subject, issuer, jwtID", () => {
    const t = new EdgeToken({ sub: "u1", iss: "https://auth.example.com", jti: "abc" }, { alg: "EdDSA" });
    expect(t.subject()).toBe("u1");
    expect(t.issuer()).toBe("https://auth.example.com");
    expect(t.jwtID()).toBe("abc");
  });

  it("normalizes audiences to array", () => {
    expect(new EdgeToken({ aud: "a" }, {}).audiences()).toEqual(["a"]);
    expect(new EdgeToken({ aud: ["a", "b"] }, {}).audiences()).toEqual(["a", "b"]);
    expect(new EdgeToken({}, {}).audiences()).toEqual([]);
  });

  it("parses scopes from space-separated scope claim", () => {
    const t = new EdgeToken({ scope: "openid profile email" } as JWTPayload, {});
    expect(t.scopes()).toEqual(["openid", "profile", "email"]);
    expect(t.hasScope("profile")).toBe(true);
    expect(t.hasScope("admin")).toBe(false);
  });

  it("prefers scopes array over scope string", () => {
    const t = new EdgeToken({ scopes: ["read", "write"], scope: "ignored" } as JWTPayload, {});
    expect(t.scopes()).toEqual(["read", "write"]);
  });

  it("checks roles", () => {
    const t = new EdgeToken({ roles: ["admin", "viewer"] } as JWTPayload, {});
    expect(t.hasRole("admin")).toBe(true);
    expect(t.hasRole("superuser")).toBe(false);
  });

  it("checks permissions", () => {
    const t = new EdgeToken({ permissions: ["users:read", "users:write"] } as JWTPayload, {});
    expect(t.hasPermission("users:read")).toBe(true);
    expect(t.hasPermission("users:delete")).toBe(false);
  });

  it("checks group membership", () => {
    const t = new EdgeToken({ groups: ["grp-1", "grp-2"] } as JWTPayload, {});
    expect(t.inGroup("grp-1")).toBe(true);
    expect(t.inGroup("grp-99")).toBe(false);
  });

  it("checks org membership", () => {
    const t = new EdgeToken({ oid: "org-123" } as JWTPayload, {});
    expect(t.inOrg("org-123")).toBe(true);
    expect(t.inOrg("org-456")).toBe(false);
  });

  it("returns token_type", () => {
    expect(new EdgeToken({ token_type: "required_action" } as JWTPayload, {}).tokenType()).toBe("required_action");
    expect(new EdgeToken({} as JWTPayload, {}).tokenType()).toBe("");
  });

  it("returns required_actions", () => {
    const t = new EdgeToken({ required_actions: ["verify_email"] } as JWTPayload, {});
    expect(t.requiredActions()).toEqual(["verify_email"]);
  });

  it("raw() returns frozen copy of payload", () => {
    const t = new EdgeToken({ sub: "u1" } as JWTPayload, {});
    const raw = t.raw();
    expect(raw.sub).toBe("u1");
    expect(Object.isFrozen(raw)).toBe(true);
  });

  it("expiry and issuedAt return Date objects", () => {
    const t = new EdgeToken({ exp: 9_999_999_999, iat: 1_700_000_000 } as JWTPayload, {});
    expect(t.expiry()).toBeInstanceOf(Date);
    expect(t.issuedAt()).toBeInstanceOf(Date);
  });
});

// ── requirePermission ─────────────────────────────────────────────────────────

describe("requirePermission", () => {
  it("returns true when token has the permission", () => {
    const token = new EdgeToken({ permissions: ["users:read"] } as JWTPayload, {});
    expect(requirePermission("users:read")(token)).toBe(true);
  });

  it("returns false when token lacks the permission", () => {
    const token = new EdgeToken({ permissions: ["users:read"] } as JWTPayload, {});
    expect(requirePermission("users:write")(token)).toBe(false);
  });

  it("returns false when permissions claim is absent", () => {
    const token = new EdgeToken({} as JWTPayload, {});
    expect(requirePermission("users:read")(token)).toBe(false);
  });
});

// ── hearthEdgeMiddleware ──────────────────────────────────────────────────────

describe("hearthEdgeMiddleware", () => {
  beforeEach(() => {
    mockJwtVerify.mockReset();
  });

  describe("missing token", () => {
    it("returns 401 when no Authorization header and required=true (default)", async () => {
      const guard = hearthEdgeMiddleware(BASE_OPTIONS);
      const res = await guard(makeRequest());
      expect(res).toBeInstanceOf(Response);
      expect(res!.status).toBe(401);
      expect(res!.headers.get("WWW-Authenticate")).toBe('Bearer realm="hearth"');
      const body = await res!.json() as Record<string, string>;
      expect(body.error).toBe("unauthorized");
    });

    it("returns 401 when Authorization header is not Bearer", async () => {
      const guard = hearthEdgeMiddleware(BASE_OPTIONS);
      const res = await guard(makeRequest("Basic dXNlcjpwYXNz"));
      expect(res!.status).toBe(401);
    });

    it("returns undefined when no token and required=false", async () => {
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, required: false });
      const res = await guard(makeRequest());
      expect(res).toBeUndefined();
    });
  });

  describe("invalid token", () => {
    it("returns 401 when token verification fails", async () => {
      rejectJwtVerify(new Error("invalid signature"));
      const guard = hearthEdgeMiddleware(BASE_OPTIONS);
      const res = await guard(makeRequest("Bearer bad-token"));
      expect(res!.status).toBe(401);
    });

    it("returns undefined when token invalid and required=false", async () => {
      rejectJwtVerify();
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, required: false });
      const res = await guard(makeRequest("Bearer bad-token"));
      expect(res).toBeUndefined();
    });
  });

  describe("required_action tokens", () => {
    it("returns 401 for required_action token regardless of required flag", async () => {
      resolveJwtVerify(makePayload({ token_type: "required_action" }));
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, required: false });
      const res = await guard(makeRequest("Bearer action-token"));
      expect(res!.status).toBe(401);
      const body = await res!.json() as Record<string, string>;
      expect(body.error_description).toContain("required actions");
    });
  });

  describe("valid token — pass through", () => {
    it("returns undefined when token is valid and no guards configured", async () => {
      resolveJwtVerify(makePayload());
      const guard = hearthEdgeMiddleware(BASE_OPTIONS);
      const res = await guard(makeRequest("Bearer good-token"));
      expect(res).toBeUndefined();
    });
  });

  describe("scope guard", () => {
    it("returns 403 when token lacks required scope", async () => {
      resolveJwtVerify(makePayload({ scope: "openid profile" }));
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, requiredScope: "admin" });
      const res = await guard(makeRequest("Bearer token"));
      expect(res!.status).toBe(403);
      const body = await res!.json() as Record<string, string>;
      expect(body.error).toBe("forbidden");
    });

    it("passes when token has the required scope", async () => {
      resolveJwtVerify(makePayload({ scope: "openid admin" }));
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, requiredScope: "admin" });
      const res = await guard(makeRequest("Bearer token"));
      expect(res).toBeUndefined();
    });
  });

  describe("role guard", () => {
    it("returns 403 when token lacks required role", async () => {
      resolveJwtVerify(makePayload({ roles: ["viewer"] }));
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, requiredRole: "admin" });
      const res = await guard(makeRequest("Bearer token"));
      expect(res!.status).toBe(403);
    });

    it("passes when token has the required role", async () => {
      resolveJwtVerify(makePayload({ roles: ["admin", "viewer"] }));
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, requiredRole: "admin" });
      const res = await guard(makeRequest("Bearer token"));
      expect(res).toBeUndefined();
    });
  });

  describe("permission guard", () => {
    it("returns 403 when token lacks required permission", async () => {
      resolveJwtVerify(makePayload({ permissions: ["users:read"] }));
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, requiredPermission: "users:write" });
      const res = await guard(makeRequest("Bearer token"));
      expect(res!.status).toBe(403);
    });

    it("passes when token has the required permission", async () => {
      resolveJwtVerify(makePayload({ permissions: ["users:read", "users:write"] }));
      const guard = hearthEdgeMiddleware({ ...BASE_OPTIONS, requiredPermission: "users:write" });
      const res = await guard(makeRequest("Bearer token"));
      expect(res).toBeUndefined();
    });
  });
});
