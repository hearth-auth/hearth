import { describe, it, expect } from "vitest";
import { VerifiedToken } from "./token.js";
import type { JWTPayload } from "jose";

function makeToken(overrides: Partial<JWTPayload & { scope?: string; scopes?: string[]; roles?: string[]; permissions?: string[]; groups?: string[]; oid?: string; org_groups?: string[]; token_type?: string; jti?: string }> = {}): VerifiedToken {
  const payload: JWTPayload = {
    sub: "user123",
    iss: "https://auth.example.com",
    aud: ["api.example.com", "admin.example.com"],
    iat: 1_700_000_000,
    exp: 1_700_003_600,
    nbf: 1_700_000_000,
    ...overrides,
  };
  return new VerifiedToken(payload, { alg: "RS256", kid: "key-1" });
}

describe("VerifiedToken claims accessors", () => {
  it("subject() returns sub", () => expect(makeToken().subject()).toBe("user123"));
  it("issuer() returns iss", () => expect(makeToken().issuer()).toBe("https://auth.example.com"));
  it("audiences() returns normalized array", () => expect(makeToken().audiences()).toEqual(["api.example.com", "admin.example.com"]));
  it("audiences() returns [] when absent", () => expect(makeToken({ aud: undefined }).audiences()).toEqual([]));
  it("audiences() wraps single string in array", () => expect(makeToken({ aud: "only.one" }).audiences()).toEqual(["only.one"]));
  it("issuedAt() returns Date", () => expect(makeToken().issuedAt()).toEqual(new Date(1_700_000_000_000)));
  it("expiry() returns Date", () => expect(makeToken().expiry()).toEqual(new Date(1_700_003_600_000)));
  it("notBefore() returns Date", () => expect(makeToken().notBefore()).toEqual(new Date(1_700_000_000_000)));
  it("issuedAt/expiry/notBefore return null when absent", () => {
    const t = makeToken({ iat: undefined, exp: undefined, nbf: undefined });
    expect(t.issuedAt()).toBeNull();
    expect(t.expiry()).toBeNull();
    expect(t.notBefore()).toBeNull();
  });

  it("jwtID() returns jti claim", () => {
    const t = makeToken({ jti: "unique-jwt-id-123" } as unknown as JWTPayload);
    expect(t.jwtID()).toBe("unique-jwt-id-123");
  });
  it("jwtID() returns empty string when absent", () => {
    expect(makeToken().jwtID()).toBe("");
  });

  it("scope() returns raw scope string", () => {
    const t = makeToken({ scope: "openid profile email" } as JWTPayload);
    expect(t.scope()).toBe("openid profile email");
  });

  it("scopes() splits scope string", () => {
    const t = makeToken({ scope: "openid profile email" } as JWTPayload);
    expect(t.scopes()).toEqual(["openid", "profile", "email"]);
  });

  it("scopes() prefers scopes array over scope string", () => {
    const t = makeToken({ scopes: ["a", "b"] } as unknown as JWTPayload);
    expect(t.scopes()).toEqual(["a", "b"]);
  });

  it("get(key) returns arbitrary claim", () => {
    const t = makeToken({ custom_claim: "hello" } as unknown as JWTPayload);
    expect(t.get("custom_claim")).toBe("hello");
  });

  it("raw() returns frozen payload copy", () => {
    const t = makeToken();
    const r = t.raw();
    expect(r.sub).toBe("user123");
    expect(Object.isFrozen(r)).toBe(true);
  });
});

describe("VerifiedToken hasScope / hasRole / hasPermission (timing-safe)", () => {
  it("hasScope returns true for present scope", () => {
    const t = makeToken({ scope: "openid read:users" } as unknown as JWTPayload);
    expect(t.hasScope("openid")).toBe(true);
    expect(t.hasScope("read:users")).toBe(true);
  });
  it("hasScope returns false for absent scope", () => {
    const t = makeToken({ scope: "openid" } as unknown as JWTPayload);
    expect(t.hasScope("admin")).toBe(false);
  });
  it("hasRole returns true/false correctly", () => {
    const t = makeToken({ roles: ["admin", "viewer"] } as unknown as JWTPayload);
    expect(t.hasRole("admin")).toBe(true);
    expect(t.hasRole("superuser")).toBe(false);
  });
  it("hasPermission returns true/false correctly", () => {
    const t = makeToken({ permissions: ["users:read", "users:write"] } as unknown as JWTPayload);
    expect(t.hasPermission("users:read")).toBe(true);
    expect(t.hasPermission("users:delete")).toBe(false);
  });
  it("hasScope handles empty scopes gracefully", () => {
    const t = makeToken({});
    expect(t.hasScope("anything")).toBe(false);
  });
});

describe("VerifiedToken Hearth custom claims", () => {
  it("inGroup() returns true when group is present", () => {
    const t = makeToken({ groups: ["admins", "developers"] } as unknown as JWTPayload);
    expect(t.inGroup("admins")).toBe(true);
    expect(t.inGroup("developers")).toBe(true);
  });
  it("inGroup() returns false when group is absent", () => {
    const t = makeToken({ groups: ["admins"] } as unknown as JWTPayload);
    expect(t.inGroup("viewers")).toBe(false);
  });
  it("inGroup() returns false when groups claim is missing", () => {
    expect(makeToken().inGroup("anything")).toBe(false);
  });

  it("inOrg() returns true when oid matches", () => {
    const t = makeToken({ oid: "org_abc123" } as unknown as JWTPayload);
    expect(t.inOrg("org_abc123")).toBe(true);
  });
  it("inOrg() returns false when oid does not match", () => {
    const t = makeToken({ oid: "org_abc123" } as unknown as JWTPayload);
    expect(t.inOrg("org_xyz789")).toBe(false);
  });
  it("inOrg() returns false when oid claim is missing", () => {
    expect(makeToken().inOrg("org_abc123")).toBe(false);
  });

  it("tokenType() returns token_type claim", () => {
    const t = makeToken({ token_type: "access" } as unknown as JWTPayload);
    expect(t.tokenType()).toBe("access");
  });
  it("tokenType() returns empty string when absent", () => {
    expect(makeToken().tokenType()).toBe("");
  });
  it("tokenType() returns required_action for required-action tokens", () => {
    const t = makeToken({ token_type: "required_action" } as unknown as JWTPayload);
    expect(t.tokenType()).toBe("required_action");
  });

  it("organizationId() returns oid claim", () => {
    const t = makeToken({ oid: "org_abc123" } as unknown as JWTPayload);
    expect(t.organizationId()).toBe("org_abc123");
  });
  it("organizationId() returns undefined when absent", () => {
    expect(makeToken().organizationId()).toBeUndefined();
  });

  it("orgGroups() returns org_groups claim array", () => {
    const t = makeToken({ org_groups: ["/acme/engineers", "/acme/admins"] } as unknown as JWTPayload);
    expect(t.orgGroups()).toEqual(["/acme/engineers", "/acme/admins"]);
  });
  it("orgGroups() returns empty array when absent", () => {
    expect(makeToken().orgGroups()).toEqual([]);
  });
});
