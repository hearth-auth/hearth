/**
 * Unit tests for Claims class — spec §4.
 * Tests are written before implementation (TDD).
 */

import { describe, it, expect } from "vitest";
import { Claims } from "../src/claims.js";

/** Build a fake JWT string with the given payload (no signature verification). */
function forgeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url",
  );
  const sig = Buffer.from("fake-sig").toString("base64url");
  return `${header}.${body}.${sig}`;
}

// ── scope() ────────────────────────────────────────────────────────────────

describe("Claims.scope()", () => {
  it("returns the raw space-delimited scope string", () => {
    const c = new Claims({ scope: "openid profile email" });
    expect(c.scope()).toBe("openid profile email");
  });

  it("returns empty string when scope is absent", () => {
    const c = new Claims({});
    expect(c.scope()).toBe("");
  });
});

// ── inGroup() ──────────────────────────────────────────────────────────────

describe("Claims.inGroup()", () => {
  it("returns true when groups claim contains the group", () => {
    const c = new Claims({ groups: ["engineering", "security"] });
    expect(c.inGroup("engineering")).toBe(true);
    expect(c.inGroup("security")).toBe(true);
  });

  it("returns false when group is not in the list", () => {
    const c = new Claims({ groups: ["engineering"] });
    expect(c.inGroup("security")).toBe(false);
  });

  it("returns false when groups claim is absent", () => {
    const c = new Claims({});
    expect(c.inGroup("engineering")).toBe(false);
  });

  it("returns false when groups claim is not an array", () => {
    const c = new Claims({ groups: "engineering" as unknown });
    expect(c.inGroup("engineering")).toBe(false);
  });
});

// ── inOrg() ────────────────────────────────────────────────────────────────

describe("Claims.inOrg()", () => {
  it("returns true when oid claim exactly matches", () => {
    const c = new Claims({ oid: "org_abc123" });
    expect(c.inOrg("org_abc123")).toBe(true);
  });

  it("returns false when oid claim does not match", () => {
    const c = new Claims({ oid: "org_abc123" });
    expect(c.inOrg("org_xyz")).toBe(false);
  });

  it("returns false when oid claim is absent", () => {
    const c = new Claims({});
    expect(c.inOrg("org_abc123")).toBe(false);
  });
});

// ── tokenType() ────────────────────────────────────────────────────────────

describe("Claims.tokenType()", () => {
  it("returns the token_type claim value", () => {
    const c = new Claims({ token_type: "access" });
    expect(c.tokenType()).toBe("access");
  });

  it("returns 'required_action' for required-action tokens", () => {
    const c = new Claims({ token_type: "required_action" });
    expect(c.tokenType()).toBe("required_action");
  });

  it("returns 'refresh' for refresh tokens", () => {
    const c = new Claims({ token_type: "refresh" });
    expect(c.tokenType()).toBe("refresh");
  });

  it("returns empty string when token_type is absent", () => {
    const c = new Claims({});
    expect(c.tokenType()).toBe("");
  });
});

// ── organizationId() ──────────────────────────────────────────────────────

describe("Claims.organizationId()", () => {
  it("returns the oid claim value", () => {
    const c = new Claims({ oid: "org_abc123" });
    expect(c.organizationId()).toBe("org_abc123");
  });

  it("returns undefined when oid is absent", () => {
    const c = new Claims({});
    expect(c.organizationId()).toBeUndefined();
  });
});

// ── orgGroups() ────────────────────────────────────────────────────────────

describe("Claims.orgGroups()", () => {
  it("returns the org_groups claim array", () => {
    const c = new Claims({
      org_groups: ["/acme-corp/admins", "/acme-corp/engineering"],
    });
    expect(c.orgGroups()).toEqual(["/acme-corp/admins", "/acme-corp/engineering"]);
  });

  it("returns empty array when org_groups is absent", () => {
    const c = new Claims({});
    expect(c.orgGroups()).toEqual([]);
  });

  it("returns empty array when org_groups is not an array", () => {
    const c = new Claims({ org_groups: "invalid" as unknown });
    expect(c.orgGroups()).toEqual([]);
  });
});

// ── decode() integration — all new claims survive round-trip ──────────────

describe("Claims.decode() — new claims present in JWT", () => {
  it("parses all new claims from a forged JWT", () => {
    const jwt = forgeJwt({
      sub: "user_1",
      scope: "openid profile",
      groups: ["eng"],
      oid: "org_42",
      token_type: "access",
      org_groups: ["/org/eng"],
    });
    const c = Claims.decode(jwt);
    expect(c.scope()).toBe("openid profile");
    expect(c.inGroup("eng")).toBe(true);
    expect(c.inOrg("org_42")).toBe(true);
    expect(c.tokenType()).toBe("access");
    expect(c.organizationId()).toBe("org_42");
    expect(c.orgGroups()).toEqual(["/org/eng"]);
  });
});
