import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createHearth, type HearthOptions } from "../src/hearth.js";
import { makeIssuer, type TestIssuer } from "./issuer.js";

/**
 * The `createHearth` facade verifies the token (EdDSA signature against the
 * realm JWKS, `exp`, `iss`, `aud`) before it reads a claim. A token that does
 * not verify holds nothing. Spec: sdk-support-contract, "Claim checks verify
 * the token signature".
 */

let realm: TestIssuer;

beforeAll(async () => {
  realm = await makeIssuer();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function facade(getToken: HearthOptions["getToken"], extra: Partial<HearthOptions> = {}) {
  vi.stubGlobal("fetch", vi.fn(realm.fetchImpl()));
  return createHearth({
    baseUrl: "https://hearth.example.com",
    realmId: "r1",
    issuerUrl: realm.issuer,
    getToken,
    ...extra,
  });
}

/** A three-segment token with an arbitrary signature. */
function forgeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: "test-key" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  return `${header}.${body}.${Buffer.from("not-a-real-signature").toString("base64url")}`;
}

describe("createHearth — signature verification", () => {
  it("returns false for a permission added to the claims after signing", async () => {
    const signed = await realm.sign({ sub: "user_1", permissions: ["docs.view"] });
    const tampered = realm.tamper(signed, { permissions: ["docs.view", "docs.admin"] });
    const hearth = facade(() => tampered);
    expect(await hearth.hasPermission("docs.admin")).toBe(false);
  });

  it("returns false for a role, group or org added after signing", async () => {
    const tampered = realm.tamper(await realm.sign({ sub: "user_1" }), {
      roles: ["admin"],
      groups: ["engineering"],
      oid: "org_42",
    });
    const hearth = facade(() => tampered);
    expect(await hearth.hasRole("admin")).toBe(false);
    expect(await hearth.inGroup("engineering")).toBe(false);
    expect(await hearth.inOrg("org_42")).toBe(false);
  });

  it("returns false for a token with an arbitrary signature", async () => {
    const hearth = facade(() => forgeJwt({ iss: realm.issuer, aud: "hearth", permissions: ["x"] }));
    expect(await hearth.hasPermission("x")).toBe(false);
  });

  it("returns false for a token minted for another API", async () => {
    const token = await realm.sign({ aud: "other-api", permissions: ["x"] });
    expect(await facade(() => token).hasPermission("x")).toBe(false);
  });

  it("checks the configured audience", async () => {
    const token = await realm.sign({ aud: "https://api.example.com", permissions: ["x"] });
    const hearth = facade(() => token, { audience: "https://api.example.com" });
    expect(await hearth.hasPermission("x")).toBe(true);
  });

  it("accepts a token from an async getToken", async () => {
    const token = await realm.sign({ permissions: ["x"] });
    expect(await facade(async () => token).hasPermission("x")).toBe(true);
  });
});

describe("createHearth — hasPermission", () => {
  it("returns true when the verified permissions claim contains the permission", async () => {
    const token = await realm.sign({ sub: "user_1", permissions: ["docs.edit", "docs.view"] });
    const hearth = facade(() => token);
    expect(await hearth.hasPermission("docs.edit")).toBe(true);
    expect(await hearth.hasPermission("docs.view")).toBe(true);
  });

  it("returns false when the permission is absent", async () => {
    const token = await realm.sign({ permissions: ["docs.view"] });
    expect(await facade(() => token).hasPermission("docs.edit")).toBe(false);
  });

  it("returns false when the token is absent", async () => {
    expect(await facade(() => null).hasPermission("docs.edit")).toBe(false);
  });

  it("returns false when the token is malformed", async () => {
    expect(await facade(() => "not.a.jwt").hasPermission("docs.edit")).toBe(false);
  });

  it("returns false when the permissions claim is missing", async () => {
    const token = await realm.sign({ sub: "user_1" });
    expect(await facade(() => token).hasPermission("docs.edit")).toBe(false);
  });

  it("calls getToken on every invocation (no caching)", async () => {
    let current: string | null = null;
    const hearth = facade(() => current);
    expect(await hearth.hasPermission("docs.edit")).toBe(false);
    current = await realm.sign({ permissions: ["docs.edit"] });
    expect(await hearth.hasPermission("docs.edit")).toBe(true);
    current = null;
    expect(await hearth.hasPermission("docs.edit")).toBe(false);
  });
});

describe("createHearth — hasRole", () => {
  it("returns true when the verified roles claim contains the role", async () => {
    const token = await realm.sign({ roles: ["admin", "editor"] });
    const hearth = facade(() => token);
    expect(await hearth.hasRole("admin")).toBe(true);
    expect(await hearth.hasRole("viewer")).toBe(false);
  });

  it("returns false when the roles claim is malformed", async () => {
    const token = await realm.sign({ roles: "admin" });
    expect(await facade(() => token).hasRole("admin")).toBe(false);
  });
});

describe("createHearth — inGroup", () => {
  it("returns true when the verified groups claim contains the group", async () => {
    const token = await realm.sign({ groups: ["engineering", "security"] });
    const hearth = facade(() => token);
    expect(await hearth.inGroup("engineering")).toBe(true);
    expect(await hearth.inGroup("marketing")).toBe(false);
  });

  it("returns false when no token", async () => {
    expect(await facade(() => undefined).inGroup("engineering")).toBe(false);
  });
});

describe("createHearth — inOrg", () => {
  it("returns true when the verified oid claim equals the org", async () => {
    const token = await realm.sign({ oid: "org_42" });
    const hearth = facade(() => token);
    expect(await hearth.inOrg("org_42")).toBe(true);
    expect(await hearth.inOrg("org_7")).toBe(false);
  });

  it("returns false when oid is missing", async () => {
    const token = await realm.sign({ sub: "user_1" });
    expect(await facade(() => token).inOrg("org_42")).toBe(false);
  });
});
