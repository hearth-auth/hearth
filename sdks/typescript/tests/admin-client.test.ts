/**
 * AdminClient construction, pagination and error handling (ported from the
 * Node SDK's admin tests).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AdminClient } from "../src/admin.js";
import { HearthError } from "../src/client.js";
import { ConfigurationError } from "../src/errors.js";

const BASE = "https://auth.example.com";
const REALM = "realm_abc";
const TOKEN = "admin-token";

let fetchSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchSpy = vi.fn();
  vi.stubGlobal("fetch", fetchSpy);
});
afterEach(() => vi.unstubAllGlobals());

function respond(body: string | null, status: number, contentType = "application/json") {
  fetchSpy.mockImplementation(() =>
    Promise.resolve(
      new Response(body, { status, headers: body ? { "Content-Type": contentType } : {} }),
    ),
  );
}

describe("AdminClient — construction", () => {
  it("throws ConfigurationError when baseUrl, realmId or accessToken is empty", () => {
    expect(() => new AdminClient("", REALM, TOKEN)).toThrow(ConfigurationError);
    expect(() => new AdminClient(BASE, "", TOKEN)).toThrow(ConfigurationError);
    expect(() => new AdminClient(BASE, REALM, "")).toThrow(ConfigurationError);
  });

  it("strips a trailing slash from baseUrl", async () => {
    respond(JSON.stringify({ id: "u1" }), 200);
    await new AdminClient(`${BASE}/`, REALM, TOKEN).getUser("u1");
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE}/admin/users/u1`);
  });
});

describe("AdminClient — pagination", () => {
  it("omits the query string when no page options are given", async () => {
    respond(JSON.stringify({ items: [], next_cursor: null }), 200);
    const admin = new AdminClient(BASE, REALM, TOKEN);
    await admin.listUsers();
    await admin.listRealms();
    await admin.listClients();
    await admin.listRoles();
    await admin.listGroups();
    const urls = fetchSpy.mock.calls.map((c) => String(c[0]));
    expect(urls).toEqual([
      `${BASE}/admin/users`,
      `${BASE}/admin/realms`,
      `${BASE}/admin/applications`,
      `${BASE}/admin/roles`,
      `${BASE}/admin/groups`,
    ]);
  });

  it("sends limit and cursor when given", async () => {
    respond(JSON.stringify({ items: [], next_cursor: null }), 200);
    await new AdminClient(BASE, REALM, TOKEN).listUsers({ limit: 25, cursor: "abc" });
    const url = new URL(String(fetchSpy.mock.calls[0][0]));
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("cursor")).toBe("abc");
  });

  it("returns items and next_cursor", async () => {
    respond(JSON.stringify({ items: [{ id: "u1" }], next_cursor: "next" }), 200);
    const page = await new AdminClient(BASE, REALM, TOKEN).listUsers();
    expect(page.items).toEqual([{ id: "u1" }]);
    expect(page.next_cursor).toBe("next");
  });
});

describe("AdminClient — error handling", () => {
  it("throws HearthError carrying the status and JSON body on 403", async () => {
    respond(JSON.stringify({ error: "forbidden" }), 403);
    const err = await new AdminClient(BASE, REALM, TOKEN).getUser("usr_1").catch((e) => e);
    expect(err).toBeInstanceOf(HearthError);
    expect(err.status).toBe(403);
    expect(err.body).toEqual({ error: "forbidden" });
  });

  it("throws HearthError with the status on 404", async () => {
    respond(JSON.stringify({ error: "not_found" }), 404);
    await expect(new AdminClient(BASE, REALM, TOKEN).getUser("missing")).rejects.toMatchObject({
      status: 404,
    });
  });

  it("throws HearthError (not a JSON SyntaxError) when the error body is not JSON", async () => {
    respond("<html>Bad Gateway</html>", 502, "text/html");
    const err = await new AdminClient(BASE, REALM, TOKEN).listUsers().catch((e) => e);
    expect(err).toBeInstanceOf(HearthError);
    expect(err.status).toBe(502);
    expect(err.body).toBe("<html>Bad Gateway</html>");
  });

  it("throws HearthError on a failed DELETE with an empty body", async () => {
    respond(null, 500);
    const err = await new AdminClient(BASE, REALM, TOKEN).deleteUser("u1").catch((e) => e);
    expect(err).toBeInstanceOf(HearthError);
    expect(err.status).toBe(500);
  });

  it("accepts 204 No Content from a write", async () => {
    respond(null, 204);
    await expect(
      new AdminClient(BASE, REALM, TOKEN).updateRole("r1", { name: "x" }),
    ).resolves.toBeUndefined();
  });

  it("always sends Authorization and X-Realm-ID headers", async () => {
    respond(JSON.stringify({ items: [], next_cursor: null }), 200);
    await new AdminClient(BASE, REALM, TOKEN).listUsers();
    const headers = new Headers((fetchSpy.mock.calls[0][1] as RequestInit).headers);
    expect(headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
    expect(headers.get("X-Realm-ID")).toBe(REALM);
  });
});
