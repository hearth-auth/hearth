/**
 * §5.2 — Admin CRUD extended: Clients, Roles, Groups, Organizations.
 * TDD tests written before implementation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AdminClient } from "../src/admin.js";

const BASE = "https://auth.example.com";
const REALM = "realm_abc";
const TOKEN = "admin-token";

function makeAdmin() {
  return new AdminClient(BASE, REALM, TOKEN);
}

function mockOk(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function mockNoContent() {
  return new Response(null, { status: 204 });
}

beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
afterEach(() => vi.unstubAllGlobals());

// ── OAuth Clients ──────────────────────────────────────────────────────────

describe("AdminClient — OAuth Clients CRUD", () => {
  it("createClient POSTs to /admin/applications", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ client_id: "cli1", client_name: "My App" }, 201));
    const admin = makeAdmin();
    const result = await admin.createClient({
      client_name: "My App",
      redirect_uris: ["https://app.example.com/cb"],
    });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/applications`);
    expect(init.method).toBe("POST");
    expect(result).toMatchObject({ client_id: "cli1" });
  });

  it("getClient GETs /admin/applications/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ client_id: "cli1" }));
    await makeAdmin().getClient("cli1");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toBe(`${BASE}/admin/applications/cli1`);
  });

  // The server mounts the whole client family at /admin/applications*: the
  // mutation route is PATCH /admin/applications/{id}. /admin/clients* is not a
  // route at all — every call to it 404s
  // (audit 2026-08-28 §25.4, §25.18).
  it("updateClient PATCHes /admin/applications/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ client_id: "cli1", client_name: "Updated" }));
    await makeAdmin().updateClient("cli1", { client_name: "Updated" });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/applications/cli1`);
    expect(init.method).toBe("PATCH");
  });

  it("regenerateClientSecret POSTs /admin/applications/:id/regenerate-secret and returns the new secret", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ client_id: "cli1", client_secret: "new-secret" }));
    const result = await makeAdmin().regenerateClientSecret("cli1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/applications/cli1/regenerate-secret`);
    expect(init.method).toBe("POST");
    expect(result.client_secret).toBe("new-secret");
  });

  it("deleteClient DELETEs /admin/applications/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await makeAdmin().deleteClient("cli1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/applications/cli1`);
    expect(init.method).toBe("DELETE");
  });

  it("listClients GETs /admin/applications", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: [], next_cursor: null }));
    const result = await makeAdmin().listClients();
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toContain("/admin/applications");
    expect(result).toMatchObject({ items: [] });
  });
});

// ── Roles ──────────────────────────────────────────────────────────────────

describe("AdminClient — Roles CRUD", () => {
  it("createRole POSTs to /admin/roles", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ id: "role1", name: "editor" }, 201));
    const result = await makeAdmin().createRole({ name: "editor" });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/roles`);
    expect(init.method).toBe("POST");
    expect(result).toMatchObject({ id: "role1" });
  });

  it("getRole GETs /admin/roles/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ id: "role1" }));
    await makeAdmin().getRole("role1");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toBe(`${BASE}/admin/roles/role1`);
  });

  it("updateRole PATCHes /admin/roles/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ id: "role1" }));
    await makeAdmin().updateRole("role1", { name: "super-editor" });
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("PATCH");
  });

  it("deleteRole DELETEs /admin/roles/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await makeAdmin().deleteRole("role1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/roles/role1`);
    expect(init.method).toBe("DELETE");
  });

  it("listRoles GETs /admin/roles", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: [], next_cursor: null }));
    await makeAdmin().listRoles();
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toContain("/admin/roles");
  });
});

// ── Groups ─────────────────────────────────────────────────────────────────

describe("AdminClient — Groups CRUD", () => {
  it("createGroup POSTs to /admin/groups", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ id: "grp1", name: "engineers" }, 201));
    const result = await makeAdmin().createGroup({ name: "engineers" });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/groups`);
    expect(init.method).toBe("POST");
    expect(result).toMatchObject({ id: "grp1" });
  });

  it("getGroup GETs /admin/groups/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ id: "grp1" }));
    await makeAdmin().getGroup("grp1");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toBe(`${BASE}/admin/groups/grp1`);
  });

  it("updateGroup PATCHes /admin/groups/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ id: "grp1" }));
    await makeAdmin().updateGroup("grp1", { name: "senior-engineers" });
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("PATCH");
  });

  it("deleteGroup DELETEs /admin/groups/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await makeAdmin().deleteGroup("grp1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/groups/grp1`);
    expect(init.method).toBe("DELETE");
  });

  it("listGroups GETs /admin/groups", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: [], next_cursor: null }));
    await makeAdmin().listGroups();
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toContain("/admin/groups");
  });
});

// ── Organizations ──────────────────────────────────────────────────────────

const ORG = {
  id: "0b6c1f0e-0000-4000-8000-000000000001",
  slug: "acme",
  display_name: "Acme",
  status: "active",
  member_limit: null,
  mfa_required: false,
  attributes: { tier: "gold" },
  created_at: 1_700_000_000_000_000,
  updated_at: 1_700_000_000_000_000,
};

function lastCall(): [string, RequestInit] {
  const calls = vi.mocked(fetch).mock.calls;
  return calls[calls.length - 1] as [string, RequestInit];
}

describe("AdminClient — Organizations", () => {
  it("listOrganizations GETs /admin/organizations with page options and decodes the page", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: [ORG], next_cursor: "50" }));
    const page = await makeAdmin().listOrganizations({ limit: 50, cursor: "0" });
    const [url, init] = lastCall();
    const parsed = new URL(url);
    expect(parsed.pathname).toBe("/admin/organizations");
    expect(parsed.searchParams.get("limit")).toBe("50");
    expect(parsed.searchParams.get("cursor")).toBe("0");
    expect(init.method).toBe("GET");
    expect(page).toEqual({ items: [ORG], next_cursor: "50" });
  });

  it("listOrganizations maps an absent next_cursor to null", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: [] }));
    expect(await makeAdmin().listOrganizations()).toEqual({ items: [], next_cursor: null });
    expect(lastCall()[0]).toBe(`${BASE}/admin/organizations`);
  });

  it("createOrganization POSTs the snake_case body and decodes the 201", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk(ORG, 201));
    const org = await makeAdmin().createOrganization({
      slug: "acme",
      display_name: "Acme",
      mfa_required: true,
      attributes: { tier: "gold" },
    });
    const [url, init] = lastCall();
    expect(url).toBe(`${BASE}/admin/organizations`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({
      slug: "acme",
      display_name: "Acme",
      mfa_required: true,
      attributes: { tier: "gold" },
    });
    expect(new Headers(init.headers).get("X-Realm-ID")).toBe(REALM);
    expect(org).toEqual(ORG);
  });

  it("getOrganization GETs /admin/organizations/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk(ORG));
    const org = await makeAdmin().getOrganization(ORG.id);
    const [url, init] = lastCall();
    expect(url).toBe(`${BASE}/admin/organizations/${ORG.id}`);
    expect(init.method).toBe("GET");
    expect(org.slug).toBe("acme");
  });

  it("updateOrganization PATCHes only the given fields", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ ...ORG, status: "suspended" }));
    const org = await makeAdmin().updateOrganization(ORG.id, { status: "suspended" });
    const [url, init] = lastCall();
    expect(url).toBe(`${BASE}/admin/organizations/${ORG.id}`);
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(String(init.body))).toEqual({ status: "suspended" });
    expect(org.status).toBe("suspended");
  });

  it("deleteOrganization DELETEs /admin/organizations/:id and accepts 204", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await expect(makeAdmin().deleteOrganization(ORG.id)).resolves.toBeUndefined();
    const [url, init] = lastCall();
    expect(url).toBe(`${BASE}/admin/organizations/${ORG.id}`);
    expect(init.method).toBe("DELETE");
  });

  it("listMemberRoles GETs the member's extra roles and returns the names", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: ["billing", "support"] }));
    const roles = await makeAdmin().listMemberRoles(ORG.id, "usr_1");
    const [url, init] = lastCall();
    expect(url).toBe(`${BASE}/admin/organizations/${ORG.id}/members/usr_1/roles`);
    expect(init.method).toBe("GET");
    expect(roles).toEqual(["billing", "support"]);
  });

  it("addMemberRole POSTs {role_name} and accepts 204", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await expect(makeAdmin().addMemberRole(ORG.id, "usr_1", "billing")).resolves.toBeUndefined();
    const [url, init] = lastCall();
    expect(url).toBe(`${BASE}/admin/organizations/${ORG.id}/members/usr_1/roles`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ role_name: "billing" });
  });

  it("addMemberRole throws HearthError 409 when the user is not a member", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ error: "not a member" }, 409));
    await expect(makeAdmin().addMemberRole(ORG.id, "usr_2", "billing")).rejects.toMatchObject({
      status: 409,
      body: { error: "not a member" },
    });
  });

  it("removeMemberRole DELETEs the role path", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await makeAdmin().removeMemberRole(ORG.id, "usr_1", "billing");
    const [url, init] = lastCall();
    expect(url).toBe(`${BASE}/admin/organizations/${ORG.id}/members/usr_1/roles/billing`);
    expect(init.method).toBe("DELETE");
  });

  it("exposes no method for the never-served /admin/orgs routes", () => {
    const admin = makeAdmin() as unknown as Record<string, unknown>;
    const dead = ["addOrgMember", "listOrgMembers", "removeOrgMember"];
    expect(dead.filter((name) => typeof admin[name] === "function")).toEqual([]);
  });
});
