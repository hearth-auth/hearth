/**
 * §5.2 — Admin CRUD extended: Clients, Roles, Groups, Org Members.
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
  it("createClient POSTs to /admin/clients", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ client_id: "cli1", client_name: "My App" }, 201));
    const admin = makeAdmin();
    const result = await admin.createClient({ client_name: "My App", redirect_uris: ["https://app.example.com/cb"] });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/clients`);
    expect(init.method).toBe("POST");
    expect(result).toMatchObject({ client_id: "cli1" });
  });

  it("getClient GETs /admin/clients/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ client_id: "cli1" }));
    await makeAdmin().getClient("cli1");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toBe(`${BASE}/admin/clients/cli1`);
  });

  it("updateClient PATCHes /admin/clients/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ client_id: "cli1", client_name: "Updated" }));
    await makeAdmin().updateClient("cli1", { client_name: "Updated" });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/clients/cli1`);
    expect(init.method).toBe("PATCH");
  });

  it("deleteClient DELETEs /admin/clients/:id", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await makeAdmin().deleteClient("cli1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/clients/cli1`);
    expect(init.method).toBe("DELETE");
  });

  it("listClients GETs /admin/clients", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: [], next_cursor: null }));
    const result = await makeAdmin().listClients();
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toContain("/admin/clients");
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

// ── Org Members ─────────────────────────────────────────────────────────────

describe("AdminClient — Org Members", () => {
  it("addOrgMember POSTs to /admin/orgs/:orgId/members", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ user_id: "usr1", role: "member" }, 201));
    await makeAdmin().addOrgMember("org1", { user_id: "usr1", role: "member" });
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/orgs/org1/members`);
    expect(init.method).toBe("POST");
  });

  it("listOrgMembers GETs /admin/orgs/:orgId/members", async () => {
    vi.mocked(fetch).mockResolvedValue(mockOk({ items: [], next_cursor: null }));
    await makeAdmin().listOrgMembers("org1");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string];
    expect(url).toContain("/admin/orgs/org1/members");
  });

  it("removeOrgMember DELETEs /admin/orgs/:orgId/members/:userId", async () => {
    vi.mocked(fetch).mockResolvedValue(mockNoContent());
    await makeAdmin().removeOrgMember("org1", "usr1");
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/admin/orgs/org1/members/usr1`);
    expect(init.method).toBe("DELETE");
  });
});
