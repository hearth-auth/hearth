import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AdminClient } from "./admin.js";

const BASE_ADMIN_CONFIG = {
  base_url: "https://auth.example.com",
  realm_id: "realm_abc123",
  access_token: "admin-token-xyz",
};

function mockFetch(response: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => response,
    text: async () => JSON.stringify(response),
  });
}

describe("AdminClient — construction", () => {
  it("can be instantiated with required params", () => {
    const client = new AdminClient(BASE_ADMIN_CONFIG);
    expect(client).toBeInstanceOf(AdminClient);
  });

  it("throws ConfigurationError when base_url is missing", () => {
    expect(() => new AdminClient({ ...BASE_ADMIN_CONFIG, base_url: "" })).toThrow();
  });

  it("throws ConfigurationError when realm_id is missing", () => {
    expect(() => new AdminClient({ ...BASE_ADMIN_CONFIG, realm_id: "" })).toThrow();
  });

  it("throws ConfigurationError when access_token is missing", () => {
    expect(() => new AdminClient({ ...BASE_ADMIN_CONFIG, access_token: "" })).toThrow();
  });
});

describe("AdminClient — Users CRUD", () => {
  let client: AdminClient;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    client = new AdminClient(BASE_ADMIN_CONFIG);
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("createUser sends POST /admin/users with correct headers", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 201, json: async () => ({ id: "usr_1", email: "alice@example.com" }) });
    const result = await client.createUser({ email: "alice@example.com", password: "secret" });
    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/users");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer admin-token-xyz");
    expect(headers["X-Realm-ID"]).toBe("realm_abc123");
    expect(result).toMatchObject({ id: "usr_1" });
  });

  it("getUser sends GET /admin/users/{id}", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: "usr_1", email: "alice@example.com" }) });
    const result = await client.getUser("usr_1");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/users/usr_1");
    expect(init.method).toBe("GET");
    expect(result).toMatchObject({ id: "usr_1" });
  });

  it("updateUser sends PATCH /admin/users/{id}", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: "usr_1", email: "newemail@example.com" }) });
    await client.updateUser("usr_1", { email: "newemail@example.com" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/users/usr_1");
    expect(init.method).toBe("PATCH");
  });

  it("deleteUser sends DELETE /admin/users/{id}", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 204, json: async () => ({}) });
    await client.deleteUser("usr_1");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/users/usr_1");
    expect(init.method).toBe("DELETE");
  });

  it("listUsers sends GET /admin/users with pagination params", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    const result = await client.listUsers({ limit: 10, cursor: "next-page-token" });
    const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/admin/users");
    expect(url).toContain("limit=10");
    expect(url).toContain("cursor=next-page-token");
    expect(result).toMatchObject({ items: [] });
  });

  it("listUsers without options omits pagination params", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    await client.listUsers();
    const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/users");
  });
});

describe("AdminClient — Realms CRUD", () => {
  let client: AdminClient;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    client = new AdminClient(BASE_ADMIN_CONFIG);
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("getRealm sends GET /admin/realms/{id}", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: "realm_1" }) });
    await client.getRealm("realm_1");
    const [url] = fetchSpy.mock.calls[0] as [string];
    expect(url).toBe("https://auth.example.com/admin/realms/realm_1");
  });

  it("updateRealm sends PATCH /admin/realms/{id}", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: "realm_1" }) });
    await client.updateRealm("realm_1", { name: "Updated" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/realms/realm_1");
    expect(init.method).toBe("PATCH");
  });

  it("deleteRealm sends DELETE /admin/realms/{id}", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 204, json: async () => ({}) });
    await client.deleteRealm("realm_1");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/realms/realm_1");
    expect(init.method).toBe("DELETE");
  });

  it("listRealms sends GET /admin/realms", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    const result = await client.listRealms();
    const [url] = fetchSpy.mock.calls[0] as [string];
    expect(url).toBe("https://auth.example.com/admin/realms");
    expect(result).toMatchObject({ items: [] });
  });
});

describe("AdminClient — Clients, Roles, Groups, OrgMembers", () => {
  let client: AdminClient;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    client = new AdminClient(BASE_ADMIN_CONFIG);
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("createClient sends POST /admin/clients", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 201, json: async () => ({ client_id: "cli_1" }) });
    await client.createClient({ client_id: "my-app", client_name: "My App" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/clients");
    expect(init.method).toBe("POST");
  });

  it("listClients sends GET /admin/clients", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    await client.listClients();
    const [url] = fetchSpy.mock.calls[0] as [string];
    expect(url).toBe("https://auth.example.com/admin/clients");
  });

  it("createRole sends POST /admin/roles", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 201, json: async () => ({ id: "role_1", name: "editor" }) });
    await client.createRole({ name: "editor" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/roles");
    expect(init.method).toBe("POST");
  });

  it("listRoles sends GET /admin/roles", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    await client.listRoles();
    const [url] = fetchSpy.mock.calls[0] as [string];
    expect(url).toBe("https://auth.example.com/admin/roles");
  });

  it("createGroup sends POST /admin/groups", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 201, json: async () => ({ id: "grp_1", name: "engineers" }) });
    await client.createGroup({ name: "engineers" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/groups");
    expect(init.method).toBe("POST");
  });

  it("listGroups sends GET /admin/groups", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    await client.listGroups();
    const [url] = fetchSpy.mock.calls[0] as [string];
    expect(url).toBe("https://auth.example.com/admin/groups");
  });

  it("addOrgMember sends POST /admin/orgs/{orgId}/members", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 201, json: async () => ({}) });
    await client.addOrgMember("org_1", { user_id: "usr_1", role: "member" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/orgs/org_1/members");
    expect(init.method).toBe("POST");
  });

  it("listOrgMembers sends GET /admin/orgs/{orgId}/members", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    await client.listOrgMembers("org_1");
    const [url] = fetchSpy.mock.calls[0] as [string];
    expect(url).toBe("https://auth.example.com/admin/orgs/org_1/members");
  });

  it("removeOrgMember sends DELETE /admin/orgs/{orgId}/members/{userId}", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 204, json: async () => ({}) });
    await client.removeOrgMember("org_1", "usr_1");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://auth.example.com/admin/orgs/org_1/members/usr_1");
    expect(init.method).toBe("DELETE");
  });
});

describe("AdminClient — error handling", () => {
  let client: AdminClient;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    client = new AdminClient(BASE_ADMIN_CONFIG);
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws an error with status code on 403 Forbidden", async () => {
    fetchSpy.mockResolvedValue({ ok: false, status: 403, json: async () => ({ error: "forbidden" }) });
    await expect(client.getUser("usr_1")).rejects.toThrow();
    await expect(client.getUser("usr_1")).rejects.toMatchObject({ status: 403 });
  });

  it("throws an error with status code on 404 Not Found", async () => {
    fetchSpy.mockResolvedValue({ ok: false, status: 404, json: async () => ({ error: "not_found" }) });
    await expect(client.getUser("nonexistent")).rejects.toMatchObject({ status: 404 });
  });

  it("always sends Authorization and X-Realm-ID headers", async () => {
    fetchSpy.mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], next_cursor: null }) });
    await client.listUsers();
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer admin-token-xyz");
    expect(headers["X-Realm-ID"]).toBe("realm_abc123");
  });
});
