import { HearthError } from "./client.js";
import type {
  CreateRealmParams,
  CreateUserParams,
  PageResponse,
  Realm,
  UpdateRealmParams,
  UpdateUserParams,
  User,
} from "./types.js";

/**
 * Admin API client for Hearth.
 *
 * Requires a valid admin access token. All operations go through
 * the /admin/* endpoints which enforce RBAC admin role checks.
 */
export class AdminClient {
  constructor(
    private readonly baseUrl: string,
    private readonly realmId: string,
    private readonly accessToken: string,
  ) {}

  // === Users ===

  /** POST /admin/users — create a user. */
  async createUser(params: CreateUserParams): Promise<User> {
    return this.post("/admin/users", {
      email: params.email,
      display_name: params.displayName,
    });
  }

  /** GET /admin/users — list users with pagination. */
  async listUsers(options?: {
    limit?: number;
    cursor?: string;
  }): Promise<PageResponse<User>> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    return this.get(`/admin/users?${q}`);
  }

  /** GET /admin/users/:id — get a user by ID. */
  async getUser(userId: string): Promise<User> {
    return this.get(`/admin/users/${userId}`);
  }

  /** PUT /admin/users/:id — update a user. */
  async updateUser(userId: string, params: UpdateUserParams): Promise<User> {
    return this.request("PATCH", `/admin/users/${userId}`, {
      email: params.email,
      display_name: params.displayName,
      status: params.status,
    });
  }

  /** DELETE /admin/users/:id — delete a user. */
  async deleteUser(userId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/users/${userId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  // === Realms ===

  /** POST /admin/realms — create a realm. */
  async createRealm(params: CreateRealmParams): Promise<Realm> {
    return this.post("/admin/realms", {
      name: params.name,
      config: params.config,
    });
  }

  /** GET /admin/realms — list realms with pagination. */
  async listRealms(options?: {
    limit?: number;
    cursor?: string;
  }): Promise<PageResponse<Realm>> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    return this.get(`/admin/realms?${q}`);
  }

  /** GET /admin/realms/:id — get a realm by ID. */
  async getRealm(realmId: string): Promise<Realm> {
    return this.get(`/admin/realms/${realmId}`);
  }

  /** PUT /admin/realms/:id — update a realm. */
  async updateRealm(
    realmId: string,
    params: UpdateRealmParams,
  ): Promise<Realm> {
    return this.request("PATCH", `/admin/realms/${realmId}`, {
      name: params.name,
      status: params.status,
      config: params.config,
    });
  }

  /** DELETE /admin/realms/:id — delete a realm. */
  async deleteRealm(realmId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/realms/${realmId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  // === OAuth Clients ===

  /** POST /admin/clients — register an OAuth 2.0 client. */
  async createClient(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.post("/admin/clients", params);
  }

  /** GET /admin/clients/:id — get a client by ID. */
  async getClient(clientId: string): Promise<Record<string, unknown>> {
    return this.get(`/admin/clients/${clientId}`);
  }

  /** PATCH /admin/clients/:id — update a client. */
  async updateClient(clientId: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PATCH", `/admin/clients/${clientId}`, params);
  }

  /** DELETE /admin/clients/:id — delete a client. */
  async deleteClient(clientId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/clients/${clientId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  /** GET /admin/clients — list clients with optional pagination. */
  async listClients(options?: { limit?: number; cursor?: string }): Promise<{ items: Record<string, unknown>[]; next_cursor: string | null }> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    const qs = q.toString();
    return this.get(`/admin/clients${qs ? `?${qs}` : ""}`);
  }

  // === Roles ===

  /** POST /admin/roles — create a role. */
  async createRole(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.post("/admin/roles", params);
  }

  /** GET /admin/roles/:id — get a role by ID. */
  async getRole(roleId: string): Promise<Record<string, unknown>> {
    return this.get(`/admin/roles/${roleId}`);
  }

  /** PATCH /admin/roles/:id — update a role. */
  async updateRole(roleId: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PATCH", `/admin/roles/${roleId}`, params);
  }

  /** DELETE /admin/roles/:id — delete a role. */
  async deleteRole(roleId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/roles/${roleId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  /** GET /admin/roles — list roles with optional pagination. */
  async listRoles(options?: { limit?: number; cursor?: string }): Promise<{ items: Record<string, unknown>[]; next_cursor: string | null }> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    const qs = q.toString();
    return this.get(`/admin/roles${qs ? `?${qs}` : ""}`);
  }

  // === Groups ===

  /** POST /admin/groups — create a group. */
  async createGroup(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.post("/admin/groups", params);
  }

  /** GET /admin/groups/:id — get a group by ID. */
  async getGroup(groupId: string): Promise<Record<string, unknown>> {
    return this.get(`/admin/groups/${groupId}`);
  }

  /** PATCH /admin/groups/:id — update a group. */
  async updateGroup(groupId: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PATCH", `/admin/groups/${groupId}`, params);
  }

  /** DELETE /admin/groups/:id — delete a group. */
  async deleteGroup(groupId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/groups/${groupId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  /** GET /admin/groups — list groups with optional pagination. */
  async listGroups(options?: { limit?: number; cursor?: string }): Promise<{ items: Record<string, unknown>[]; next_cursor: string | null }> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    const qs = q.toString();
    return this.get(`/admin/groups${qs ? `?${qs}` : ""}`);
  }

  // === Org Members ===

  /** POST /admin/orgs/:orgId/members — add a member to an organization. */
  async addOrgMember(orgId: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.post(`/admin/orgs/${orgId}/members`, params);
  }

  /** GET /admin/orgs/:orgId/members — list members of an organization. */
  async listOrgMembers(orgId: string, options?: { limit?: number; cursor?: string }): Promise<{ items: Record<string, unknown>[]; next_cursor: string | null }> {
    const q = new URLSearchParams();
    if (options?.limit) q.set("limit", String(options.limit));
    if (options?.cursor) q.set("cursor", options.cursor);
    const qs = q.toString();
    return this.get(`/admin/orgs/${orgId}/members${qs ? `?${qs}` : ""}`);
  }

  /** DELETE /admin/orgs/:orgId/members/:userId — remove a member from an organization. */
  async removeOrgMember(orgId: string, userId: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/admin/orgs/${orgId}/members/${userId}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
  }

  private headers(): Record<string, string> {
    return {
      "X-Realm-ID": this.realmId,
      Authorization: `Bearer ${this.accessToken}`,
      "Content-Type": "application/json",
    };
  }

  private async get<T>(path: string): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      headers: this.headers(),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<T>;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request("POST", path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body: unknown,
  ): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<T>;
  }
}
