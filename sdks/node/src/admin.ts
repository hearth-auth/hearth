/** §12 — AdminClient: management operations against the Hearth admin API. */

import { ConfigurationError, AdminHttpError } from "./errors.js";

export interface AdminClientConfig {
  /** Root URL of the Hearth instance (no trailing slash). */
  base_url: string;
  /** ID of the realm to administer. */
  realm_id: string;
  /** A valid access token whose subject holds the `admin` role in the target realm. */
  access_token: string;
}

export interface PageOptions {
  limit?: number;
  cursor?: string;
}

export interface PageResponse<T> {
  items: T[];
  next_cursor: string | null;
}

export class AdminClient {
  private readonly baseUrl: string;
  private readonly realmId: string;
  private readonly accessToken: string;

  constructor(config: AdminClientConfig) {
    if (!config.base_url) throw new ConfigurationError("AdminClient: base_url is required");
    if (!config.realm_id) throw new ConfigurationError("AdminClient: realm_id is required");
    if (!config.access_token) throw new ConfigurationError("AdminClient: access_token is required");
    this.baseUrl = config.base_url.replace(/\/$/, "");
    this.realmId = config.realm_id;
    this.accessToken = config.access_token;
  }

  private get authHeaders(): Record<string, string> {
    return {
      "Authorization": `Bearer ${this.accessToken}`,
      "X-Realm-ID": this.realmId,
      "Content-Type": "application/json",
    };
  }

  private buildUrl(path: string, params?: PageOptions): string {
    const url = new URL(`${this.baseUrl}${path}`);
    if (params?.limit !== undefined) url.searchParams.set("limit", String(params.limit));
    if (params?.cursor !== undefined) url.searchParams.set("cursor", params.cursor);
    return url.toString();
  }

  private async request<T>(method: string, url: string, body?: unknown): Promise<T> {
    const init: RequestInit = {
      method,
      headers: this.authHeaders,
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const res = await fetch(url, init);
    if (!res.ok) {
      let message = `Admin API error: HTTP ${res.status}`;
      try {
        const json = (await res.json()) as Record<string, unknown>;
        if (json.error && typeof json.error === "string") message = json.error;
      } catch {
        // ignore parse failure
      }
      throw new AdminHttpError(res.status, message);
    }
    if (res.status === 204) return {} as T;
    return res.json() as Promise<T>;
  }

  // ── Users ──────────────────────────────────────────────────────────────────

  /** Create a new user in the realm. */
  async createUser(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", this.buildUrl("/admin/users"), params);
  }

  /** Get a user by ID. */
  async getUser(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", this.buildUrl(`/admin/users/${id}`));
  }

  /** Update a user by ID. */
  async updateUser(id: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PUT", this.buildUrl(`/admin/users/${id}`), params);
  }

  /** Delete a user by ID. */
  async deleteUser(id: string): Promise<void> {
    await this.request("DELETE", this.buildUrl(`/admin/users/${id}`));
  }

  /** List users with optional pagination. */
  async listUsers(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    const url = options ? this.buildUrl("/admin/users", options) : `${this.baseUrl}/admin/users`;
    return this.request("GET", url);
  }

  // ── Realms ─────────────────────────────────────────────────────────────────

  /** Create a new realm. */
  async createRealm(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", this.buildUrl("/admin/realms"), params);
  }

  /** Get a realm by ID. */
  async getRealm(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", this.buildUrl(`/admin/realms/${id}`));
  }

  /** Update a realm by ID. */
  async updateRealm(id: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PUT", this.buildUrl(`/admin/realms/${id}`), params);
  }

  /** Delete a realm by ID. */
  async deleteRealm(id: string): Promise<void> {
    await this.request("DELETE", this.buildUrl(`/admin/realms/${id}`));
  }

  /** List realms with optional pagination. */
  async listRealms(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    const url = options ? this.buildUrl("/admin/realms", options) : `${this.baseUrl}/admin/realms`;
    return this.request("GET", url);
  }

  // ── OAuth Clients ──────────────────────────────────────────────────────────

  /** Create an OAuth 2.0 client registration. */
  async createClient(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", this.buildUrl("/admin/clients"), params);
  }

  /** Get an OAuth client by ID. */
  async getClient(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", this.buildUrl(`/admin/clients/${id}`));
  }

  /** Update an OAuth client by ID. */
  async updateClient(id: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PUT", this.buildUrl(`/admin/clients/${id}`), params);
  }

  /** Delete an OAuth client by ID. */
  async deleteClient(id: string): Promise<void> {
    await this.request("DELETE", this.buildUrl(`/admin/clients/${id}`));
  }

  /** List OAuth clients with optional pagination. */
  async listClients(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    const url = options ? this.buildUrl("/admin/clients", options) : `${this.baseUrl}/admin/clients`;
    return this.request("GET", url);
  }

  // ── Roles ──────────────────────────────────────────────────────────────────

  /** Create a role in the realm. */
  async createRole(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", this.buildUrl("/admin/roles"), params);
  }

  /** Get a role by ID. */
  async getRole(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", this.buildUrl(`/admin/roles/${id}`));
  }

  /** Update a role by ID. */
  async updateRole(id: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PUT", this.buildUrl(`/admin/roles/${id}`), params);
  }

  /** Delete a role by ID. */
  async deleteRole(id: string): Promise<void> {
    await this.request("DELETE", this.buildUrl(`/admin/roles/${id}`));
  }

  /** List roles with optional pagination. */
  async listRoles(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    const url = options ? this.buildUrl("/admin/roles", options) : `${this.baseUrl}/admin/roles`;
    return this.request("GET", url);
  }

  // ── Groups ─────────────────────────────────────────────────────────────────

  /** Create a group in the realm. */
  async createGroup(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", this.buildUrl("/admin/groups"), params);
  }

  /** Get a group by ID. */
  async getGroup(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", this.buildUrl(`/admin/groups/${id}`));
  }

  /** Update a group by ID. */
  async updateGroup(id: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("PUT", this.buildUrl(`/admin/groups/${id}`), params);
  }

  /** Delete a group by ID. */
  async deleteGroup(id: string): Promise<void> {
    await this.request("DELETE", this.buildUrl(`/admin/groups/${id}`));
  }

  /** List groups with optional pagination. */
  async listGroups(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    const url = options ? this.buildUrl("/admin/groups", options) : `${this.baseUrl}/admin/groups`;
    return this.request("GET", url);
  }

  // ── Organization Memberships ───────────────────────────────────────────────

  /** Add a member to an organization. */
  async addOrgMember(orgId: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", this.buildUrl(`/admin/orgs/${orgId}/members`), params);
  }

  /** List members of an organization. */
  async listOrgMembers(orgId: string, options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    const path = `/admin/orgs/${orgId}/members`;
    const url = options ? this.buildUrl(path, options) : `${this.baseUrl}${path}`;
    return this.request("GET", url);
  }

  /** Remove a member from an organization. */
  async removeOrgMember(orgId: string, userId: string): Promise<void> {
    await this.request("DELETE", this.buildUrl(`/admin/orgs/${orgId}/members/${userId}`));
  }
}
