import { HearthError } from "./client.js";
import { ConfigurationError } from "./errors.js";
import type {
  CreateUserParams,
  PageOptions,
  PageResponse,
  Realm,
  UpdateUserParams,
  User,
} from "./types.js";

/**
 * Admin API client for Hearth.
 *
 * Requires a valid admin access token. All operations go through
 * the /admin/* endpoints which enforce RBAC admin role checks.
 *
 * Every non-2xx response throws {@link HearthError} carrying the HTTP status
 * and the response body (parsed JSON, or the raw text when it is not JSON).
 */
export class AdminClient {
  private readonly baseUrl: string;

  /**
   * @param baseUrl - Root URL of the Hearth instance.
   * @param realmId - Realm to administer; sent as `X-Realm-ID`.
   * @param accessToken - Token whose subject holds the admin role in that realm.
   * @throws {@link ConfigurationError} when any argument is empty.
   */
  constructor(
    baseUrl: string,
    private readonly realmId: string,
    private readonly accessToken: string,
  ) {
    if (!baseUrl) throw new ConfigurationError("AdminClient: baseUrl is required");
    if (!realmId) throw new ConfigurationError("AdminClient: realmId is required");
    if (!accessToken) throw new ConfigurationError("AdminClient: accessToken is required");
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  // === Users ===

  /** POST /admin/users — create a user. */
  async createUser(params: CreateUserParams): Promise<User> {
    return this.request("POST", "/admin/users", {
      email: params.email,
      display_name: params.displayName,
    });
  }

  /** GET /admin/users — list users with pagination. */
  async listUsers(options?: PageOptions): Promise<PageResponse<User>> {
    return this.request("GET", withPage("/admin/users", options));
  }

  /** GET /admin/users/:id — get a user by ID. */
  async getUser(userId: string): Promise<User> {
    return this.request("GET", `/admin/users/${userId}`);
  }

  /** PATCH /admin/users/:id — update a user. */
  async updateUser(userId: string, params: UpdateUserParams): Promise<User> {
    return this.request("PATCH", `/admin/users/${userId}`, {
      email: params.email,
      display_name: params.displayName,
      status: params.status,
    });
  }

  /** DELETE /admin/users/:id — delete a user. */
  async deleteUser(userId: string): Promise<void> {
    await this.request("DELETE", `/admin/users/${userId}`);
  }

  // === Realms ===
  //
  // Realms are provisioned via hearth.yaml, not the admin API. There is no
  // `createRealm`/`updateRealm` client method: the server answers 405 with
  // "Realms are managed via hearth.yaml" to both POST /admin/realms and
  // PATCH /admin/realms/{id} (HEA-2171, audit 2026-08-28 §25.4). Only read
  // paths and deletion are exposed.

  /** GET /admin/realms — list realms with pagination. */
  async listRealms(options?: PageOptions): Promise<PageResponse<Realm>> {
    return this.request("GET", withPage("/admin/realms", options));
  }

  /** GET /admin/realms/:id — get a realm by ID. */
  async getRealm(realmId: string): Promise<Realm> {
    return this.request("GET", `/admin/realms/${realmId}`);
  }

  /** DELETE /admin/realms/:id — delete a realm. */
  async deleteRealm(realmId: string): Promise<void> {
    await this.request("DELETE", `/admin/realms/${realmId}`);
  }

  // === OAuth Clients ===

  /** POST /admin/applications — register an OAuth 2.0 client. */
  async createClient(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/applications", params);
  }

  /** GET /admin/applications/:id — get a client by ID. */
  async getClient(clientId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/admin/applications/${clientId}`);
  }

  /** PATCH /admin/applications/:id — update a client. */
  async updateClient(
    clientId: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request("PATCH", `/admin/applications/${clientId}`, params);
  }

  /**
   * POST /admin/applications/:id/regenerate-secret — replace a confidential
   * client's secret. The response carries the new `client_secret` once; the
   * old secret stops working immediately.
   */
  async regenerateClientSecret(clientId: string): Promise<Record<string, unknown>> {
    return this.request("POST", `/admin/applications/${clientId}/regenerate-secret`, {});
  }

  /** DELETE /admin/applications/:id — delete a client. */
  async deleteClient(clientId: string): Promise<void> {
    await this.request("DELETE", `/admin/applications/${clientId}`);
  }

  /** GET /admin/applications — list clients with optional pagination. */
  async listClients(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    return this.request("GET", withPage("/admin/applications", options));
  }

  // === Roles ===

  /** POST /admin/roles — create a role. */
  async createRole(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/roles", params);
  }

  /** GET /admin/roles/:id — get a role by ID. */
  async getRole(roleId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/admin/roles/${roleId}`);
  }

  /** PATCH /admin/roles/:id — update a role. */
  async updateRole(
    roleId: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request("PATCH", `/admin/roles/${roleId}`, params);
  }

  /** DELETE /admin/roles/:id — delete a role. */
  async deleteRole(roleId: string): Promise<void> {
    await this.request("DELETE", `/admin/roles/${roleId}`);
  }

  /** GET /admin/roles — list roles with optional pagination. */
  async listRoles(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    return this.request("GET", withPage("/admin/roles", options));
  }

  // === Groups ===

  /** POST /admin/groups — create a group. */
  async createGroup(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/groups", params);
  }

  /** GET /admin/groups/:id — get a group by ID. */
  async getGroup(groupId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/admin/groups/${groupId}`);
  }

  /** PATCH /admin/groups/:id — update a group. */
  async updateGroup(
    groupId: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.request("PATCH", `/admin/groups/${groupId}`, params);
  }

  /** DELETE /admin/groups/:id — delete a group. */
  async deleteGroup(groupId: string): Promise<void> {
    await this.request("DELETE", `/admin/groups/${groupId}`);
  }

  /** GET /admin/groups — list groups with optional pagination. */
  async listGroups(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    return this.request("GET", withPage("/admin/groups", options));
  }

  // === Org Members — removed ===
  //
  // Hearth serves no organization route over HTTP: there is no /admin/orgs, no
  // /admin/orgs/:orgId/members and no per-member route anywhere in the router,
  // so addOrgMember, listOrgMembers and removeOrgMember every one 404'd
  // (audit 2026-08-28 §25.19). Organization membership is administered through
  // the admin console, not the admin API.

  /**
   * Send a request to the admin API. Resolves with the parsed JSON body, or
   * `undefined` for an empty body (204, or a DELETE). Throws {@link HearthError}
   * on any non-2xx status.
   */
  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        "X-Realm-ID": this.realmId,
        Authorization: `Bearer ${this.accessToken}`,
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await resp.text();
    if (!resp.ok) throw new HearthError(resp.status, parseBody(text));
    return (text === "" ? undefined : JSON.parse(text)) as T;
  }
}

/** Append `limit` and `cursor` to a list path, omitting the query string when both are unset. */
function withPage(path: string, options?: PageOptions): string {
  const q = new URLSearchParams();
  if (options?.limit !== undefined) q.set("limit", String(options.limit));
  if (options?.cursor !== undefined) q.set("cursor", options.cursor);
  const qs = q.toString();
  return qs ? `${path}?${qs}` : path;
}

/** An error body as JSON when it parses, else the raw text (`null` when empty). */
function parseBody(text: string): unknown {
  if (text === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
