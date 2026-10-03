import createClient, { type Client } from "openapi-fetch";
import { HearthError } from "./client.js";
import { ConfigurationError } from "./errors.js";
import type { components, paths } from "./generated/admin/schema.js";
import type {
  CreateUserParams,
  PageOptions,
  PageResponse,
  Realm,
  UpdateUserParams,
  User,
} from "./types.js";

type Schemas = components["schemas"];

/** An organization, as `GET /admin/organizations/{id}` returns it. */
export type Organization = Schemas["AdminOrganization"];
/** Body of `POST /admin/organizations`. */
export type CreateOrganizationParams = Schemas["AdminCreateOrganizationRequest"];
/** Body of `PATCH /admin/organizations/{id}`; absent fields are unchanged. */
export type UpdateOrganizationParams = Schemas["AdminUpdateOrganizationRequest"];

/**
 * Admin API client for Hearth.
 *
 * Requires a valid admin access token. All operations go through
 * the /admin/* endpoints which enforce RBAC admin role checks.
 *
 * Routes and path parameters are typed by the client generated from
 * `docs/api/openapi.json` (`src/generated/admin/`, `make sdk-admin-gen`); the
 * generated names stay internal.
 *
 * Every non-2xx response throws {@link HearthError} carrying the HTTP status
 * and the response body (parsed JSON, or the raw text when it is not JSON).
 */
export class AdminClient {
  private readonly api: Client<paths>;

  /**
   * @param baseUrl - Root URL of the Hearth instance.
   * @param realmId - Realm to administer; sent as `X-Realm-ID`.
   * @param accessToken - Token whose subject holds the admin role in that realm.
   * @throws {@link ConfigurationError} when any argument is empty.
   */
  constructor(baseUrl: string, realmId: string, accessToken: string) {
    if (!baseUrl) throw new ConfigurationError("AdminClient: baseUrl is required");
    if (!realmId) throw new ConfigurationError("AdminClient: realmId is required");
    if (!accessToken) throw new ConfigurationError("AdminClient: accessToken is required");
    this.api = createClient<paths>({
      baseUrl: baseUrl.replace(/\/$/, ""),
      headers: { "X-Realm-ID": realmId, Authorization: `Bearer ${accessToken}` },
      fetch: forwardToGlobalFetch,
    });
  }

  // === Users ===

  /** POST /admin/users — create a user. */
  async createUser(params: CreateUserParams): Promise<User> {
    return unwrap(
      this.api.POST("/admin/users", {
        body: snakeCaseBody({ email: params.email, display_name: params.displayName }),
      }),
    );
  }

  /** GET /admin/users — list users with pagination. */
  async listUsers(options?: PageOptions): Promise<PageResponse<User>> {
    return unwrap(this.api.GET("/admin/users", { params: { query: page(options) } }));
  }

  /** GET /admin/users/:id — get a user by ID. */
  async getUser(userId: string): Promise<User> {
    return unwrap(this.api.GET("/admin/users/{id}", { params: { path: { id: userId } } }));
  }

  /** PATCH /admin/users/:id — update a user. */
  async updateUser(userId: string, params: UpdateUserParams): Promise<User> {
    return unwrap(
      this.api.PATCH("/admin/users/{id}", {
        params: { path: { id: userId } },
        body: snakeCaseBody({
          email: params.email,
          display_name: params.displayName,
          status: params.status,
        }),
      }),
    );
  }

  /** DELETE /admin/users/:id — delete a user. */
  async deleteUser(userId: string): Promise<void> {
    await unwrap(this.api.DELETE("/admin/users/{id}", { params: { path: { id: userId } } }));
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
    return unwrap(this.api.GET("/admin/realms", { params: { query: page(options) } }));
  }

  /** GET /admin/realms/:id — get a realm by ID. */
  async getRealm(realmId: string): Promise<Realm> {
    return unwrap(this.api.GET("/admin/realms/{id}", { params: { path: { id: realmId } } }));
  }

  /** DELETE /admin/realms/:id — delete a realm. */
  async deleteRealm(realmId: string): Promise<void> {
    await unwrap(this.api.DELETE("/admin/realms/{id}", { params: { path: { id: realmId } } }));
  }

  // === OAuth Clients ===

  /** POST /admin/applications — register an OAuth 2.0 client. */
  async createClient(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return unwrap(this.api.POST("/admin/applications", { body: snakeCaseBody(params) }));
  }

  /** GET /admin/applications/:id — get a client by ID. */
  async getClient(clientId: string): Promise<Record<string, unknown>> {
    return unwrap(
      this.api.GET("/admin/applications/{clientId}", { params: { path: { clientId } } }),
    );
  }

  /** PATCH /admin/applications/:id — update a client. */
  async updateClient(
    clientId: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return unwrap(
      this.api.PATCH("/admin/applications/{clientId}", {
        params: { path: { clientId } },
        body: snakeCaseBody(params),
      }),
    );
  }

  /**
   * POST /admin/applications/:id/regenerate-secret — replace a confidential
   * client's secret. The response carries the new `client_secret` once; the
   * old secret stops working immediately.
   */
  async regenerateClientSecret(clientId: string): Promise<Record<string, unknown>> {
    return unwrap(
      this.api.POST("/admin/applications/{clientId}/regenerate-secret", {
        params: { path: { clientId } },
      }),
    );
  }

  /** DELETE /admin/applications/:id — delete a client. */
  async deleteClient(clientId: string): Promise<void> {
    await unwrap(
      this.api.DELETE("/admin/applications/{clientId}", { params: { path: { clientId } } }),
    );
  }

  /** GET /admin/applications — list clients with optional pagination. */
  async listClients(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    return unwrap(this.api.GET("/admin/applications", { params: { query: page(options) } }));
  }

  // === Roles ===

  /** POST /admin/roles — create a role. */
  async createRole(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return unwrap(this.api.POST("/admin/roles", { body: snakeCaseBody(params) }));
  }

  /** GET /admin/roles/:id — get a role by ID. */
  async getRole(roleId: string): Promise<Record<string, unknown>> {
    return unwrap(this.api.GET("/admin/roles/{roleId}", { params: { path: { roleId } } }));
  }

  /** PATCH /admin/roles/:id — update a role. */
  async updateRole(
    roleId: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return unwrap(
      this.api.PATCH("/admin/roles/{roleId}", {
        params: { path: { roleId } },
        body: snakeCaseBody(params),
      }),
    );
  }

  /** DELETE /admin/roles/:id — delete a role. */
  async deleteRole(roleId: string): Promise<void> {
    await unwrap(this.api.DELETE("/admin/roles/{roleId}", { params: { path: { roleId } } }));
  }

  /** GET /admin/roles — list roles with optional pagination. */
  async listRoles(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    return unwrap(this.api.GET("/admin/roles", { params: { query: page(options) } }));
  }

  // === Groups ===

  /** POST /admin/groups — create a group. */
  async createGroup(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return unwrap(this.api.POST("/admin/groups", { body: snakeCaseBody(params) }));
  }

  /** GET /admin/groups/:id — get a group by ID. */
  async getGroup(groupId: string): Promise<Record<string, unknown>> {
    return unwrap(this.api.GET("/admin/groups/{groupId}", { params: { path: { groupId } } }));
  }

  /** PATCH /admin/groups/:id — update a group. */
  async updateGroup(
    groupId: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return unwrap(
      this.api.PATCH("/admin/groups/{groupId}", {
        params: { path: { groupId } },
        body: snakeCaseBody(params),
      }),
    );
  }

  /** DELETE /admin/groups/:id — delete a group. */
  async deleteGroup(groupId: string): Promise<void> {
    await unwrap(this.api.DELETE("/admin/groups/{groupId}", { params: { path: { groupId } } }));
  }

  /** GET /admin/groups — list groups with optional pagination. */
  async listGroups(options?: PageOptions): Promise<PageResponse<Record<string, unknown>>> {
    return unwrap(this.api.GET("/admin/groups", { params: { query: page(options) } }));
  }

  // === Organizations ===

  /** GET /admin/organizations — list organizations with pagination. */
  async listOrganizations(options?: PageOptions): Promise<PageResponse<Organization>> {
    const result = await unwrap<Schemas["AdminOrganizationPage"]>(
      this.api.GET("/admin/organizations", { params: { query: page(options) } }),
    );
    return { items: result.items, next_cursor: result.next_cursor ?? null };
  }

  /** POST /admin/organizations — create an organization. */
  async createOrganization(params: CreateOrganizationParams): Promise<Organization> {
    return unwrap(this.api.POST("/admin/organizations", { body: params }));
  }

  /** GET /admin/organizations/:id — get an organization by ID. */
  async getOrganization(orgId: string): Promise<Organization> {
    return unwrap(this.api.GET("/admin/organizations/{id}", { params: { path: { id: orgId } } }));
  }

  /**
   * PATCH /admin/organizations/:id — update an organization. A `slug` change
   * is refused with 400 (the slug is immutable).
   */
  async updateOrganization(orgId: string, params: UpdateOrganizationParams): Promise<Organization> {
    return unwrap(
      this.api.PATCH("/admin/organizations/{id}", {
        params: { path: { id: orgId } },
        body: params,
      }),
    );
  }

  /** DELETE /admin/organizations/:id — delete an organization. */
  async deleteOrganization(orgId: string): Promise<void> {
    await unwrap(this.api.DELETE("/admin/organizations/{id}", { params: { path: { id: orgId } } }));
  }

  /**
   * GET /admin/organizations/:id/members/:userId/roles — the names of the
   * extra org roles a member holds on top of the organization's base role.
   */
  async listMemberRoles(orgId: string, userId: string): Promise<string[]> {
    const result = await unwrap<Schemas["AdminRoleNameList"]>(
      this.api.GET("/admin/organizations/{id}/members/{user_id}/roles", {
        params: { path: { id: orgId, user_id: userId } },
      }),
    );
    return result.items;
  }

  /**
   * POST /admin/organizations/:id/members/:userId/roles — give a member an
   * extra org role. The user must already be a member (409 otherwise).
   */
  async addMemberRole(orgId: string, userId: string, roleName: string): Promise<void> {
    await unwrap(
      this.api.POST("/admin/organizations/{id}/members/{user_id}/roles", {
        params: { path: { id: orgId, user_id: userId } },
        body: { role_name: roleName },
      }),
    );
  }

  /** DELETE /admin/organizations/:id/members/:userId/roles/:roleName — remove an extra org role. */
  async removeMemberRole(orgId: string, userId: string, roleName: string): Promise<void> {
    await unwrap(
      this.api.DELETE("/admin/organizations/{id}/members/{user_id}/roles/{role_name}", {
        params: { path: { id: orgId, user_id: userId, role_name: roleName } },
      }),
    );
  }
}

/** The `limit` and `cursor` query parameters of a list call; unset ones are left out. */
function page(options?: PageOptions): { limit?: number; cursor?: string } {
  return { limit: options?.limit, cursor: options?.cursor };
}

/**
 * Pass a snake_case body through untyped. The proto-derived request schemas in
 * `docs/api/openapi.json` use camelCase JSON names, but the REST handlers read
 * snake_case, so the generated body types do not describe the wire for these
 * routes. The organization routes are typed from the handlers and need no cast.
 */
function snakeCaseBody(body: object): never {
  return body as never;
}

/**
 * Resolve an openapi-fetch call to its parsed body (`undefined` for an empty
 * body, e.g. 204), or throw {@link HearthError} on any non-2xx status.
 */
async function unwrap<T>(
  call: Promise<{ data?: unknown; error?: unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await call;
  if (!response.ok) throw new HearthError(response.status, error === "" ? null : (error ?? null));
  return data as T;
}

/**
 * openapi-fetch calls `fetch(request)`. Forward to the global `fetch` as
 * `(url, init)`, read at call time, so the SDK keeps one transport shape and a
 * stubbed global `fetch` sees every admin call.
 */
async function forwardToGlobalFetch(request: Request): Promise<Response> {
  const body = request.body === null ? undefined : await request.text();
  return globalThis.fetch(request.url, {
    method: request.method,
    headers: request.headers,
    body,
  });
}
