package io.hearth.sdk

import okhttp3.OkHttpClient

/**
 * Admin API client for Hearth (sdk-spec §12).
 *
 * A separate entry point from [HearthClient] — does not perform OIDC discovery and does
 * not manage token lifecycle. The caller is responsible for obtaining and refreshing the
 * admin access token.
 *
 * Every request includes:
 * - `Authorization: Bearer {accessToken}`
 * - `X-Realm-ID: {realmId}`
 *
 * Obtain via [HearthClient.admin] or construct directly:
 * ```kotlin
 * val admin = AdminClient(
 *     baseUrl = "https://auth.example.com",
 *     realmId = "my-realm-id",
 *     accessToken = adminAccessToken,
 * )
 * val user = admin.createUser(CreateUserRequest("alice@example.com", "Alice"))
 * ```
 */
class AdminClient(
    private val baseUrl: String,
    private val realmId: String,
    private val accessToken: String,
    private val httpClient: OkHttpClient = buildHttpClient(10_000L),
) {
    internal constructor(
        baseUrl: String,
        accessToken: String,
        httpClient: OkHttpClient,
        realmId: String = "",
    ) : this(baseUrl, realmId, accessToken, httpClient)

    private fun authHeaders(): Map<String, String> = mapOf(
        "Authorization" to "Bearer $accessToken",
        "X-Realm-ID" to realmId,
    )

    // ── Users ──────────────────────────────────────────────────────────────────

    /** Creates a new user. */
    suspend fun createUser(request: CreateUserRequest): User =
        httpClient.post("$baseUrl/admin/users", request, authHeaders())

    /** Retrieves a user by [userId]. */
    suspend fun getUser(userId: String): User =
        httpClient.get("$baseUrl/admin/users/$userId", authHeaders())

    /** Updates a user. Only non-null fields are changed. */
    suspend fun updateUser(userId: String, request: UpdateUserRequest): User =
        httpClient.patch("$baseUrl/admin/users/$userId", request, authHeaders())

    /** Deletes a user permanently. */
    suspend fun deleteUser(userId: String): Unit =
        httpClient.delete("$baseUrl/admin/users/$userId", authHeaders())

    /** Lists users with optional pagination. Returns a [PageResponse]. */
    suspend fun listUsers(limit: Int = 20, cursor: String? = null): PageResponse<User> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/users$q", authHeaders())
    }

    // ── Realms ─────────────────────────────────────────────────────────────────
    //
    // Realms are provisioned via hearth.yaml, not the admin API. There is no
    // `createRealm` and no `updateRealm` method: the server answers 405 with
    // "Realms are managed via hearth.yaml" to both POST /admin/realms and
    // PATCH /admin/realms/{id} (HEA-2171, audit 2026-08-28 §25.4). Only read
    // paths and deletion are exposed.

    /** Retrieves a realm by [realmId]. */
    suspend fun getRealm(realmId: String): Realm =
        httpClient.get("$baseUrl/admin/realms/$realmId", authHeaders())

    /** Deletes a realm permanently. */
    suspend fun deleteRealm(realmId: String): Unit =
        httpClient.delete("$baseUrl/admin/realms/$realmId", authHeaders())

    /** Lists realms with optional pagination. */
    suspend fun listRealms(limit: Int = 20, cursor: String? = null): PageResponse<Realm> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/realms$q", authHeaders())
    }

    // ── OAuth Clients ──────────────────────────────────────────────────────────

    /** Registers a new OAuth 2.0 client. */
    suspend fun registerClient(request: RegisterClientRequest): OAuthClient =
        httpClient.post("$baseUrl/admin/applications", request, authHeaders())

    /** Retrieves an OAuth client by [clientId]. */
    suspend fun getClient(clientId: String): OAuthClient =
        httpClient.get("$baseUrl/admin/applications/$clientId", authHeaders())

    /** Updates an OAuth client. Only non-null fields are changed. */
    suspend fun updateClient(clientId: String, request: UpdateClientRequest): OAuthClient =
        httpClient.patch("$baseUrl/admin/applications/$clientId", request, authHeaders())

    /** Deletes an OAuth client permanently. */
    suspend fun deleteClient(clientId: String): Unit =
        httpClient.delete("$baseUrl/admin/applications/$clientId", authHeaders())

    /** Lists OAuth clients with optional pagination. */
    suspend fun listClients(limit: Int = 20, cursor: String? = null): PageResponse<OAuthClient> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/applications$q", authHeaders())
    }

    // ── Roles ──────────────────────────────────────────────────────────────────

    /** Creates a new role in the realm. */
    suspend fun createRole(request: CreateRoleRequest): Role =
        httpClient.post("$baseUrl/admin/roles", request, authHeaders())

    /** Retrieves a role by [roleId]. */
    suspend fun getRole(roleId: String): Role =
        httpClient.get("$baseUrl/admin/roles/$roleId", authHeaders())

    /** Updates a role. Only non-null fields are changed. */
    suspend fun updateRole(roleId: String, request: UpdateRoleRequest): Role =
        httpClient.patch("$baseUrl/admin/roles/$roleId", request, authHeaders())

    /** Deletes a role permanently. */
    suspend fun deleteRole(roleId: String): Unit =
        httpClient.delete("$baseUrl/admin/roles/$roleId", authHeaders())

    /** Lists roles with optional pagination. */
    suspend fun listRoles(limit: Int = 20, cursor: String? = null): PageResponse<Role> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/roles$q", authHeaders())
    }

    /**
     * Assigns [roleId] to [userId], realm-scoped unless [orgId] is supplied.
     *
     * The server registers `/admin/users/{id}/roles` as `GET`(list)`.POST`(assign)
     * and deserialises `{ "role_id": ..., "org_id"?: ... }`. This method used to
     * send `PUT` with a `{"roles":[...]}` body — a bare 405 from axum's method
     * router, and a 422 from the `Json` extractor even once the verb was right
     * (audit 2026-08-28 §25.19).
     *
     * A sub-admin may only assign a role whose permissions are a subset of their
     * own; the server answers 403 otherwise.
     */
    suspend fun assignRole(userId: String, roleId: String, orgId: String? = null): RoleAssignment =
        httpClient.post(
            "$baseUrl/admin/users/$userId/roles",
            AssignRoleRequest(roleId = roleId, orgId = orgId),
            authHeaders(),
        )

    /**
     * Lists the role assignments held by [userId].
     *
     * The handler answers `{"items": [...]}` with no cursor, so this is a
     * [PageResponse] with a permanently null `nextCursor`, not a bare list.
     */
    suspend fun listUserRoleAssignments(userId: String): PageResponse<RoleAssignment> =
        httpClient.get("$baseUrl/admin/users/$userId/roles", authHeaders())

    // ── Groups ─────────────────────────────────────────────────────────────────

    /** Creates a new group in the realm. */
    suspend fun createGroup(request: CreateGroupRequest): Group =
        httpClient.post("$baseUrl/admin/groups", request, authHeaders())

    /** Retrieves a group by [groupId]. */
    suspend fun getGroup(groupId: String): Group =
        httpClient.get("$baseUrl/admin/groups/$groupId", authHeaders())

    /** Updates a group. Only non-null fields are changed. */
    suspend fun updateGroup(groupId: String, request: UpdateGroupRequest): Group =
        httpClient.patch("$baseUrl/admin/groups/$groupId", request, authHeaders())

    /** Deletes a group permanently. */
    suspend fun deleteGroup(groupId: String): Unit =
        httpClient.delete("$baseUrl/admin/groups/$groupId", authHeaders())

    /** Lists groups with optional pagination. */
    suspend fun listGroups(limit: Int = 20, cursor: String? = null): PageResponse<Group> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/groups$q", authHeaders())
    }

    // ── Organization Memberships — removed ─────────────────────────────────────
    //
    // Hearth serves no organization route over HTTP: there is no /admin/orgs, no
    // /admin/orgs/{id}/members and no per-member route anywhere in the router, so
    // addOrgMember, removeOrgMember and listOrgMembers every one 404'd
    // (audit 2026-08-28 §25.19). Organization membership is administered through
    // the admin console, not the admin API.

    // ── SCIM-compatible bulk operations ────────────────────────────────────────

    /**
     * Lists users whose email matches [emailPrefix] (SCIM-style filter).
     * Uses the standard list endpoint with a `q` query parameter.
     */
    suspend fun findUsersByEmail(emailPrefix: String, limit: Int = 20): PageResponse<User> {
        val q = buildQueryString(mapOf("q" to emailPrefix, "limit" to limit.toString()))
        return httpClient.get("$baseUrl/admin/users$q", authHeaders())
    }

    private fun buildQueryString(params: Map<String, String?>): String {
        val parts = params.entries
            .filter { !it.value.isNullOrBlank() }
            .joinToString("&") { "${it.key}=${it.value}" }
        return if (parts.isEmpty()) "" else "?$parts"
    }
}
