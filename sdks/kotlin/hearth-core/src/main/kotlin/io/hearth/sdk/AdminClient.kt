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
        httpClient.put("$baseUrl/admin/users/$userId", request, authHeaders())

    /** Deletes a user permanently. */
    suspend fun deleteUser(userId: String): Unit =
        httpClient.delete("$baseUrl/admin/users/$userId", authHeaders())

    /** Lists users with optional pagination. Returns a [PageResponse]. */
    suspend fun listUsers(limit: Int = 20, cursor: String? = null): PageResponse<User> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/users$q", authHeaders())
    }

    // ── Realms ─────────────────────────────────────────────────────────────────

    /** Creates a new realm. */
    suspend fun createRealm(request: CreateRealmRequest): Realm =
        httpClient.post("$baseUrl/admin/realms", request, authHeaders())

    /** Retrieves a realm by [realmId]. */
    suspend fun getRealm(realmId: String): Realm =
        httpClient.get("$baseUrl/admin/realms/$realmId", authHeaders())

    /** Updates a realm. Only non-null fields are changed. */
    suspend fun updateRealm(realmId: String, request: UpdateRealmRequest): Realm =
        httpClient.put("$baseUrl/admin/realms/$realmId", request, authHeaders())

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
        httpClient.post("$baseUrl/admin/clients", request, authHeaders())

    /** Retrieves an OAuth client by [clientId]. */
    suspend fun getClient(clientId: String): OAuthClient =
        httpClient.get("$baseUrl/admin/clients/$clientId", authHeaders())

    /** Updates an OAuth client. Only non-null fields are changed. */
    suspend fun updateClient(clientId: String, request: UpdateClientRequest): OAuthClient =
        httpClient.put("$baseUrl/admin/clients/$clientId", request, authHeaders())

    /** Deletes an OAuth client permanently. */
    suspend fun deleteClient(clientId: String): Unit =
        httpClient.delete("$baseUrl/admin/clients/$clientId", authHeaders())

    /** Lists OAuth clients with optional pagination. */
    suspend fun listClients(limit: Int = 20, cursor: String? = null): PageResponse<OAuthClient> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/clients$q", authHeaders())
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
        httpClient.put("$baseUrl/admin/roles/$roleId", request, authHeaders())

    /** Deletes a role permanently. */
    suspend fun deleteRole(roleId: String): Unit =
        httpClient.delete("$baseUrl/admin/roles/$roleId", authHeaders())

    /** Lists roles with optional pagination. */
    suspend fun listRoles(limit: Int = 20, cursor: String? = null): PageResponse<Role> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/roles$q", authHeaders())
    }

    /**
     * Assigns [role] to [userId].
     *
     * Implementation note: Hearth exposes role assignment via the user roles endpoint.
     */
    suspend fun assignRole(userId: String, role: String): User {
        @kotlinx.serialization.Serializable
        data class RoleRequest(val roles: List<String>)
        return httpClient.put(
            "$baseUrl/admin/users/$userId/roles",
            RoleRequest(listOf(role)),
            authHeaders(),
        )
    }

    // ── Groups ─────────────────────────────────────────────────────────────────

    /** Creates a new group in the realm. */
    suspend fun createGroup(request: CreateGroupRequest): Group =
        httpClient.post("$baseUrl/admin/groups", request, authHeaders())

    /** Retrieves a group by [groupId]. */
    suspend fun getGroup(groupId: String): Group =
        httpClient.get("$baseUrl/admin/groups/$groupId", authHeaders())

    /** Updates a group. Only non-null fields are changed. */
    suspend fun updateGroup(groupId: String, request: UpdateGroupRequest): Group =
        httpClient.put("$baseUrl/admin/groups/$groupId", request, authHeaders())

    /** Deletes a group permanently. */
    suspend fun deleteGroup(groupId: String): Unit =
        httpClient.delete("$baseUrl/admin/groups/$groupId", authHeaders())

    /** Lists groups with optional pagination. */
    suspend fun listGroups(limit: Int = 20, cursor: String? = null): PageResponse<Group> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/groups$q", authHeaders())
    }

    // ── Organization Memberships ───────────────────────────────────────────────

    /** Adds [userId] to organization [orgId] with the given [role]. */
    suspend fun addOrgMember(orgId: String, request: AddOrgMemberRequest): OrgMember =
        httpClient.post("$baseUrl/admin/orgs/$orgId/members", request, authHeaders())

    /** Removes [userId] from organization [orgId]. */
    suspend fun removeOrgMember(orgId: String, userId: String): Unit =
        httpClient.delete("$baseUrl/admin/orgs/$orgId/members/$userId", authHeaders())

    /** Lists members of organization [orgId] with optional pagination. */
    suspend fun listOrgMembers(
        orgId: String,
        limit: Int = 20,
        cursor: String? = null,
    ): PageResponse<OrgMember> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/orgs/$orgId/members$q", authHeaders())
    }

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
