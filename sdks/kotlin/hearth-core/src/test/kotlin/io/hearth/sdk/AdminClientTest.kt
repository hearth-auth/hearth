package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AdminClientTest {

    private lateinit var server: MockWebServer
    private lateinit var client: AdminClient

    @BeforeTest
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = AdminClient(
            baseUrl = server.url("/").toString().trimEnd('/'),
            realmId = "realm-1",
            accessToken = "admin-token",
        )
    }

    @AfterTest
    fun tearDown() {
        server.shutdown()
    }

    private fun userJson(id: String = "u1") =
        """{"id":"$id","email":"alice@example.com","display_name":"Alice","status":"active"}"""

    private fun realmJson(id: String = "r1") =
        """{"id":"$id","name":"Test Realm","status":"active"}"""

    private fun clientJson(id: String = "c1") =
        """{"client_id":"$id","client_name":"My App","redirect_uris":["https://app.example.com/callback"],"grant_types":["authorization_code"]}"""

    private fun roleJson(id: String = "role-1") =
        """{"id":"$id","name":"admin","description":"Admin role"}"""

    private fun groupJson(id: String = "grp-1") =
        """{"id":"$id","name":"engineering","description":"Engineering group"}"""

    private fun assignmentJson(id: String = "asg-1") =
        """{"id":"$id","realm_id":"realm-1","subject":{"type":"user","id":"u1"},""" +
            """"role_id":"role_456","scope":{"type":"realm"},"assigned_at":1234567890}"""

    // ── Realm-ID header ───────────────────────────────────────────────────────

    @Test
    fun `every request sends X-Realm-ID header`() = runTest {
        server.enqueue(MockResponse().setBody(userJson()).setResponseCode(200))
        client.getUser("u1")
        val req = server.takeRequest()
        assertEquals("realm-1", req.getHeader("X-Realm-ID"))
    }

    @Test
    fun `every request sends Authorization Bearer header`() = runTest {
        server.enqueue(MockResponse().setBody(userJson()).setResponseCode(200))
        client.getUser("u1")
        val req = server.takeRequest()
        assertEquals("Bearer admin-token", req.getHeader("Authorization"))
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    @Test
    fun `createUser POSTs to admin slash users`() = runTest {
        server.enqueue(MockResponse().setBody(userJson()).setResponseCode(200))
        val user = client.createUser(CreateUserRequest("alice@example.com", "Alice"))
        assertEquals("/admin/users", server.takeRequest().path)
        assertEquals("u1", user.id)
    }

    @Test
    fun `getUser GETs admin slash users slash id`() = runTest {
        server.enqueue(MockResponse().setBody(userJson()).setResponseCode(200))
        client.getUser("u1")
        assertEquals("/admin/users/u1", server.takeRequest().path)
    }

    @Test
    fun `updateUser PATCHes admin slash users slash id`() = runTest {
        server.enqueue(MockResponse().setBody(userJson()).setResponseCode(200))
        client.updateUser("u1", UpdateUserRequest(displayName = "Alice Updated"))
        val req = server.takeRequest()
        assertEquals("/admin/users/u1", req.path)
        assertEquals("PATCH", req.method)
    }

    @Test
    fun `deleteUser DELETEs admin slash users slash id`() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        client.deleteUser("u1")
        val req = server.takeRequest()
        assertEquals("/admin/users/u1", req.path)
        assertEquals("DELETE", req.method)
    }

    @Test
    fun `listUsers GETs admin slash users with pagination`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[${userJson()}],"next_cursor":null}""")
                .setResponseCode(200)
        )
        val page = client.listUsers(limit = 5)
        val path = server.takeRequest().path!!
        assertTrue(path.startsWith("/admin/users"))
        assertTrue(path.contains("limit=5"))
        assertEquals(1, page.items.size)
    }

    // ── Realms ────────────────────────────────────────────────────────────────

    @Test
    fun `getRealm GETs admin slash realms slash id`() = runTest {
        server.enqueue(MockResponse().setBody(realmJson()).setResponseCode(200))
        client.getRealm("r1")
        assertEquals("/admin/realms/r1", server.takeRequest().path)
    }

    @Test
    fun `deleteRealm DELETEs admin slash realms slash id`() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        client.deleteRealm("r1")
        val req = server.takeRequest()
        assertEquals("/admin/realms/r1", req.path)
        assertEquals("DELETE", req.method)
    }

    @Test
    fun `listRealms GETs admin slash realms`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[${realmJson()}],"next_cursor":null}""")
                .setResponseCode(200)
        )
        client.listRealms()
        assertTrue(server.takeRequest().path!!.startsWith("/admin/realms"))
    }

    // ── OAuth Clients ─────────────────────────────────────────────────────────

    @Test
    fun `registerClient POSTs to admin slash clients`() = runTest {
        server.enqueue(MockResponse().setBody(clientJson()).setResponseCode(200))
        client.registerClient(RegisterClientRequest("My App", listOf("https://app.example.com/callback")))
        assertEquals("/admin/applications", server.takeRequest().path)
    }

    @Test
    fun `getClient GETs admin slash clients slash id`() = runTest {
        server.enqueue(MockResponse().setBody(clientJson()).setResponseCode(200))
        client.getClient("c1")
        assertEquals("/admin/applications/c1", server.takeRequest().path)
    }

    @Test
    fun `updateClient PATCHes admin slash applications slash id`() = runTest {
        server.enqueue(MockResponse().setBody(clientJson()).setResponseCode(200))
        client.updateClient("c1", UpdateClientRequest(clientName = "Updated App"))
        val req = server.takeRequest()
        assertEquals("/admin/applications/c1", req.path)
        assertEquals("PATCH", req.method)
    }

    @Test
    fun `deleteClient DELETEs admin slash clients slash id`() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        client.deleteClient("c1")
        val req = server.takeRequest()
        assertEquals("/admin/applications/c1", req.path)
        assertEquals("DELETE", req.method)
    }

    @Test
    fun `listClients GETs admin slash clients`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[${clientJson()}],"next_cursor":null}""")
                .setResponseCode(200)
        )
        client.listClients()
        assertTrue(server.takeRequest().path!!.startsWith("/admin/applications"))
    }

    // ── Roles ─────────────────────────────────────────────────────────────────

    @Test
    fun `createRole POSTs to admin slash roles`() = runTest {
        server.enqueue(MockResponse().setBody(roleJson()).setResponseCode(200))
        client.createRole(CreateRoleRequest("admin", "Admin role"))
        assertEquals("/admin/roles", server.takeRequest().path)
    }

    @Test
    fun `getRole GETs admin slash roles slash id`() = runTest {
        server.enqueue(MockResponse().setBody(roleJson()).setResponseCode(200))
        client.getRole("role-1")
        assertEquals("/admin/roles/role-1", server.takeRequest().path)
    }

    @Test
    fun `updateRole PATCHes admin slash roles slash id`() = runTest {
        server.enqueue(MockResponse().setBody(roleJson()).setResponseCode(200))
        client.updateRole("role-1", UpdateRoleRequest(description = "Updated"))
        val req = server.takeRequest()
        assertEquals("/admin/roles/role-1", req.path)
        assertEquals("PATCH", req.method)
    }

    @Test
    fun `deleteRole DELETEs admin slash roles slash id`() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        client.deleteRole("role-1")
        val req = server.takeRequest()
        assertEquals("/admin/roles/role-1", req.path)
        assertEquals("DELETE", req.method)
    }

    @Test
    fun `listRoles GETs admin slash roles`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[${roleJson()}],"next_cursor":null}""")
                .setResponseCode(200)
        )
        client.listRoles()
        assertTrue(server.takeRequest().path!!.startsWith("/admin/roles"))
    }

    // ── Groups ────────────────────────────────────────────────────────────────

    @Test
    fun `createGroup POSTs to admin slash groups`() = runTest {
        server.enqueue(MockResponse().setBody(groupJson()).setResponseCode(200))
        client.createGroup(CreateGroupRequest("engineering", "Engineering group"))
        assertEquals("/admin/groups", server.takeRequest().path)
    }

    @Test
    fun `getGroup GETs admin slash groups slash id`() = runTest {
        server.enqueue(MockResponse().setBody(groupJson()).setResponseCode(200))
        client.getGroup("grp-1")
        assertEquals("/admin/groups/grp-1", server.takeRequest().path)
    }

    @Test
    fun `updateGroup PATCHes admin slash groups slash id`() = runTest {
        server.enqueue(MockResponse().setBody(groupJson()).setResponseCode(200))
        client.updateGroup("grp-1", UpdateGroupRequest(description = "Updated"))
        val req = server.takeRequest()
        assertEquals("/admin/groups/grp-1", req.path)
        assertEquals("PATCH", req.method)
    }

    @Test
    fun `deleteGroup DELETEs admin slash groups slash id`() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        client.deleteGroup("grp-1")
        val req = server.takeRequest()
        assertEquals("/admin/groups/grp-1", req.path)
        assertEquals("DELETE", req.method)
    }

    @Test
    fun `listGroups GETs admin slash groups`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[${groupJson()}],"next_cursor":null}""")
                .setResponseCode(200)
        )
        client.listGroups()
        assertTrue(server.takeRequest().path!!.startsWith("/admin/groups"))
    }

    // ── Organization Memberships — removed ────────────────────────────────────
    //
    // Hearth serves no organization route over HTTP: there is no /admin/orgs, no
    // /admin/orgs/{id}/members and no per-member route anywhere in the router, so
    // addOrgMember, removeOrgMember and listOrgMembers every one 404'd
    // (audit 2026-08-28 §25.19). The X-Realm-ID coverage these tests carried is
    // already held by `every request sends X-Realm-ID header` above.

    // ── Role assignment ───────────────────────────────────────────────────────

    @Test
    fun `assignRole POSTs to admin slash users slash id slash roles`() = runTest {
        // The server registers `/users/{id}/roles` as GET(list).POST(assign).
        // A PUT gets a bare 405 from axum's method router
        // (audit 2026-08-28 §25.19).
        server.enqueue(MockResponse().setBody(assignmentJson()).setResponseCode(201))
        client.assignRole("u1", "role_456")
        val req = server.takeRequest()
        assertEquals("/admin/users/u1/roles", req.path)
        assertEquals("POST", req.method)
    }

    @Test
    fun `assignRole sends the role_id body the server deserialises`() = runTest {
        // `AssignRoleBody { role_id, org_id? }` — a `{"roles":[...]}` body is a
        // 422 from the Json extractor before the handler ever runs.
        server.enqueue(MockResponse().setBody(assignmentJson()).setResponseCode(201))
        client.assignRole("u1", "role_456")
        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains(""""role_id":"role_456""""), "body was $body")
        assertTrue(!body.contains("\"roles\""), "body still sends the dead `roles` array: $body")
    }

    @Test
    fun `listUserRoleAssignments GETs the roles route and unwraps items`() = runTest {
        // The handler answers `{"items": [...]}` — not a bare array — so a
        // List<RoleAssignment> return type would fail to deserialise.
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[${assignmentJson()}]}""")
                .setResponseCode(200)
        )
        val page = client.listUserRoleAssignments("u1")
        val req = server.takeRequest()
        assertEquals("/admin/users/u1/roles", req.path)
        assertEquals("GET", req.method)
        assertEquals(1, page.items.size)
        assertEquals("role_456", page.items[0].roleId)
    }

    @Test
    fun `assignRole passes org_id through for an org-scoped assignment`() = runTest {
        server.enqueue(MockResponse().setBody(assignmentJson()).setResponseCode(201))
        client.assignRole("u1", "role_456", orgId = "org_abc")
        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains(""""org_id":"org_abc""""), "body was $body")
    }
}
