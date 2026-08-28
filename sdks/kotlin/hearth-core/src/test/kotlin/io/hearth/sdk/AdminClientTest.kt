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

    private fun memberJson(userId: String = "u1") =
        """{"user_id":"$userId","role":"member","joined_at":1234567890}"""

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
    fun `updateUser PUTs to admin slash users slash id`() = runTest {
        server.enqueue(MockResponse().setBody(userJson()).setResponseCode(200))
        client.updateUser("u1", UpdateUserRequest(displayName = "Alice Updated"))
        assertEquals("/admin/users/u1", server.takeRequest().path)
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
    fun `updateRealm PUTs to admin slash realms slash id`() = runTest {
        server.enqueue(MockResponse().setBody(realmJson()).setResponseCode(200))
        client.updateRealm("r1", UpdateRealmRequest(name = "Updated"))
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
        assertEquals("/admin/clients", server.takeRequest().path)
    }

    @Test
    fun `getClient GETs admin slash clients slash id`() = runTest {
        server.enqueue(MockResponse().setBody(clientJson()).setResponseCode(200))
        client.getClient("c1")
        assertEquals("/admin/clients/c1", server.takeRequest().path)
    }

    @Test
    fun `updateClient PUTs to admin slash clients slash id`() = runTest {
        server.enqueue(MockResponse().setBody(clientJson()).setResponseCode(200))
        client.updateClient("c1", UpdateClientRequest(clientName = "Updated App"))
        assertEquals("/admin/clients/c1", server.takeRequest().path)
    }

    @Test
    fun `deleteClient DELETEs admin slash clients slash id`() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        client.deleteClient("c1")
        val req = server.takeRequest()
        assertEquals("/admin/clients/c1", req.path)
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
        assertTrue(server.takeRequest().path!!.startsWith("/admin/clients"))
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
    fun `updateRole PUTs to admin slash roles slash id`() = runTest {
        server.enqueue(MockResponse().setBody(roleJson()).setResponseCode(200))
        client.updateRole("role-1", UpdateRoleRequest(description = "Updated"))
        assertEquals("/admin/roles/role-1", server.takeRequest().path)
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
    fun `updateGroup PUTs to admin slash groups slash id`() = runTest {
        server.enqueue(MockResponse().setBody(groupJson()).setResponseCode(200))
        client.updateGroup("grp-1", UpdateGroupRequest(description = "Updated"))
        assertEquals("/admin/groups/grp-1", server.takeRequest().path)
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

    // ── Organization Memberships ──────────────────────────────────────────────

    @Test
    fun `addOrgMember POSTs to admin slash orgs slash orgId slash members`() = runTest {
        server.enqueue(MockResponse().setBody(memberJson()).setResponseCode(200))
        client.addOrgMember("org-1", AddOrgMemberRequest("u1", "member"))
        assertEquals("/admin/orgs/org-1/members", server.takeRequest().path)
    }

    @Test
    fun `removeOrgMember DELETEs admin slash orgs slash orgId slash members slash userId`() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))
        client.removeOrgMember("org-1", "u1")
        val req = server.takeRequest()
        assertEquals("/admin/orgs/org-1/members/u1", req.path)
        assertEquals("DELETE", req.method)
    }

    @Test
    fun `listOrgMembers GETs admin slash orgs slash orgId slash members`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[${memberJson()}],"next_cursor":null}""")
                .setResponseCode(200)
        )
        client.listOrgMembers("org-1")
        assertTrue(server.takeRequest().path!!.startsWith("/admin/orgs/org-1/members"))
    }

    @Test
    fun `listOrgMembers sends X-Realm-ID header`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"items":[],"next_cursor":null}""")
                .setResponseCode(200)
        )
        client.listOrgMembers("org-1")
        assertEquals("realm-1", server.takeRequest().getHeader("X-Realm-ID"))
    }
}
