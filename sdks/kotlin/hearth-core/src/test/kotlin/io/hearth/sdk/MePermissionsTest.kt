package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MePermissionsTest {

    private lateinit var server: MockWebServer

    @BeforeTest
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterTest
    fun tearDown() {
        server.shutdown()
    }

    private fun makeClient(realmId: String? = "realm-1") = HearthClient(
        issuerUrl = server.url("/").toString().trimEnd('/'),
        realmId = realmId,
    )

    @Test
    fun `mePermissions sends GET to v1 me permissions`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"roles":["admin"],"groups":["eng"],"permissions":["docs.read"],"scope":"openid"}""")
                .setResponseCode(200)
        )

        makeClient().mePermissions("token")

        val req = server.takeRequest()
        assertEquals("GET", req.method)
        assertTrue(req.path!!.endsWith("/v1/me/permissions"))
    }

    @Test
    fun `mePermissions sends Authorization header`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"roles":[],"groups":[],"permissions":[],"scope":"openid"}""")
                .setResponseCode(200)
        )

        makeClient().mePermissions("bearer-xyz")

        val req = server.takeRequest()
        assertEquals("Bearer bearer-xyz", req.getHeader("Authorization"))
    }

    @Test
    fun `mePermissions sends X-Realm-ID header`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"roles":[],"groups":[],"permissions":[],"scope":"openid"}""")
                .setResponseCode(200)
        )

        makeClient("my-realm").mePermissions("token")

        val req = server.takeRequest()
        assertEquals("my-realm", req.getHeader("X-Realm-ID"))
    }

    @Test
    fun `mePermissions returns parsed MePermissionsResponse`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"roles":["admin","viewer"],"groups":["eng","qa"],""" +
                    """"permissions":["docs.read","docs.write"],"scope":"openid profile"}"""
                )
                .setResponseCode(200)
        )

        val result = makeClient().mePermissions("token")

        assertEquals(listOf("admin", "viewer"), result.roles)
        assertEquals(listOf("eng", "qa"), result.groups)
        assertEquals(listOf("docs.read", "docs.write"), result.permissions)
        assertEquals("openid profile", result.scope)
    }

    @Test
    fun `mePermissions throws ApiError on non-2xx response`() = runTest {
        server.enqueue(MockResponse().setResponseCode(401))

        assertFailsWith<ApiError> { makeClient().mePermissions("expired-token") }
    }

    @Test
    fun `mePermissions throws ConfigurationError when realmId is not set`() = runTest {
        assertFailsWith<ConfigurationError> { makeClient(realmId = null).mePermissions("token") }
    }
}
