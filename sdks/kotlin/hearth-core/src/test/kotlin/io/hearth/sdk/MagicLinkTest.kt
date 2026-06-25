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

/** Tests for the magic-link *send* half (`requestMagicLink`) added for C-12 parity. */
class MagicLinkTest {

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
    fun `requestMagicLink POSTs to v1 realm auth magic-link with email body`() = runTest {
        server.enqueue(MockResponse().setResponseCode(202))

        makeClient().requestMagicLink("user@example.com")

        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertTrue(req.path!!.endsWith("/v1/realm-1/auth/magic-link"))
        assertTrue(req.body.readUtf8().contains("\"email\":\"user@example.com\""))
    }

    @Test
    fun `requestMagicLink succeeds silently on 202 (enumeration resistance)`() = runTest {
        server.enqueue(MockResponse().setResponseCode(202))
        // Must not throw and must not require a response body.
        makeClient().requestMagicLink("nobody@example.com")
    }

    @Test
    fun `requestMagicLink throws ApiError on 429 rate limit`() = runTest {
        server.enqueue(MockResponse().setResponseCode(429))

        assertFailsWith<ApiError> { makeClient().requestMagicLink("user@example.com") }
    }

    @Test
    fun `requestMagicLink throws ConfigurationError when realmId is not set`() = runTest {
        assertFailsWith<ConfigurationError> { makeClient(realmId = null).requestMagicLink("user@example.com") }
    }
}
