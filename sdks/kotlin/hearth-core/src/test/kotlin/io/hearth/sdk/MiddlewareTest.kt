package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MiddlewareTest {

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

    /** Builds a minimal JWT with the given JSON payload (signature not verified locally). */
    private fun makeToken(payload: String): String {
        val enc = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"EdDSA","kid":"test"}""".toByteArray())
        val body = enc.encodeToString(payload.toByteArray())
        return "$header.$body.AAAA"
    }

    private val tokenWithPerms = makeToken("""{"permissions":["docs.read"],"sub":"u1"}""")
    private val tokenNoPerms   = makeToken("""{"sub":"u1"}""")

    private fun makeClient(
        clientId: String? = null,
        clientSecret: String? = null,
        introspectionOverride: String? = null,
    ) = HearthClient(
        issuerUrl = server.url("/").toString().trimEnd('/'),
        realmId = "realm-1",
        clientId = clientId,
        clientSecret = clientSecret,
        introspectionEndpointOverride = introspectionOverride,
    )

    // ── EMBEDDED mode ─────────────────────────────────────────────────────────

    @Test
    fun `embedded - returns true when permissions claim contains permission`() = runTest {
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertTrue(checker.check(tokenWithPerms))
    }

    @Test
    fun `embedded - returns false when permission not in claim`() = runTest {
        val checker = requirePermission(
            "docs.write",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertFalse(checker.check(tokenWithPerms))
    }

    @Test
    fun `embedded - returns false when permissions claim absent`() = runTest {
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertFalse(checker.check(tokenNoPerms))
    }

    @Test
    fun `embedded - makes no network calls`() = runTest {
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        checker.check(tokenWithPerms)
        checker.check(tokenNoPerms)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `embedded - does not fall back to network when claim absent`() = runTest {
        // Even if we could call /oauth/authorize, embedded mode must NOT do so.
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        // token has no permissions claim — must return false, not hit the server
        assertFalse(checker.check(tokenNoPerms))
        assertEquals(0, server.requestCount)
    }

    // ── DECISION mode ─────────────────────────────────────────────────────────

    @Test
    fun `decision - returns true when server responds allowed=true`() = runTest {
        server.enqueue(MockResponse().setBody("""{"allowed":true}""").setResponseCode(200))

        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.DECISION, client = makeClient()),
        )
        assertTrue(checker.check("some-token"))
    }

    @Test
    fun `decision - returns false when server responds allowed=false`() = runTest {
        server.enqueue(MockResponse().setBody("""{"allowed":false}""").setResponseCode(200))

        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.DECISION, client = makeClient()),
        )
        assertFalse(checker.check("some-token"))
    }

    @Test
    fun `decision - fail-closed on 5xx`() = runTest {
        server.enqueue(MockResponse().setResponseCode(503))

        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.DECISION, client = makeClient()),
        )
        assertFalse(checker.check("some-token"))
    }

    @Test
    fun `decision - sends permission and realm header`() = runTest {
        server.enqueue(MockResponse().setBody("""{"allowed":true}""").setResponseCode(200))

        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.DECISION, client = makeClient()),
        )
        checker.check("bearer-xyz")

        val req = server.takeRequest()
        assertEquals("/oauth/authorize", req.path)
        assertEquals("realm-1", req.getHeader("X-Realm-ID"))
        assertEquals("Bearer bearer-xyz", req.getHeader("Authorization"))
        assertTrue(req.body.readUtf8().contains("docs.read"))
    }

    @Test
    fun `decision - includes organizationId when provided`() = runTest {
        server.enqueue(MockResponse().setBody("""{"allowed":true}""").setResponseCode(200))

        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(
                mode = AccessTokenAuthorizationMode.DECISION,
                client = makeClient(),
                organizationId = "org-abc",
            ),
        )
        checker.check("some-token")

        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("org-abc"))
    }

    // ── INTROSPECTION mode ────────────────────────────────────────────────────

    @Test
    fun `introspection - returns true when active and permission present`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"active":true,"mode":"introspection","permissions":["docs.read"],"sub":"u1"}""")
                .setResponseCode(200)
        )

        val client = makeClient(
            clientId = "app",
            clientSecret = "secret",
            introspectionOverride = server.url("/introspect").toString(),
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.INTROSPECTION, client = client),
        )
        assertTrue(checker.check("some-token"))
    }

    @Test
    fun `introspection - returns false when active=false`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"active":false,"mode":"introspection","permissions":["docs.read"]}""")
                .setResponseCode(200)
        )

        val client = makeClient(
            clientId = "app",
            clientSecret = "secret",
            introspectionOverride = server.url("/introspect").toString(),
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.INTROSPECTION, client = client),
        )
        assertFalse(checker.check("some-token"))
    }

    @Test
    fun `introspection - throws AuthorizationModeMismatchError on mode echo mismatch`() = runTest {
        // Server echoes "embedded" but SDK is configured for "introspection"
        server.enqueue(
            MockResponse()
                .setBody("""{"active":true,"mode":"embedded","permissions":["docs.read"]}""")
                .setResponseCode(200)
        )

        val client = makeClient(
            clientId = "app",
            clientSecret = "secret",
            introspectionOverride = server.url("/introspect").toString(),
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.INTROSPECTION, client = client),
        )
        assertFailsWith<AuthorizationModeMismatchError> { checker.check("some-token") }
    }

    @Test
    fun `introspection - absent mode field defaults to embedded and triggers mismatch`() = runTest {
        // No mode field → treated as "embedded" → mismatch with configured "introspection"
        server.enqueue(
            MockResponse()
                .setBody("""{"active":true,"permissions":["docs.read"]}""")
                .setResponseCode(200)
        )

        val client = makeClient(
            clientId = "app",
            clientSecret = "secret",
            introspectionOverride = server.url("/introspect").toString(),
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.INTROSPECTION, client = client),
        )
        assertFailsWith<AuthorizationModeMismatchError> { checker.check("some-token") }
    }

    @Test
    fun `introspection - returns false when permission not in list`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"active":true,"mode":"introspection","permissions":["docs.read"]}""")
                .setResponseCode(200)
        )

        val client = makeClient(
            clientId = "app",
            clientSecret = "secret",
            introspectionOverride = server.url("/introspect").toString(),
        )
        val checker = requirePermission(
            "docs.write",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.INTROSPECTION, client = client),
        )
        assertFalse(checker.check("some-token"))
    }

    // ── §6 Rule 6: required_action token detection ────────────────────────────

    @Test
    fun `embedded - throws RequiredActionError when token_type is required_action`() = runTest {
        val requiredActionToken = makeToken(
            """{"token_type":"required_action","required_actions":["VERIFY_EMAIL"],"sub":"u1"}"""
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertFailsWith<RequiredActionError> { checker.check(requiredActionToken) }
    }

    @Test
    fun `embedded - RequiredActionError has populated requiredActions from token`() = runTest {
        val requiredActionToken = makeToken(
            """{"token_type":"required_action","required_actions":["VERIFY_EMAIL","UPDATE_PASSWORD"],"sub":"u1"}"""
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        val err = assertFailsWith<RequiredActionError> { checker.check(requiredActionToken) }
        assertEquals(listOf("VERIFY_EMAIL", "UPDATE_PASSWORD"), err.requiredActions)
    }

    @Test
    fun `decision - throws RequiredActionError when token_type is required_action`() = runTest {
        val requiredActionToken = makeToken(
            """{"token_type":"required_action","required_actions":["VERIFY_EMAIL"],"sub":"u1"}"""
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.DECISION, client = makeClient()),
        )
        assertFailsWith<RequiredActionError> { checker.check(requiredActionToken) }
        // must not hit the server
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `introspection - throws RequiredActionError when token_type is required_action`() = runTest {
        val requiredActionToken = makeToken(
            """{"token_type":"required_action","required_actions":["VERIFY_EMAIL"],"sub":"u1"}"""
        )
        val client = makeClient(
            clientId = "app",
            clientSecret = "secret",
            introspectionOverride = server.url("/introspect").toString(),
        )
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.INTROSPECTION, client = client),
        )
        assertFailsWith<RequiredActionError> { checker.check(requiredActionToken) }
        // must not hit the introspection endpoint
        assertEquals(0, server.requestCount)
    }
}
