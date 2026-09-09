package io.hearth.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.util.Date
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

    /**
     * Builds a minimal JWT with the given JSON payload and a garbage signature.
     * Models an attacker's token — the EMBEDDED checker verifies, so this is only
     * ever acceptable to modes that do not read the payload themselves.
     */
    private fun makeToken(payload: String): String {
        val enc = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"EdDSA","kid":"test"}""".toByteArray())
        val body = enc.encodeToString(payload.toByteArray())
        return "$header.$body.AAAA"
    }

    private val tokenWithPerms = makeToken("""{"permissions":["docs.read"],"sub":"u1"}""")
    private val tokenNoPerms   = makeToken("""{"sub":"u1"}""")

    // ── Real signing key, for the EMBEDDED tests that must be admitted ────────

    private val keyPair: OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519)
        .keyID("hearth-ed-1")
        .generate()

    private fun issuerUrl(): String = server.url("/").toString().trimEnd('/')

    /** Queue enough discovery + JWKS responses for [checks] verifications. */
    private fun enqueueIssuerResponses(checks: Int = 4) {
        repeat(checks) {
            server.enqueue(
                MockResponse()
                    .setBody("""{"issuer":"${issuerUrl()}","jwks_uri":"${issuerUrl()}/jwks"}""")
                    .setResponseCode(200),
            )
            server.enqueue(
                MockResponse().setBody(JWKSet(keyPair.toPublicJWK()).toString()).setResponseCode(200),
            )
        }
    }

    /** Mints a properly signed token carrying [permissions] (null omits the claim). */
    private fun signedToken(permissions: List<String>?): String {
        val now = System.currentTimeMillis()
        val claims = JWTClaimsSet.Builder()
            .subject("u1")
            .issuer(issuerUrl())
            .issueTime(Date(now))
            .expirationTime(Date(now + 300_000L))
            .apply { permissions?.let { claim("permissions", it) } }
            .build()
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("hearth-ed-1").build(),
            claims,
        )
        jwt.sign(Ed25519Signer(keyPair))
        return jwt.serialize()
    }

    /** Paths the server was asked for, drained from the MockWebServer queue. */
    private fun requestedPaths(): List<String> =
        (0 until server.requestCount).mapNotNull { server.takeRequest().path }

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
        enqueueIssuerResponses()
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertTrue(checker.check(signedToken(listOf("docs.read"))))
    }

    @Test
    fun `embedded - returns false when permission not in claim`() = runTest {
        enqueueIssuerResponses()
        val checker = requirePermission(
            "docs.write",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertFalse(checker.check(signedToken(listOf("docs.read"))))
    }

    @Test
    fun `embedded - returns false when permissions claim absent`() = runTest {
        enqueueIssuerResponses()
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertFalse(checker.check(signedToken(null)))
    }

    @Test
    fun `embedded - refuses a token whose signature does not verify`() = runTest {
        enqueueIssuerResponses()
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertFalse(
            checker.check(tokenWithPerms),
            "EMBEDDED checker admitted a token with a garbage signature",
        )
    }

    @Test
    fun `embedded - does not fall back to a network authorization call`() = runTest {
        // Discovery and JWKS are expected traffic — they are how the signature gets
        // checked. Reaching for /oauth/authorize or /introspect would be the fallback
        // this design constraint forbids.
        enqueueIssuerResponses()
        val checker = requirePermission(
            "docs.read",
            RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = makeClient()),
        )
        assertFalse(checker.check(signedToken(null)))

        val authzCalls = requestedPaths().filter {
            it.contains("/oauth/authorize") || it.contains("/introspect")
        }
        assertEquals(emptyList(), authzCalls)
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
