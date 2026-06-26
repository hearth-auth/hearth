package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Tests for HearthClient.beginLogin() and completeLogin() (HEA-1592).
 */
class LoginTest {

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

    private val discoveryDoc get() = """
        {
          "issuer": "${server.url("/").toString().trimEnd('/')}",
          "jwks_uri": "${server.url("/jwks")}",
          "token_endpoint": "${server.url("/token")}",
          "authorization_endpoint": "${server.url("/authorize")}",
          "userinfo_endpoint": "${server.url("/userinfo")}"
        }
    """.trimIndent()

    private fun makeClient(opts: Map<String, String?> = emptyMap()): HearthClient =
        HearthClient(
            issuerUrl = server.url("/").toString().trimEnd('/'),
            clientId = opts["clientId"] ?: "test-client",
            clientSecret = opts["clientSecret"] ?: "s3cr3t",
        )

    private fun parseQuery(query: String): Map<String, String> =
        query.split("&").associate { part ->
            val (k, v) = part.split("=", limit = 2)
            URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
        }

    // ── beginLogin ────────────────────────────────────────────────────────────

    @Test
    fun `beginLogin returns authorizationUrl with code_challenge derived from codeVerifier`() = runTest {
        server.enqueue(MockResponse().setBody(discoveryDoc).setResponseCode(200))

        val client = makeClient()
        val result = client.beginLogin("https://app.example.com/callback")

        val url = java.net.URL(result.authorizationUrl)
        val params = parseQuery(url.query)
        val challenge = params["code_challenge"] ?: error("code_challenge missing")

        val digest = MessageDigest.getInstance("SHA-256").digest(result.codeVerifier.toByteArray())
        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        assertEquals(expected, challenge, "code_challenge must be BASE64URL(SHA256(codeVerifier))")
    }

    @Test
    fun `beginLogin state is non-empty and present in URL`() = runTest {
        server.enqueue(MockResponse().setBody(discoveryDoc).setResponseCode(200))

        val client = makeClient()
        val result = client.beginLogin("https://app.example.com/callback")

        assertTrue(result.state.isNotEmpty(), "state must not be empty")
        val url = java.net.URL(result.authorizationUrl)
        val params = parseQuery(url.query)
        assertEquals(result.state, params["state"], "state in URL must match returned state")
    }

    @Test
    fun `beginLogin URL contains required OAuth and PKCE params`() = runTest {
        server.enqueue(MockResponse().setBody(discoveryDoc).setResponseCode(200))

        val client = makeClient()
        val result = client.beginLogin("https://app.example.com/callback", "openid profile")

        val url = java.net.URL(result.authorizationUrl)
        val params = parseQuery(url.query)
        assertEquals("code", params["response_type"])
        assertEquals("test-client", params["client_id"])
        assertEquals("https://app.example.com/callback", params["redirect_uri"])
        assertEquals("openid profile", params["scope"])
        assertEquals("S256", params["code_challenge_method"])
        assertNotNull(params["code_challenge"])
    }

    @Test
    fun `beginLogin defaults scope to openid`() = runTest {
        server.enqueue(MockResponse().setBody(discoveryDoc).setResponseCode(200))

        val client = makeClient()
        val result = client.beginLogin("https://app.example.com/callback")

        val params = parseQuery(java.net.URL(result.authorizationUrl).query)
        assertEquals("openid", params["scope"])
    }

    @Test
    fun `beginLogin throws ConfigurationError when clientId is not set`() = runTest {
        val client = HearthClient(
            issuerUrl = server.url("/").toString().trimEnd('/'),
            clientId = null,
        )
        assertFailsWith<ConfigurationError> {
            client.beginLogin("https://app.example.com/callback")
        }
    }

    // ── completeLogin ─────────────────────────────────────────────────────────

    @Test
    fun `completeLogin posts code_verifier to token endpoint`() = runTest {
        server.enqueue(MockResponse().setBody(discoveryDoc).setResponseCode(200))
        server.enqueue(
            MockResponse().setBody(
                """{"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}"""
            ).setResponseCode(200)
        )

        val client = makeClient()
        val tokens = client.completeLogin(
            code = "auth-code-xyz",
            codeVerifier = "my-verifier-abc",
            redirectUri = "https://app.example.com/callback",
        )

        assertEquals("eyJ...", tokens.accessToken)

        // The second request must be to the token endpoint with the verifier.
        server.takeRequest() // discovery
        val tokenReq = server.takeRequest()
        val body = tokenReq.body.readUtf8()
        // Token endpoint receives JSON (Kotlin SDK uses JSON encoding)
        assertTrue(body.contains("my-verifier-abc"), "code_verifier missing: $body")
        assertTrue(body.contains("auth-code-xyz"), "code missing: $body")
        assertTrue(body.contains("authorization_code"), "grant_type missing: $body")
    }
}
