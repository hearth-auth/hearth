package io.hearth.sdk

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class WebAuthnTest {

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

    private fun makeClient(realmId: String = "realm-1") = HearthClient(
        issuerUrl = server.url("/").toString().trimEnd('/'),
        realmId = realmId,
    )

    // ── Registration begin ────────────────────────────────────────────────────

    @Test
    fun `startWebAuthnRegistration posts to webauthn register begin`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"challenge":"abc123","rp_id":"example.com","rp_name":"Example",""" +
                    """"user_id":"u1","user_name":"alice","user_display_name":"Alice",""" +
                    """"attestation":"none","timeout":60000}"""
                )
                .setResponseCode(200)
        )

        makeClient().startWebAuthnRegistration("bearer-token")

        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertTrue(req.path!!.endsWith("/webauthn/register/begin"), "path was: ${req.path}")
    }

    @Test
    fun `startWebAuthnRegistration sends Authorization header`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"challenge":"c","rp_id":"x","rp_name":"X","user_id":"u",""" +
                    """"user_name":"u","user_display_name":"U","attestation":"none","timeout":60000}"""
                )
                .setResponseCode(200)
        )

        makeClient().startWebAuthnRegistration("my-access-token")

        val req = server.takeRequest()
        assertEquals("Bearer my-access-token", req.getHeader("Authorization"))
    }

    @Test
    fun `startWebAuthnRegistration returns parsed response`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"challenge":"abc123","rp_id":"example.com","rp_name":"Example App",""" +
                    """"user_id":"user-1","user_name":"alice","user_display_name":"Alice Smith",""" +
                    """"attestation":"none","timeout":60000}"""
                )
                .setResponseCode(200)
        )

        val resp = makeClient().startWebAuthnRegistration("token")

        assertEquals("abc123", resp.challenge)
        assertEquals("example.com", resp.rpId)
        assertEquals("Example App", resp.rpName)
        assertEquals("user-1", resp.userId)
        assertEquals("alice", resp.userName)
        assertEquals("Alice Smith", resp.userDisplayName)
        assertEquals("none", resp.attestation)
        assertEquals(60_000L, resp.timeout)
    }

    // ── Registration finish ───────────────────────────────────────────────────

    @Test
    fun `finishWebAuthnRegistration posts to webauthn register complete`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"credential_id":"cred-abc","algorithm":-7,"discoverable":true}""")
                .setResponseCode(200)
        )

        makeClient().finishWebAuthnRegistration(
            "bearer-token",
            WebAuthnRegistrationCompleteRequest(
                clientDataJson = "eyJ...",
                attestationObject = "o2N...",
                origin = "https://example.com",
            ),
        )

        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertTrue(req.path!!.endsWith("/webauthn/register/complete"), "path was: ${req.path}")
    }

    @Test
    fun `finishWebAuthnRegistration returns parsed credential response`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody("""{"credential_id":"cred-xyz","algorithm":-8,"discoverable":false}""")
                .setResponseCode(200)
        )

        val resp = makeClient().finishWebAuthnRegistration(
            "token",
            WebAuthnRegistrationCompleteRequest(
                clientDataJson = "eyJ...",
                attestationObject = "o2N...",
                origin = "https://example.com",
                discoverable = true,
            ),
        )

        assertEquals("cred-xyz", resp.credentialId)
        assertEquals(-8L, resp.algorithm)
        assertEquals(false, resp.discoverable)
    }

    // ── Authentication begin ──────────────────────────────────────────────────

    @Test
    fun `startWebAuthnAuthentication posts to webauthn auth begin`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"challenge":"xyz789","rp_id":"example.com","allow_credentials":[],""" +
                    """"user_verification":"preferred","timeout":60000}"""
                )
                .setResponseCode(200)
        )

        makeClient().startWebAuthnAuthentication()

        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertTrue(req.path!!.endsWith("/webauthn/auth/begin"), "path was: ${req.path}")
    }

    @Test
    fun `startWebAuthnAuthentication without userId sends empty body`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"challenge":"c","rp_id":"x","allow_credentials":[],""" +
                    """"user_verification":"preferred","timeout":60000}"""
                )
                .setResponseCode(200)
        )

        makeClient().startWebAuthnAuthentication()

        val req = server.takeRequest()
        val body = req.body.readUtf8()
        assertTrue(!body.contains("user_id"), "body must not contain user_id when omitted: $body")
    }

    @Test
    fun `startWebAuthnAuthentication with userId includes user_id in body`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"challenge":"c","rp_id":"x","allow_credentials":[],""" +
                    """"user_verification":"preferred","timeout":60000}"""
                )
                .setResponseCode(200)
        )

        makeClient().startWebAuthnAuthentication(userId = "user-abc")

        val req = server.takeRequest()
        val body = req.body.readUtf8()
        assertTrue(body.contains("user-abc"), "body should contain userId: $body")
    }

    @Test
    fun `startWebAuthnAuthentication returns parsed response`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"challenge":"xyz789","rp_id":"example.com",""" +
                    """"allow_credentials":[{"id":"cred-1","type":"public-key"}],""" +
                    """"user_verification":"required","timeout":30000}"""
                )
                .setResponseCode(200)
        )

        val resp = makeClient().startWebAuthnAuthentication()

        assertEquals("xyz789", resp.challenge)
        assertEquals("example.com", resp.rpId)
        assertEquals(1, resp.allowCredentials.size)
        assertEquals("cred-1", resp.allowCredentials[0].id)
        assertEquals("public-key", resp.allowCredentials[0].type)
        assertEquals("required", resp.userVerification)
        assertEquals(30_000L, resp.timeout)
    }

    // ── Authentication finish ─────────────────────────────────────────────────

    @Test
    fun `finishWebAuthnAuthentication posts to webauthn auth complete`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"access_token":"eyJ...","token_type":"Bearer",""" +
                    """"expires_in":3600,"refresh_token":"ref..."}"""
                )
                .setResponseCode(200)
        )

        makeClient().finishWebAuthnAuthentication(
            WebAuthnAuthenticationCompleteRequest(
                credentialId = "cred-abc",
                clientDataJson = "eyJ...",
                authenticatorData = "SZYN...",
                signature = "abc...",
                origin = "https://example.com",
            ),
        )

        val req = server.takeRequest()
        assertEquals("POST", req.method)
        assertTrue(req.path!!.endsWith("/webauthn/auth/complete"), "path was: ${req.path}")
    }

    @Test
    fun `finishWebAuthnAuthentication returns TokenResponse`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"access_token":"eyJ.access","token_type":"Bearer",""" +
                    """"expires_in":3600,"refresh_token":"eyJ.refresh"}"""
                )
                .setResponseCode(200)
        )

        val resp = makeClient().finishWebAuthnAuthentication(
            WebAuthnAuthenticationCompleteRequest(
                credentialId = "cred-abc",
                clientDataJson = "eyJ...",
                authenticatorData = "SZYN...",
                signature = "abc...",
                origin = "https://example.com",
            ),
        )

        assertEquals("eyJ.access", resp.accessToken)
        assertEquals("Bearer", resp.tokenType)
        assertEquals(3600, resp.expiresIn)
        assertNotNull(resp.refreshToken)
    }

    @Test
    fun `finishWebAuthnAuthentication sends credential fields in body`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(
                    """{"access_token":"t","token_type":"Bearer","expires_in":3600}"""
                )
                .setResponseCode(200)
        )

        makeClient().finishWebAuthnAuthentication(
            WebAuthnAuthenticationCompleteRequest(
                credentialId = "cred-123",
                clientDataJson = "cdj-data",
                authenticatorData = "auth-data",
                signature = "sig-data",
                origin = "https://example.com",
                userHandle = "handle-abc",
            ),
        )

        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("cred-123"), "body should contain credential_id: $body")
        assertTrue(body.contains("cdj-data"), "body should contain client_data_json: $body")
        assertTrue(body.contains("handle-abc"), "body should contain user_handle: $body")
    }
}
