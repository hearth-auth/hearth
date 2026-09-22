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
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The EMBEDDED permission checker reads the `permissions` claim to decide whether a
 * request proceeds. Reading that claim out of an unverified JWT would let an
 * unauthenticated attacker mint a token carrying `permissions: ["admin.write"]` and be
 * admitted, so the gate is exercised against exactly that forgery as well as against a
 * properly signed token.
 */
class MiddlewareVerificationTest {

    private lateinit var server: MockWebServer

    private val keyPair: OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519)
        .keyID("hearth-ed-1")
        .generate()

    @BeforeTest
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterTest
    fun tearDown() {
        server.shutdown()
    }

    private fun issuer(): String = server.url("/").toString().trimEnd('/')

    /** Serve the discovery document and the JWKS for every request the SDK makes. */
    private fun enqueueIssuerResponses(count: Int = 4) {
        repeat(count) {
            server.enqueue(
                MockResponse()
                    .setBody(
                        """{"issuer":"${issuer()}","jwks_uri":"${issuer()}/jwks"}""",
                    )
                    .setResponseCode(200),
            )
            server.enqueue(
                MockResponse().setBody(JWKSet(keyPair.toPublicJWK()).toString()).setResponseCode(200),
            )
        }
    }

    /** A properly signed token carrying the given permissions. */
    private fun signedToken(
        permissions: List<String>,
        signingKey: OctetKeyPair = keyPair,
    ): String {
        val now = System.currentTimeMillis()
        val claims = JWTClaimsSet.Builder()
            .subject("user-abc")
            .issuer(issuer())
            .issueTime(Date(now))
            .expirationTime(Date(now + 300_000L))
            .claim("permissions", permissions)
            .build()
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("hearth-ed-1").build(),
            claims,
        )
        jwt.sign(Ed25519Signer(signingKey))
        return jwt.serialize()
    }

    /** A well-formed token with a garbage signature — the attacker's forgery. */
    private fun forgedToken(permissions: List<String>): String {
        val enc = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = enc.encodeToString("""{"alg":"EdDSA","kid":"hearth-ed-1"}""".toByteArray())
        val perms = permissions.joinToString(",") { "\"$it\"" }
        val body = enc.encodeToString(
            """{"sub":"attacker","iss":"${issuer()}","permissions":[$perms]}""".toByteArray(),
        )
        return "$header.$body.AAAA"
    }

    private fun client() = HearthClient(
        issuerUrl = issuer(),
        realmId = "realm-1",
    )

    private fun checker(permission: String) = requirePermission(
        permission,
        RequirePermissionOptions(
            mode = AccessTokenAuthorizationMode.EMBEDDED,
            client = client(),
        ),
    )

    @Test
    fun `embedded - refuses a forged token that claims the permission`() = runTest {
        enqueueIssuerResponses()
        assertFalse(
            checker("admin.write").check(forgedToken(listOf("admin.write"))),
            "EMBEDDED checker admitted a token with an invalid signature",
        )
    }

    @Test
    fun `embedded - refuses a token signed by a key outside the JWKS`() = runTest {
        enqueueIssuerResponses()
        val foreignKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("hearth-ed-1").generate()
        assertFalse(
            checker("admin.write").check(signedToken(listOf("admin.write"), foreignKey)),
            "EMBEDDED checker admitted a token signed by a key outside the JWKS",
        )
    }

    @Test
    fun `embedded - admits a properly signed token carrying the permission`() = runTest {
        enqueueIssuerResponses()
        assertTrue(checker("admin.write").check(signedToken(listOf("admin.write"))))
    }

    @Test
    fun `embedded - denies a properly signed token lacking the permission`() = runTest {
        enqueueIssuerResponses()
        assertFalse(checker("admin.write").check(signedToken(listOf("docs.read"))))
    }
}
