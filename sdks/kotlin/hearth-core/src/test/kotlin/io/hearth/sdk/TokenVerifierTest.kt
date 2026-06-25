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

/**
 * Verifies that [TokenVerifier] correctly handles Ed25519/EdDSA-signed JWTs, which is
 * Hearth's only signing algorithm (SDK.md §2, §7.1).
 *
 * All tests are failing before the EdDSA selector is registered in [TokenVerifier.processJwt] —
 * the composite selector silently returned an empty key list, causing every verification attempt
 * to throw [TokenInvalidError] regardless of token validity.
 */
class TokenVerifierTest {

    private lateinit var server: MockWebServer

    // A fresh Ed25519 key pair per test instance; class is re-instantiated per test by JUnit.
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

    /** JWKS document containing only the public half of [keyPair]. */
    private fun jwksJson(): String = JWKSet(keyPair.toPublicJWK()).toJSONString()

    /**
     * Mints a compact-serialized Ed25519-signed JWT.
     *
     * [ttlMs] controls the `exp` offset from now; pass a negative value for an already-expired token.
     */
    private fun mintJwt(
        subject: String = "user-abc",
        issuer: String = issuer(),
        audience: List<String>? = null,
        ttlMs: Long = 300_000L,
    ): String {
        val now = System.currentTimeMillis()
        val claims = JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .issueTime(Date(now))
            .expirationTime(Date(now + ttlMs))
            .apply { audience?.let { audience(it) } }
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("hearth-ed-1").build()
        val jwt = SignedJWT(header, claims)
        jwt.sign(Ed25519Signer(keyPair))
        return jwt.serialize()
    }

    private fun verifier(audience: String? = null) = TokenVerifier(
        jwksClient = JwksClient(
            jwksUri = server.url("/jwks").toString(),
            httpClient = buildHttpClient(5_000),
        ),
        issuerUrl = issuer(),
        expectedAudience = audience,
    )

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    fun `verify - succeeds for valid Ed25519 signed JWT`() = runTest {
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))

        val claims = verifier().verify(mintJwt())

        assertEquals("user-abc", claims.subject())
        assertEquals(issuer(), claims.issuer())
    }

    @Test
    fun `verify - respects expectedAudience when present in token`() = runTest {
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))

        val token = mintJwt(audience = listOf("my-app"))
        val claims = verifier(audience = "my-app").verify(token)

        assertEquals("user-abc", claims.subject())
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    @Test
    fun `verify - throws TokenExpiredError for expired Ed25519 JWT`() = runTest {
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))

        // Expire 10 s in the past — beyond the 5 s clock-skew allowance.
        val expired = mintJwt(ttlMs = -10_000L)
        assertFailsWith<TokenExpiredError> { verifier().verify(expired) }
    }

    @Test
    fun `verify - throws TokenIssuerError when iss does not match configured issuer`() = runTest {
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))

        val wrongIssuer = mintJwt(issuer = "https://evil.example.com")
        assertFailsWith<TokenIssuerError> { verifier().verify(wrongIssuer) }
    }

    @Test
    fun `verify - throws TokenAudienceError when aud does not contain expectedAudience`() = runTest {
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))

        val token = mintJwt(audience = listOf("wrong-client"))
        assertFailsWith<TokenAudienceError> { verifier(audience = "expected-client").verify(token) }
    }

    @Test
    fun `verify - throws TokenInvalidError for malformed JWT string`() = runTest {
        assertFailsWith<TokenInvalidError> { verifier().verify("not.a.valid.jwt") }
    }

    @Test
    fun `verify - throws TokenInvalidError for tampered Ed25519 signature`() = runTest {
        // First attempt uses cached JWKS; on TokenInvalidError the verifier re-fetches once.
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))

        val token = mintJwt()
        val parts = token.split(".")
        // Corrupt the last character of the signature segment.
        val sig = parts[2]
        val corruptedSig = sig.dropLast(1) + if (sig.last() == 'A') 'B' else 'A'
        val tampered = "${parts[0]}.${parts[1]}.$corruptedSig"

        assertFailsWith<TokenInvalidError> { verifier().verify(tampered) }
    }

    @Test
    fun `verify - throws TokenInvalidError when kid is absent from JWKS (missing OKP key)`() = runTest {
        // The JWKS contains no key with kid "unknown-key". The verifier re-fetches once on kid
        // miss, finds it still absent, and must throw TokenInvalidError (not crash or hang).
        val unknownKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("unknown-key").generate()
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))
        server.enqueue(MockResponse().setBody(jwksJson()).setResponseCode(200))

        val claims = JWTClaimsSet.Builder()
            .subject("attacker")
            .issuer(issuer())
            .issueTime(Date(System.currentTimeMillis()))
            .expirationTime(Date(System.currentTimeMillis() + 300_000L))
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("unknown-key").build()
        val jwt = SignedJWT(header, claims)
        jwt.sign(Ed25519Signer(unknownKey))

        assertFailsWith<TokenInvalidError> { verifier().verify(jwt.serialize()) }
    }

    @Test
    fun `verify - OKP key with no y field is parsed and accepted`() = runTest {
        // Ed25519 JWKS keys must have no y coordinate — parsers must not require it.
        val pub = keyPair.toPublicJWK()
        val okpJson = pub.toJSONObject()
        // Confirm y is absent from the generated JSON (OctetKeyPair never includes y for Ed25519).
        val jwksNoY = """{"keys":[${okpJson}]}"""
        server.enqueue(MockResponse().setBody(jwksNoY).setResponseCode(200))

        val claims = verifier().verify(mintJwt())

        assertEquals("user-abc", claims.subject())
    }
}
