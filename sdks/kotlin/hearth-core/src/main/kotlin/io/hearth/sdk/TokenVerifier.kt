package io.hearth.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.ParseException

/** Allowed clock skew for `exp` and `iat` validation per sdk-spec §2. */
private const val CLOCK_SKEW_SECONDS = 5

/**
 * JWT signature verifier backed by a [JwksClient].
 *
 * Implements the mandatory validation order from SDK.md §2:
 * 1. Signature against JWKS (EdDSA/Ed25519 — Hearth's primary algorithm; RS256/ES256 for federation)
 * 2. `exp` claim
 * 3. `iss` matches configured issuer
 * 4. `aud` contains configured client_id (optional — server SDK mode)
 * 5. `iat` not in the future (±5s clock skew)
 *
 * Tokens and secrets never appear in thrown error messages.
 */
class TokenVerifier(
    private val jwksClient: JwksClient,
    private val issuerUrl: String,
    /** When set, `aud` must contain this value. Omit for pure server-side verification. */
    private val expectedAudience: String? = null,
) {
    /**
     * Verifies [token] and returns the decoded [Claims] on success.
     *
     * On kid-cache miss, re-fetches JWKS once before failing (sdk-spec §2.2 rule 3).
     *
     * @throws TokenInvalidError   on bad signature, malformed JWT, or unsupported algorithm
     * @throws TokenExpiredError   when `exp` is in the past
     * @throws TokenIssuerError    when `iss` does not match [issuerUrl]
     * @throws TokenAudienceError  when `aud` does not contain [expectedAudience]
     * @throws JWKSFetchError      when the JWKS endpoint is unreachable
     */
    suspend fun verify(token: String): Claims = withContext(Dispatchers.IO) {
        val jwt = try {
            SignedJWT.parse(token)
        } catch (e: ParseException) {
            throw TokenInvalidError("Malformed JWT — could not parse token structure")
        }

        // First attempt with the cached key set.
        try {
            return@withContext processJwt(jwt, jwksClient.getOrFetchSet())
        } catch (e: ClaimsError) {
            // Signature was verified but claims are invalid — re-fetch won't help; propagate now.
            throw e.typed
        } catch (e: HearthException) {
            // Re-throw all typed errors immediately — they aren't key-miss errors.
            if (e !is TokenInvalidError) throw e
        }

        // kid not found or signature mismatch — re-fetch once per sdk-spec §2.2 rule 3.
        val freshSet = try {
            jwksClient.invalidateAndRefetch()
        } catch (fetchErr: JWKSFetchError) {
            throw fetchErr
        }

        try {
            processJwt(jwt, freshSet)
        } catch (e: ClaimsError) {
            throw e.typed
        }
    }

    private fun processJwt(jwt: SignedJWT, keySet: JWKSet): Claims =
        when (jwt.header.algorithm) {
            JWSAlgorithm.EdDSA -> processEdDSA(jwt, keySet)
            else -> processFederation(jwt, keySet)
        }

    /**
     * EdDSA verification via [Ed25519Verifier] operating directly on [OctetKeyPair] from the JWKS.
     *
     * We intentionally bypass [JWSVerificationKeySelector] here: that path converts OctetKeyPair
     * to a [java.security.PublicKey] whose round-trip through [java.security.spec.EdECPoint]
     * corrupts the public-key bytes on some JVM/provider combinations, causing valid signatures
     * to fail. Using [Ed25519Verifier] with the OctetKeyPair directly avoids that conversion.
     *
     * Claims errors are wrapped in [ClaimsError] so the caller's re-fetch logic cannot mistake
     * them for "key not found" and trigger an unnecessary JWKS re-fetch.
     */
    private fun processEdDSA(jwt: SignedJWT, keySet: JWKSet): Claims {
        val kid = jwt.header.keyID
        val matcher = JWKMatcher.Builder()
            .keyType(KeyType.OKP)
            .curve(Curve.Ed25519)
            .apply { if (kid != null) keyID(kid) }
            .build()
        val candidates = JWKSelector(matcher).select(keySet)

        for (jwk in candidates) {
            val okp = (jwk as? OctetKeyPair)?.toPublicJWK() ?: continue
            try {
                val verifier = Ed25519Verifier(okp)
                if (!jwt.verify(verifier)) continue
            } catch (e: com.nimbusds.jose.JOSEException) {
                continue  // This key couldn't be used; try the next one.
            }
            // Signature is valid — verify claims, wrapping errors to prevent spurious JWKS re-fetch.
            return try {
                verifyClaims(jwt.jwtClaimsSet)
            } catch (e: HearthException) {
                throw ClaimsError(e)
            }
        }

        throw TokenInvalidError("JWT signature verification failed")
    }

    /**
     * RS256/ES256 verification for federation tokens via [DefaultJWTProcessor].
     *
     * These algorithms never appear on Hearth-issued tokens (SDK.md §2); this path
     * only applies when relaying third-party IdP tokens.
     */
    private fun processFederation(jwt: SignedJWT, keySet: JWKSet): Claims {
        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            val source = ImmutableJWKSet<SecurityContext>(keySet)
            val rsaSelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, source)
            val ecSelector  = JWSVerificationKeySelector(JWSAlgorithm.ES256, source)
            jwsKeySelector = CompositeKeySelector(rsaSelector, ecSelector)
            jwtClaimsSetVerifier = buildClaimsVerifier()
        }

        return try {
            Claims(processor.process(jwt, null))
        } catch (e: BadJWTException) {
            mapBadJwtException(e)
        } catch (e: com.nimbusds.jose.JOSEException) {
            throw TokenInvalidError("JWT signature verification failed")
        } catch (e: Exception) {
            val msg = e.message ?: ""
            when {
                msg.contains("expired", ignoreCase = true) ->
                    throw TokenExpiredError("Token has expired")
                msg.contains("issuer", ignoreCase = true) || msg.contains("iss claim", ignoreCase = true) ->
                    throw TokenIssuerError("Token issuer does not match configured issuer")
                msg.contains("audience", ignoreCase = true) ->
                    throw TokenAudienceError("Token audience does not include expected client_id")
                else -> throw TokenInvalidError("JWT verification failed")
            }
        }
    }

    /**
     * Verifies JWT claims after the signature has already been confirmed.
     *
     * Includes an explicit `iat`-in-the-future check because [DefaultJWTClaimsVerifier]
     * only verifies that `iat` is present, not that it is not ahead of the current time.
     */
    private fun verifyClaims(claimsSet: JWTClaimsSet): Claims {
        try {
            buildClaimsVerifier().verify(claimsSet, null)
        } catch (e: BadJWTException) {
            mapBadJwtException(e)
        }

        // DefaultJWTClaimsVerifier checks iat is present but not that it's in the past.
        val iatMs = claimsSet.issueTime?.time
        if (iatMs != null && iatMs > System.currentTimeMillis() + CLOCK_SKEW_SECONDS * 1000L) {
            throw TokenNotYetValidError("Token issued-at is in the future beyond clock skew")
        }

        return Claims(claimsSet)
    }

    private fun buildClaimsVerifier(): DefaultJWTClaimsVerifier<SecurityContext> {
        val exactMatchClaims = JWTClaimsSet.Builder()
            .issuer(issuerUrl)
            .build()
        val requiredClaims = mutableSetOf("sub", "exp", "iat", "iss")
        return DefaultJWTClaimsVerifier<SecurityContext>(
            expectedAudience?.let { setOf(it) },
            exactMatchClaims,
            requiredClaims,
            null,
        ).apply {
            maxClockSkew = CLOCK_SKEW_SECONDS
        }
    }

    private fun mapBadJwtException(e: BadJWTException): Nothing {
        val msg = e.message ?: ""
        when {
            msg.contains("expired", ignoreCase = true) ->
                throw TokenExpiredError("Token has expired")
            // nimbus emits "JWT iss claim has value X, must be Y" — no "issuer" keyword
            msg.contains("issuer", ignoreCase = true) || msg.contains("iss claim", ignoreCase = true) ->
                throw TokenIssuerError("Token issuer does not match configured issuer")
            msg.contains("audience", ignoreCase = true) ->
                throw TokenAudienceError("Token audience does not include expected client_id")
            else -> throw TokenInvalidError("JWT claims verification failed")
        }
    }
}

/**
 * Wraps a [HearthException] thrown during claims verification (after a valid EdDSA signature)
 * so that [TokenVerifier.verify] does not mistake a claims failure for a JWKS key-miss and
 * trigger a spurious JWKS re-fetch.
 */
private class ClaimsError(val typed: HearthException) : Exception()

/**
 * Tries each [JWSKeySelector] in order; returns keys from the first whose algorithm matches the
 * JWS header. Used only for RS256/ES256 federation fallbacks — EdDSA is handled separately.
 */
private class CompositeKeySelector(
    private vararg val selectors: JWSKeySelector<SecurityContext>,
) : JWSKeySelector<SecurityContext> {
    override fun selectJWSKeys(
        header: com.nimbusds.jose.JWSHeader,
        ctx: SecurityContext?,
    ): List<java.security.Key> {
        for (sel in selectors) {
            try {
                val keys = sel.selectJWSKeys(header, ctx)
                if (keys.isNotEmpty()) return keys
            } catch (_: Exception) {
                // Try next selector
            }
        }
        return emptyList()
    }
}
