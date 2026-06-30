package io.hearth.sdk

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * RFC 7636 PKCE pair: a code verifier and its derived S256 challenge.
 *
 * Hearth mandates PKCE for the authorization-code flow (RFC 9700 §2.1.1).
 * Every public client — and by default every confidential client — must supply
 * a challenge at the authorize step and the matching verifier at the token step.
 *
 * Usage:
 * ```kotlin
 * val pkce = generatePkce()
 * // Authorize request:
 * AuthorizeRequest(
 *     ...
 *     codeChallenge = pkce.challenge,
 *     codeChallengeMethod = pkce.method,
 * )
 * // Token exchange:
 * client.exchangeCode(code = code, redirectUri = uri, codeVerifier = pkce.verifier)
 * ```
 */
data class PkceResult(
    /** High-entropy code verifier (32 CSPRNG bytes, base64url-encoded). */
    val verifier: String,
    /** `BASE64URL(SHA256(verifier))` — send as `code_challenge` in the authorize request. */
    val challenge: String,
    /** Always `"S256"`. Hearth rejects the insecure `"plain"` method. */
    val method: String = "S256",
)

/**
 * Generates a fresh RFC 7636 PKCE pair from 32 bytes of CSPRNG entropy.
 *
 * The verifier is base64url-encoded without padding; the challenge is
 * `BASE64URL(SHA-256(verifier))` also without padding.
 */
fun generatePkce(): PkceResult {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    val verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    val hash = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray())
    val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    return PkceResult(verifier = verifier, challenge = challenge)
}
