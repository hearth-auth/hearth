package io.hearth.sdk.spring

import io.hearth.sdk.Claims
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority

/**
 * Spring Security [org.springframework.security.core.Authentication] token backed by a verified
 * Hearth JWT.
 *
 * Populated by [HearthJwtAuthenticationFilter] after signature verification.
 * Retrieve it in controllers with:
 *
 * ```kotlin
 * @GetMapping("/me")
 * fun me(@AuthenticationPrincipal auth: HearthAuthentication): ResponseEntity<Map<String, String>> =
 *     ResponseEntity.ok(mapOf("sub" to auth.claims.subject()))
 * ```
 *
 * Or via [org.springframework.security.core.context.SecurityContextHolder]:
 * ```kotlin
 * val auth = SecurityContextHolder.getContext().authentication as HearthAuthentication
 * ```
 *
 * Granted authorities are derived from the JWT claims:
 * - Each role in [Claims.roles] maps to `ROLE_<role>` (e.g. `ROLE_admin`).
 * - Each permission in [Claims.permissions] is granted verbatim (e.g. `docs.write`).
 */
class HearthAuthentication(
    /** The raw bearer token string as received in the Authorization header. */
    private val rawToken: String,
    /** Verified and decoded JWT claims from [io.hearth.sdk.HearthClient.verifyToken]. */
    val claims: Claims,
) : AbstractAuthenticationToken(buildAuthorities(claims)) {

    init {
        isAuthenticated = true
    }

    /** Returns this [HearthAuthentication] as the principal, enabling `@AuthenticationPrincipal`. */
    override fun getPrincipal(): HearthAuthentication = this

    /** Returns the raw bearer token string as the credential. */
    override fun getCredentials(): String = rawToken
}

private fun buildAuthorities(claims: Claims) =
    claims.roles().map { SimpleGrantedAuthority("ROLE_$it") } +
        claims.permissions().map { SimpleGrantedAuthority(it) }
