package io.hearth.sdk

import com.nimbusds.jwt.JWTClaimsSet
import java.time.Instant

/**
 * Typed access to JWT claims from a verified token (SDK.md §4).
 *
 * All standard claims are exposed as typed properties.
 * Custom claims are available via [get].
 */
class Claims(private val claimsSet: JWTClaimsSet) {

    /** `sub` — subject identifier. */
    fun subject(): String = claimsSet.subject ?: ""

    /** `iss` — token issuer. */
    fun issuer(): String = claimsSet.issuer ?: ""

    /** `aud` — intended audiences. */
    fun audiences(): List<String> = claimsSet.audience ?: emptyList()

    /** `exp` — expiration time. */
    fun expiry(): Instant = Instant.ofEpochMilli(claimsSet.expirationTime?.time ?: 0)

    /** `iat` — issued-at time. */
    fun issuedAt(): Instant = Instant.ofEpochMilli(claimsSet.issueTime?.time ?: 0)

    /** `jti` — JWT ID (may be empty). */
    fun jwtID(): String = claimsSet.jwtid ?: ""

    /**
     * `scope` — space-delimited scope string.
     *
     * Hearth stores scope as a string claim; falls back to empty string if absent.
     */
    fun scope(): String = claimsSet.getStringClaim("scope") ?: ""

    /** Parsed list of scope strings from [scope]. */
    fun scopes(): List<String> =
        scope().split(" ").filter { it.isNotBlank() }

    /** Returns true iff [scope] contains [s]. */
    fun hasScope(s: String): Boolean = scopes().contains(s)

    /**
     * Returns true iff the Hearth `roles` claim contains [role].
     *
     * Returns false when the claim is absent — never throws (sdk-spec §4).
     */
    fun hasRole(role: String): Boolean {
        val roles = claimsSet.getStringListClaim("roles") ?: return false
        return roles.contains(role)
    }

    /**
     * Returns true iff the Hearth `permissions` claim contains [permission].
     *
     * Returns false when the claim is absent — never throws (sdk-spec §4).
     */
    fun hasPermission(permission: String): Boolean {
        val perms = claimsSet.getStringListClaim("permissions") ?: return false
        return perms.contains(permission)
    }

    /**
     * Returns the raw claim value for [claim], or null if absent.
     *
     * Returns the nimbus-parsed type (String, Long, Date, List, Map, etc.).
     */
    fun get(claim: String): Any? = claimsSet.getClaim(claim)

    /** All Hearth `roles` from the token, or empty list if absent. */
    fun roles(): List<String> = claimsSet.getStringListClaim("roles") ?: emptyList()

    /** All Hearth `permissions` from the token, or empty list if absent. */
    fun permissions(): List<String> =
        claimsSet.getStringListClaim("permissions") ?: emptyList()

    /** All Hearth `groups` from the token, or empty list if absent. */
    fun groups(): List<String> =
        claimsSet.getStringListClaim("groups") ?: emptyList()

    /** Returns true iff the token's `groups` claim contains [groupSlug]. */
    fun inGroup(groupSlug: String): Boolean = groups().contains(groupSlug)

    /**
     * Returns true iff the `oid` claim exactly matches [orgId].
     *
     * Returns false when the claim is absent — never throws (sdk-spec §4).
     */
    fun inOrg(orgId: String): Boolean = claimsSet.getStringClaim("oid") == orgId

    /** `oid` — organization ID the token was issued for, or null if absent. */
    fun organizationId(): String? = claimsSet.getStringClaim("oid")

    /**
     * `token_type` — token purpose: `"access"`, `"refresh"`, or `"required_action"`.
     *
     * Returns empty string when the claim is absent (sdk-spec §4).
     */
    fun tokenType(): String = claimsSet.getStringClaim("token_type") ?: ""

    /**
     * `org_groups` — group paths scoped to the organization (Keycloak-style paths,
     * e.g. `/org-slug/group`). Returns empty list when the claim is absent (sdk-spec §4).
     */
    fun orgGroups(): List<String> =
        claimsSet.getStringListClaim("org_groups") ?: emptyList()

    override fun toString(): String =
        "Claims(sub=${subject()}, iss=${issuer()}, exp=${expiry()})"
}
