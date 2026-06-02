package io.hearth.sdk

import com.nimbusds.jwt.JWTClaimsSet
import java.time.Instant
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ClaimsTest {

    private fun makeClaims(block: JWTClaimsSet.Builder.() -> JWTClaimsSet.Builder): Claims {
        val builder = JWTClaimsSet.Builder()
            .subject("user-123")
            .issuer("https://auth.example.com")
            .audience("my-app")
            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
            .issueTime(Date.from(Instant.now()))
        val claimsSet = builder.block().build()
        return Claims(claimsSet)
    }

    @Test
    fun `subject returns sub claim`() {
        val c = makeClaims { this }
        assertEquals("user-123", c.subject())
    }

    @Test
    fun `issuer returns iss claim`() {
        val c = makeClaims { this }
        assertEquals("https://auth.example.com", c.issuer())
    }

    @Test
    fun `audiences returns aud list`() {
        val c = makeClaims { this }
        assertEquals(listOf("my-app"), c.audiences())
    }

    @Test
    fun `scope and scopes parse correctly`() {
        val c = makeClaims { claim("scope", "read write admin") }
        assertEquals("read write admin", c.scope())
        assertEquals(listOf("read", "write", "admin"), c.scopes())
        assertTrue(c.hasScope("write"))
        assertFalse(c.hasScope("delete"))
    }

    @Test
    fun `hasRole returns true when role present`() {
        val c = makeClaims { claim("roles", listOf("admin", "viewer")) }
        assertTrue(c.hasRole("admin"))
        assertFalse(c.hasRole("superuser"))
    }

    @Test
    fun `hasRole returns false when roles claim absent`() {
        val c = makeClaims { this }
        assertFalse(c.hasRole("admin"))
    }

    @Test
    fun `hasPermission returns true when permission present`() {
        val c = makeClaims { claim("permissions", listOf("user:read", "user:write")) }
        assertTrue(c.hasPermission("user:read"))
        assertFalse(c.hasPermission("user:delete"))
    }

    @Test
    fun `hasPermission returns false when permissions claim absent`() {
        val c = makeClaims { this }
        assertFalse(c.hasPermission("user:read"))
    }

    @Test
    fun `inGroup returns true when group present`() {
        val c = makeClaims { claim("groups", listOf("engineering", "platform")) }
        assertTrue(c.inGroup("engineering"))
        assertFalse(c.inGroup("marketing"))
    }

    @Test
    fun `get returns raw claim value`() {
        val c = makeClaims { claim("custom_field", "custom_value") }
        assertEquals("custom_value", c.get("custom_field"))
    }

    @Test
    fun `get returns null for absent claim`() {
        val c = makeClaims { this }
        assertEquals(null, c.get("nonexistent"))
    }

    @Test
    fun `expiry and issuedAt return instants`() {
        val c = makeClaims { this }
        assertTrue(c.expiry().isAfter(Instant.now()))
        assertTrue(c.issuedAt().isBefore(Instant.now().plusSeconds(1)))
    }

    // ── §4 gaps: inOrg, tokenType, organizationId, orgGroups ──────────────────

    @Test
    fun `inOrg returns true when oid matches`() {
        val c = makeClaims { claim("oid", "org-abc") }
        assertTrue(c.inOrg("org-abc"))
    }

    @Test
    fun `inOrg returns false when oid does not match`() {
        val c = makeClaims { claim("oid", "org-abc") }
        assertFalse(c.inOrg("org-xyz"))
    }

    @Test
    fun `inOrg returns false when oid claim absent`() {
        val c = makeClaims { this }
        assertFalse(c.inOrg("org-abc"))
    }

    @Test
    fun `organizationId returns oid claim value`() {
        val c = makeClaims { claim("oid", "org-abc") }
        assertEquals("org-abc", c.organizationId())
    }

    @Test
    fun `organizationId returns null when oid absent`() {
        val c = makeClaims { this }
        assertEquals(null, c.organizationId())
    }

    @Test
    fun `tokenType returns token_type claim`() {
        val c = makeClaims { claim("token_type", "access") }
        assertEquals("access", c.tokenType())
    }

    @Test
    fun `tokenType returns empty string when claim absent`() {
        val c = makeClaims { this }
        assertEquals("", c.tokenType())
    }

    @Test
    fun `tokenType returns required_action when token is a required-action token`() {
        val c = makeClaims { claim("token_type", "required_action") }
        assertEquals("required_action", c.tokenType())
    }

    @Test
    fun `orgGroups returns org_groups claim list`() {
        val c = makeClaims { claim("org_groups", listOf("/org-slug/eng", "/org-slug/platform")) }
        assertEquals(listOf("/org-slug/eng", "/org-slug/platform"), c.orgGroups())
    }

    @Test
    fun `orgGroups returns empty list when claim absent`() {
        val c = makeClaims { this }
        assertEquals(emptyList<String>(), c.orgGroups())
    }
}
