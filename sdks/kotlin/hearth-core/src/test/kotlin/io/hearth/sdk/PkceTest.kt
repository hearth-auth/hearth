package io.hearth.sdk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PkceTest {

    @Test
    fun `generatePkce returns verifier of at least 43 characters`() {
        val pair = generatePkce()
        // 32 bytes → base64url without padding = 43 chars
        assertTrue(pair.verifier.length >= 43, "verifier length was ${pair.verifier.length}")
    }

    @Test
    fun `generatePkce challenge is SHA-256 of verifier base64url-encoded without padding`() {
        val pair = generatePkce()
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(pair.verifier.toByteArray())
        val expected = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
        assertEquals(expected, pair.challenge)
    }

    @Test
    fun `generatePkce method is always S256`() {
        val pair = generatePkce()
        assertEquals("S256", pair.method)
    }

    @Test
    fun `generatePkce returns different pairs on each call`() {
        val pair1 = generatePkce()
        val pair2 = generatePkce()
        assertNotEquals(pair1.verifier, pair2.verifier)
        assertNotEquals(pair1.challenge, pair2.challenge)
    }

    @Test
    fun `generatePkce verifier contains only base64url characters without padding`() {
        val pair = generatePkce()
        assertTrue(
            pair.verifier.all { it.isLetterOrDigit() || it == '-' || it == '_' },
            "verifier contained invalid chars: ${pair.verifier}"
        )
        assertTrue(!pair.verifier.contains('='), "verifier must not be padded")
    }

    @Test
    fun `generatePkce challenge contains only base64url characters without padding`() {
        val pair = generatePkce()
        assertTrue(
            pair.challenge.all { it.isLetterOrDigit() || it == '-' || it == '_' },
            "challenge contained invalid chars: ${pair.challenge}"
        )
        assertTrue(!pair.challenge.contains('='), "challenge must not be padded")
    }
}
