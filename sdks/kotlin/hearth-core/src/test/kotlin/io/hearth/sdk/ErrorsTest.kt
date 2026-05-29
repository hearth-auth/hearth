package io.hearth.sdk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertIs

class ErrorsTest {

    @Test
    fun `RequiredActionError is a HearthException`() {
        val e = RequiredActionError(requiredActions = listOf("VERIFY_EMAIL"))
        assertIs<HearthException>(e)
    }

    @Test
    fun `RequiredActionError exposes requiredActions`() {
        val actions = listOf("VERIFY_EMAIL", "UPDATE_PASSWORD")
        val e = RequiredActionError(requiredActions = actions)
        assertEquals(actions, e.requiredActions)
    }

    @Test
    fun `RequiredActionError redirectUri is null by default`() {
        val e = RequiredActionError(requiredActions = listOf("VERIFY_EMAIL"))
        assertNull(e.redirectUri)
    }

    @Test
    fun `RequiredActionError accepts optional redirectUri`() {
        val uri = "https://auth.example.com/ui/required-actions/VERIFY_EMAIL"
        val e = RequiredActionError(requiredActions = listOf("VERIFY_EMAIL"), redirectUri = uri)
        assertEquals(uri, e.redirectUri)
    }

    @Test
    fun `RequiredActionError has human-readable message`() {
        val e = RequiredActionError(requiredActions = listOf("VERIFY_EMAIL"))
        assertNotNull(e.message)
        assert(e.message!!.isNotBlank())
    }
}
