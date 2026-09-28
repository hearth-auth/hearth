package io.hearth.sdk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
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
    fun `RequiredActionError has human-readable message`() {
        val e = RequiredActionError(requiredActions = listOf("VERIFY_EMAIL"))
        assertNotNull(e.message)
        assert(e.message!!.isNotBlank())
    }
}
