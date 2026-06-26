package io.hearth.sdk.spring

import io.hearth.sdk.Claims
import io.hearth.sdk.HearthClient
import io.hearth.sdk.TokenInvalidError
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class HearthJwtAuthenticationFilterTest {

    private val client = mockk<HearthClient>()
    private val filter = HearthJwtAuthenticationFilter(client)

    @BeforeTest
    fun clearContext() {
        SecurityContextHolder.clearContext()
    }

    @AfterTest
    fun afterEach() {
        SecurityContextHolder.clearContext()
    }

    // ── No token ────────────────────────────────────────────────────────────────

    @Test
    fun `passes through when Authorization header is absent`() {
        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()
        val chain = mockk<FilterChain>(relaxed = true)

        filter.doFilter(request, response, chain)

        verify(exactly = 1) { chain.doFilter(request, response) }
        assertEquals(HttpStatus.OK.value(), response.status)
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    @Test
    fun `passes through when Authorization header has no Bearer prefix`() {
        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Basic dXNlcjpwYXNz")
        }
        val response = MockHttpServletResponse()
        val chain = mockk<FilterChain>(relaxed = true)

        filter.doFilter(request, response, chain)

        verify(exactly = 1) { chain.doFilter(request, response) }
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    @Test
    fun `passes through when Bearer token is blank`() {
        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Bearer   ")
        }
        val response = MockHttpServletResponse()
        val chain = mockk<FilterChain>(relaxed = true)

        filter.doFilter(request, response, chain)

        verify(exactly = 1) { chain.doFilter(request, response) }
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    // ── Valid token ─────────────────────────────────────────────────────────────

    @Test
    fun `populates SecurityContext with HearthAuthentication on valid token`() {
        val token = "header.payload.sig"
        val claims = mockk<Claims> {
            every { roles() } returns listOf("admin")
            every { permissions() } returns listOf("docs.write")
            every { subject() } returns "user-123"
        }
        coEvery { client.verifyToken(token) } returns claims

        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Bearer $token")
        }
        val response = MockHttpServletResponse()
        val chain = mockk<FilterChain>(relaxed = true)

        filter.doFilter(request, response, chain)

        val auth = SecurityContextHolder.getContext().authentication
        assertIs<HearthAuthentication>(auth)
        assertEquals(claims, auth.claims)
        assertEquals(HttpStatus.OK.value(), response.status)
        verify(exactly = 1) { chain.doFilter(request, response) }
    }

    @Test
    fun `granted authorities include ROLE_ prefixed roles and raw permissions`() {
        val token = "a.b.c"
        val claims = mockk<Claims> {
            every { roles() } returns listOf("admin", "editor")
            every { permissions() } returns listOf("docs.write", "users.read")
            every { subject() } returns "u1"
        }
        coEvery { client.verifyToken(token) } returns claims

        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Bearer $token")
        }
        filter.doFilter(request, MockHttpServletResponse(), mockk(relaxed = true))

        val auth = SecurityContextHolder.getContext().authentication as HearthAuthentication
        val authorityNames = auth.authorities.map { it.authority }.toSet()
        assertEquals(
            setOf("ROLE_admin", "ROLE_editor", "docs.write", "users.read"),
            authorityNames,
        )
    }

    @Test
    fun `getPrincipal returns the HearthAuthentication itself`() {
        val token = "x.y.z"
        val claims = mockk<Claims> {
            every { roles() } returns emptyList()
            every { permissions() } returns emptyList()
            every { subject() } returns "sub"
        }
        coEvery { client.verifyToken(token) } returns claims

        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Bearer $token")
        }
        filter.doFilter(request, MockHttpServletResponse(), mockk(relaxed = true))

        val auth = SecurityContextHolder.getContext().authentication as HearthAuthentication
        assertIs<HearthAuthentication>(auth.principal)
    }

    // ── Invalid / expired token ─────────────────────────────────────────────────

    @Test
    fun `returns HTTP 401 and clears context when token is invalid`() {
        val token = "bad.jwt.token"
        coEvery { client.verifyToken(token) } throws TokenInvalidError("bad signature")

        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Bearer $token")
        }
        val response = MockHttpServletResponse()
        val chain = mockk<FilterChain>(relaxed = true)

        filter.doFilter(request, response, chain)

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.status)
        assertNull(SecurityContextHolder.getContext().authentication)
        coVerify(exactly = 1) { client.verifyToken(token) }
        verify(exactly = 0) { chain.doFilter(any(), any()) }
    }

    @Test
    fun `returns HTTP 401 on arbitrary exception from verifyToken`() {
        coEvery { client.verifyToken(any()) } throws RuntimeException("network error")

        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Bearer some.token.here")
        }
        val response = MockHttpServletResponse()

        filter.doFilter(request, response, mockk(relaxed = true))

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.status)
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    // ── Token extraction ────────────────────────────────────────────────────────

    @Test
    fun `strips leading and trailing whitespace from token`() {
        val token = "clean.token.value"
        val claims = mockk<Claims> {
            every { roles() } returns emptyList()
            every { permissions() } returns emptyList()
            every { subject() } returns "u"
        }
        coEvery { client.verifyToken(token) } returns claims

        val request = MockHttpServletRequest().also {
            it.addHeader("Authorization", "Bearer  $token  ")
        }
        filter.doFilter(request, MockHttpServletResponse(), mockk(relaxed = true))

        coVerify(exactly = 1) { client.verifyToken(token) }
    }
}
