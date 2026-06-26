package io.hearth.sdk.ktor

import io.hearth.sdk.Claims
import io.hearth.sdk.HearthClient
import io.hearth.sdk.TokenExpiredError
import io.hearth.sdk.TokenInvalidError
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Unit tests for [HearthAuthProvider] — plugin installation and principal extraction.
 *
 * Each test uses [testApplication] with a mocked [HearthClient]; no real Hearth server required.
 */
class HearthAuthPluginTest {

    // ── HearthPrincipal ──────────────────────────────────────────────────────

    @Test
    fun `HearthPrincipal holds rawToken and claims`() {
        val claims = mockk<Claims> {
            every { subject() } returns "u1"
        }
        val principal = HearthPrincipal(rawToken = "tok.en.here", claims = claims)
        assertEquals("tok.en.here", principal.rawToken)
        assertEquals("u1", principal.claims.subject())
    }

    // ── No token ─────────────────────────────────────────────────────────────

    @Test
    fun `returns 401 when Authorization header is absent`() = testApplication {
        install(Authentication) { hearth("h") { client = noOpClient() } }
        routing {
            authenticate("h") { get("/p") { call.respondText("ok") } }
        }
        val resp = client.get("/p")
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `returns 401 when Authorization scheme is not Bearer`() = testApplication {
        install(Authentication) { hearth("h") { client = noOpClient() } }
        routing {
            authenticate("h") { get("/p") { call.respondText("ok") } }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Basic dXNlcjpwYXNz") }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `returns 401 when Bearer token is blank`() = testApplication {
        install(Authentication) { hearth("h") { client = noOpClient() } }
        routing {
            authenticate("h") { get("/p") { call.respondText("ok") } }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Bearer   ") }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    // ── Valid token ──────────────────────────────────────────────────────────

    @Test
    fun `sets HearthPrincipal on valid bearer token`() = testApplication {
        val mockClient = validTokenClient("valid.jwt", subject = "user-abc")
        install(Authentication) { hearth("h") { client = mockClient } }
        routing {
            authenticate("h") {
                get("/p") {
                    val p = call.principal<HearthPrincipal>()!!
                    call.respondText(p.claims.subject())
                }
            }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Bearer valid.jwt") }
        assertEquals(HttpStatusCode.OK, resp.status)
        assertEquals("user-abc", resp.bodyAsText())
    }

    @Test
    fun `rawToken on principal matches the submitted bearer token`() = testApplication {
        val mockClient = validTokenClient("tok.en.sig", subject = "u2")
        install(Authentication) { hearth("h") { client = mockClient } }
        routing {
            authenticate("h") {
                get("/p") {
                    val p = call.principal<HearthPrincipal>()!!
                    call.respondText(p.rawToken)
                }
            }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Bearer tok.en.sig") }
        assertEquals("tok.en.sig", resp.bodyAsText())
    }

    @Test
    fun `principal exposes roles from claims`() = testApplication {
        val mockClient = mockk<HearthClient>()
        val claims = mockk<Claims> {
            every { subject() } returns "u3"
            every { roles() } returns listOf("admin", "editor")
            every { permissions() } returns listOf("docs.write")
        }
        coEvery { mockClient.verifyToken("tok") } returns claims
        install(Authentication) { hearth("h") { client = mockClient } }
        routing {
            authenticate("h") {
                get("/p") {
                    val p = call.principal<HearthPrincipal>()!!
                    call.respondText(p.claims.roles().joinToString(","))
                }
            }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Bearer tok") }
        assertEquals("admin,editor", resp.bodyAsText())
    }

    // ── Invalid / expired token ──────────────────────────────────────────────

    @Test
    fun `returns 401 when token signature is invalid`() = testApplication {
        val mockClient = mockk<HearthClient>()
        coEvery { mockClient.verifyToken(any()) } throws TokenInvalidError("bad signature")
        install(Authentication) { hearth("h") { client = mockClient } }
        routing {
            authenticate("h") { get("/p") { call.respondText("ok") } }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Bearer bad.jwt.sig") }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `returns 401 when token is expired`() = testApplication {
        val mockClient = mockk<HearthClient>()
        coEvery { mockClient.verifyToken(any()) } throws TokenExpiredError("expired")
        install(Authentication) { hearth("h") { client = mockClient } }
        routing {
            authenticate("h") { get("/p") { call.respondText("ok") } }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Bearer expired.jwt") }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `returns 401 on unexpected exception from verifyToken`() = testApplication {
        val mockClient = mockk<HearthClient>()
        coEvery { mockClient.verifyToken(any()) } throws RuntimeException("network error")
        install(Authentication) { hearth("h") { client = mockClient } }
        routing {
            authenticate("h") { get("/p") { call.respondText("ok") } }
        }
        val resp = client.get("/p") { header(HttpHeaders.Authorization, "Bearer some.token") }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    // ── Multiple providers ───────────────────────────────────────────────────

    @Test
    fun `two hearth providers with different names can coexist`() = testApplication {
        val client1 = validTokenClient("tok1", subject = "user-1")
        val client2 = validTokenClient("tok2", subject = "user-2")
        install(Authentication) {
            hearth("api") { client = client1 }
            hearth("admin") { client = client2 }
        }
        routing {
            authenticate("api") {
                get("/api") {
                    call.respondText(call.principal<HearthPrincipal>()!!.claims.subject())
                }
            }
            authenticate("admin") {
                get("/admin") {
                    call.respondText(call.principal<HearthPrincipal>()!!.claims.subject())
                }
            }
        }
        val r1 = client.get("/api") { header(HttpHeaders.Authorization, "Bearer tok1") }
        val r2 = client.get("/admin") { header(HttpHeaders.Authorization, "Bearer tok2") }
        assertEquals("user-1", r1.bodyAsText())
        assertEquals("user-2", r2.bodyAsText())
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** A [HearthClient] mock that always throws for any token (simulates missing configuration). */
    private fun noOpClient(): HearthClient = mockk<HearthClient>().also {
        coEvery { it.verifyToken(any()) } throws TokenInvalidError("no-op")
    }

    /** A [HearthClient] mock that returns a valid [Claims] for [token]. */
    private fun validTokenClient(token: String, subject: String): HearthClient {
        val claims = mockk<Claims> {
            every { this@mockk.subject() } returns subject
            every { roles() } returns emptyList()
            every { permissions() } returns emptyList()
        }
        return mockk<HearthClient>().also { c ->
            coEvery { c.verifyToken(token) } returns claims
        }
    }
}
