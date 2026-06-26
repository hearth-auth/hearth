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
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Integration test: end-to-end Ktor + Hearth JWT authentication via route-level [authenticate].
 *
 * Uses [testApplication] with a mocked [HearthClient] — no real Hearth server required.
 */
class HearthKtorIntegrationTest {

    private lateinit var mockHearthClient: HearthClient
    private lateinit var validClaims: Claims

    companion object {
        private const val VALID_TOKEN = "header.payload.sig"
        private const val EXPIRED_TOKEN = "header.payload.expired"
        private const val INVALID_TOKEN = "header.payload.invalid"
    }

    @BeforeTest
    fun setUp() {
        validClaims = mockk {
            every { subject() } returns "user-abc"
            every { roles() } returns listOf("reader")
            every { permissions() } returns listOf("docs.read")
            every { groups() } returns listOf("team-a")
            every { hasPermission("docs.read") } returns true
            every { hasPermission("docs.write") } returns false
            every { hasRole("reader") } returns true
            every { hasRole("admin") } returns false
        }
        mockHearthClient = mockk {
            coEvery { verifyToken(VALID_TOKEN) } returns validClaims
            coEvery { verifyToken(EXPIRED_TOKEN) } throws TokenExpiredError("token expired")
            coEvery { verifyToken(INVALID_TOKEN) } throws TokenInvalidError("bad signature")
        }
    }

    // ── Public endpoint ──────────────────────────────────────────────────────

    @Test
    fun `public endpoint is accessible without a token`() = testApplication {
        withHearthApp()
        val resp = client.get("/public/ping")
        assertEquals(HttpStatusCode.OK, resp.status)
        assertEquals("pong", resp.bodyAsText())
    }

    // ── Protected endpoint — valid token ─────────────────────────────────────

    @Test
    fun `protected endpoint returns 200 with a valid Hearth JWT`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/me") {
            header(HttpHeaders.Authorization, "Bearer $VALID_TOKEN")
        }
        assertEquals(HttpStatusCode.OK, resp.status)
    }

    @Test
    fun `protected endpoint returns subject from claims`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/me") {
            header(HttpHeaders.Authorization, "Bearer $VALID_TOKEN")
        }
        assertEquals("user-abc", resp.bodyAsText())
    }

    @Test
    fun `protected endpoint principal contains roles from token`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/roles") {
            header(HttpHeaders.Authorization, "Bearer $VALID_TOKEN")
        }
        assertEquals("reader", resp.bodyAsText())
    }

    @Test
    fun `protected endpoint principal contains permissions from token`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/permissions") {
            header(HttpHeaders.Authorization, "Bearer $VALID_TOKEN")
        }
        assertEquals("docs.read", resp.bodyAsText())
    }

    // ── Protected endpoint — no token ────────────────────────────────────────

    @Test
    fun `protected endpoint returns 401 when Authorization header is absent`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/me")
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    // ── Protected endpoint — invalid token ───────────────────────────────────

    @Test
    fun `protected endpoint returns 401 when token signature is invalid`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/me") {
            header(HttpHeaders.Authorization, "Bearer $INVALID_TOKEN")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `protected endpoint returns 401 when token is expired`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/me") {
            header(HttpHeaders.Authorization, "Bearer $EXPIRED_TOKEN")
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    // ── Permission checks in route handlers ──────────────────────────────────

    @Test
    fun `permission-gated route allows access when claim is present`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/docs") {
            header(HttpHeaders.Authorization, "Bearer $VALID_TOKEN")
        }
        assertEquals(HttpStatusCode.OK, resp.status)
    }

    @Test
    fun `permission-gated route returns 403 when claim is absent`() = testApplication {
        withHearthApp()
        val resp = client.get("/protected/admin-docs") {
            header(HttpHeaders.Authorization, "Bearer $VALID_TOKEN")
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private fun ApplicationTestBuilder.withHearthApp() {
        install(Authentication) {
            hearth("hearth") {
                client = mockHearthClient
            }
        }
        routing {
            get("/public/ping") { call.respondText("pong") }

            authenticate("hearth") {
                get("/protected/me") {
                    val p = call.principal<HearthPrincipal>()!!
                    call.respondText(p.claims.subject())
                }
                get("/protected/roles") {
                    val p = call.principal<HearthPrincipal>()!!
                    call.respondText(p.claims.roles().joinToString(","))
                }
                get("/protected/permissions") {
                    val p = call.principal<HearthPrincipal>()!!
                    call.respondText(p.claims.permissions().joinToString(","))
                }
                get("/protected/docs") {
                    val p = call.principal<HearthPrincipal>()!!
                    if (p.claims.hasPermission("docs.read")) {
                        call.respondText("granted")
                    } else {
                        call.respond(HttpStatusCode.Forbidden)
                    }
                }
                get("/protected/admin-docs") {
                    val p = call.principal<HearthPrincipal>()!!
                    if (p.claims.hasPermission("docs.write")) {
                        call.respondText("granted")
                    } else {
                        call.respond(HttpStatusCode.Forbidden)
                    }
                }
            }
        }
    }
}
