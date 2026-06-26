package io.hearth.sdk.spring

import io.hearth.sdk.Claims
import io.hearth.sdk.HearthClient
import io.hearth.sdk.TokenExpiredError
import io.hearth.sdk.TokenInvalidError
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Integration test: verifies end-to-end Spring Boot + Spring Security + Hearth JWT flow
 * using MockMvc and a mocked [HearthClient] (no real Hearth server required).
 */
@SpringBootTest(classes = [HearthSpringIntegrationTest.TestApplication::class])
@AutoConfigureMockMvc
class HearthSpringIntegrationTest {

    companion object {
        const val VALID_TOKEN = "valid.jwt.token"
        const val EXPIRED_TOKEN = "expired.jwt.token"
        const val INVALID_TOKEN = "invalid.jwt.token"
    }

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var mockClient: HearthClient

    @BeforeEach
    fun setUpMocks() {
        val fakeClaims = mockk<Claims> {
            every { subject() } returns "user-abc"
            every { roles() } returns listOf("reader")
            every { permissions() } returns listOf("docs.read")
            every { hasPermission("docs.read") } returns true
            every { hasPermission("docs.write") } returns false
        }
        coEvery { mockClient.verifyToken(VALID_TOKEN) } returns fakeClaims
        coEvery { mockClient.verifyToken(EXPIRED_TOKEN) } throws TokenExpiredError("token expired")
        coEvery { mockClient.verifyToken(INVALID_TOKEN) } throws TokenInvalidError("bad signature")
    }

    // ── Public endpoint ─────────────────────────────────────────────────────────

    @Test
    fun `public endpoint is accessible without a token`() {
        mockMvc.get("/public/ping").andExpect {
            status { isOk() }
            content { string("pong") }
        }
    }

    // ── Protected endpoint — valid token ────────────────────────────────────────

    @Test
    fun `protected endpoint returns 200 with a valid Hearth JWT`() {
        mockMvc.get("/protected/me") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $VALID_TOKEN")
        }.andExpect {
            status { isOk() }
            content { contentTypeCompatibleWith(MediaType.APPLICATION_JSON) }
            jsonPath("$.sub") { value("user-abc") }
        }
    }

    @Test
    fun `protected endpoint returns roles in response`() {
        mockMvc.get("/protected/me") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $VALID_TOKEN")
        }.andExpect {
            status { isOk() }
            jsonPath("$.roles[0]") { value("reader") }
        }
    }

    // ── Protected endpoint — no token ───────────────────────────────────────────

    @Test
    fun `protected endpoint returns 401 when no Authorization header is present`() {
        mockMvc.get("/protected/me").andExpect {
            status { isUnauthorized() }
        }
    }

    // ── Protected endpoint — invalid / expired token ────────────────────────────

    @Test
    fun `protected endpoint returns 401 when token signature is invalid`() {
        mockMvc.get("/protected/me") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $INVALID_TOKEN")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `protected endpoint returns 401 when token is expired`() {
        mockMvc.get("/protected/me") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $EXPIRED_TOKEN")
        }.andExpect {
            status { isUnauthorized() }
        }
    }

    // ── Permission-guarded endpoint ─────────────────────────────────────────────

    @Test
    fun `permission-guarded endpoint is accessible when token has required permission`() {
        mockMvc.get("/protected/docs") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $VALID_TOKEN")
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `permission-guarded endpoint returns 403 when token lacks required permission`() {
        mockMvc.get("/protected/admin-docs") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $VALID_TOKEN")
        }.andExpect {
            status { isForbidden() }
        }
    }

    // ── Test application bootstrap ──────────────────────────────────────────────

    @SpringBootApplication(scanBasePackages = ["io.hearth.sdk.spring"])
    open class TestApplication {

        @Bean
        open fun mockHearthClient(): HearthClient = mockk(relaxed = true)

        @Bean
        open fun hearthJwtAuthenticationFilter(client: HearthClient): HearthJwtAuthenticationFilter =
            HearthJwtAuthenticationFilter(client)

        @Bean
        open fun securityFilterChain(
            http: HttpSecurity,
            filter: HearthJwtAuthenticationFilter,
        ): SecurityFilterChain {
            http
                .csrf { it.disable() }
                .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter::class.java)
                .authorizeHttpRequests { auth ->
                    auth.requestMatchers("/public/**").permitAll()
                    auth.requestMatchers("/protected/admin-docs").hasAuthority("docs.write")
                    auth.requestMatchers("/protected/**").authenticated()
                    auth.anyRequest().authenticated()
                }
                .exceptionHandling { }
            return http.build()
        }
    }

    @RestController
    class TestController {

        @GetMapping("/public/ping")
        fun ping(): String = "pong"

        @GetMapping("/protected/me")
        fun me(@AuthenticationPrincipal auth: HearthAuthentication): Map<String, Any> =
            mapOf(
                "sub" to auth.claims.subject(),
                "roles" to auth.claims.roles(),
                "permissions" to auth.claims.permissions(),
            )

        @GetMapping("/protected/docs")
        fun docs(@AuthenticationPrincipal auth: HearthAuthentication): Map<String, String> =
            mapOf("message" to "doc access granted for ${auth.claims.subject()}")

        @GetMapping("/protected/admin-docs")
        fun adminDocs(): Map<String, String> =
            mapOf("message" to "admin doc access")
    }
}
