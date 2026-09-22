package io.hearth.sdk.spring

import io.hearth.sdk.Claims
import io.hearth.sdk.HearthClient
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
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * The adapter must answer a missing or unusable bearer token with **401**,
 * with no `exceptionHandling` block written by the integrator.
 *
 * Spring Security's `ExceptionHandlingConfigurer` falls back to
 * `Http403ForbiddenEntryPoint` when no entry point was registered — and nothing
 * registers one unless the chain configures `httpBasic`, `formLogin` or
 * `oauth2ResourceServer`. The adapter's own README showed a chain with an empty
 * `exceptionHandling`, so a tokenless request to a shipped integration answered
 * 403 and carried no `WWW-Authenticate` header, which is what RFC 6750 §3 tells
 * a client to read (audit 2026-08-28 §25.22).
 *
 * This application declares NO `SecurityFilterChain` of its own: everything under
 * test comes from [HearthSecurityAutoConfiguration].
 */
@SpringBootTest(classes = [HearthDefaultEntryPointTest.DefaultsOnlyApplication::class])
@AutoConfigureMockMvc
@TestPropertySource(properties = ["hearth.issuer-url=https://auth.example.com"])
class HearthDefaultEntryPointTest {

    companion object {
        const val VALID_TOKEN = "valid.jwt.token"
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
            every { roles() } returns emptyList()
            every { permissions() } returns emptyList()
        }
        coEvery { mockClient.verifyToken(VALID_TOKEN) } returns fakeClaims
        coEvery { mockClient.verifyToken(INVALID_TOKEN) } throws TokenInvalidError("bad signature")
    }

    @Test
    fun `a missing bearer token answers 401, not Spring Security's default 403`() {
        mockMvc.get("/me").andExpect {
            status { isUnauthorized() }
        }
    }

    @Test
    fun `a missing bearer token carries a WWW-Authenticate Bearer challenge`() {
        mockMvc.get("/me").andExpect {
            header { string(HttpHeaders.WWW_AUTHENTICATE, "Bearer") }
        }
    }

    @Test
    fun `an unusable bearer token answers 401 with an invalid_token challenge`() {
        mockMvc.get("/me") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $INVALID_TOKEN")
        }.andExpect {
            status { isUnauthorized() }
            header {
                string(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")
            }
        }
    }

    @Test
    fun `a valid bearer token still reaches the controller`() {
        mockMvc.get("/me") {
            header(HttpHeaders.AUTHORIZATION, "Bearer $VALID_TOKEN")
        }.andExpect {
            status { isOk() }
        }
    }

    // ── Application bootstrap — no SecurityFilterChain declared on purpose ──────

    @SpringBootApplication(scanBasePackages = ["io.hearth.sdk.spring"])
    open class DefaultsOnlyApplication {

        // Registered explicitly: Spring Boot's TestTypeExcludeFilter drops every
        // class nested inside a test class from component scanning.
        @Bean
        open fun meController(): MeController = MeController()

        // Wins over the auto-configured client via @ConditionalOnMissingBean, so
        // no real JWKS fetch happens.
        @Bean
        open fun mockHearthClient(): HearthClient = mockk(relaxed = true)
    }

    @RestController
    class MeController {

        @GetMapping("/me")
        fun me(@AuthenticationPrincipal auth: HearthAuthentication): Map<String, Any> =
            mapOf("sub" to auth.claims.subject())
    }
}
