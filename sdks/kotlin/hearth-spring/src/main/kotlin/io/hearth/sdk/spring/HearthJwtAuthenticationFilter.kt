package io.hearth.sdk.spring

import io.hearth.sdk.HearthClient
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter

/**
 * Spring Security filter that validates Hearth JWT bearer tokens on every request.
 *
 * Register it before [org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter]
 * in your `SecurityFilterChain`:
 *
 * ```kotlin
 * @Bean
 * fun securityFilterChain(
 *     http: HttpSecurity,
 *     filter: HearthJwtAuthenticationFilter,
 * ): SecurityFilterChain {
 *     http
 *         .csrf { it.disable() }
 *         .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
 *         .addFilterBefore(filter, UsernamePasswordAuthenticationFilter::class.java)
 *         .authorizeHttpRequests { auth ->
 *             auth.requestMatchers("/public/*").permitAll()
 *             auth.anyRequest().authenticated()
 *         }
 *     return http.build()
 * }
 * ```
 *
 * **Request lifecycle:**
 * 1. Extracts the bearer token from the `Authorization: Bearer <jwt>` header.
 * 2. If no token is present, the request passes through untouched — Spring Security's
 *    own exception translation will issue HTTP 401 for protected endpoints.
 * 3. If a token is present, [HearthClient.verifyToken] verifies the signature and expiry
 *    via JWKS (cached, no network call on the hot path after the first fetch).
 * 4. On success, a [HearthAuthentication] is stored in the [SecurityContextHolder].
 * 5. On failure (expired, bad signature, malformed), the context is cleared and
 *    HTTP 401 is returned immediately.
 *
 * The verified [io.hearth.sdk.Claims] are available via `@AuthenticationPrincipal`:
 * ```kotlin
 * @GetMapping("/me")
 * fun me(@AuthenticationPrincipal auth: HearthAuthentication) =
 *     mapOf("sub" to auth.claims.subject(), "roles" to auth.claims.roles())
 * ```
 *
 * When auto-configuration is active ([HearthSecurityAutoConfiguration]) this bean is created
 * automatically; no manual instantiation is needed.
 */
class HearthJwtAuthenticationFilter(
    private val client: HearthClient,
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(HearthJwtAuthenticationFilter::class.java)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
    ) {
        val token = extractBearer(request) ?: run {
            // No token — pass through; Spring Security handles 401 for protected routes.
            chain.doFilter(request, response)
            return
        }

        try {
            val claims = runBlocking { client.verifyToken(token) }
            SecurityContextHolder.getContext().authentication = HearthAuthentication(token, claims)
            chain.doFilter(request, response)
        } catch (ex: Exception) {
            log.debug("Hearth JWT verification failed: {}", ex.message)
            SecurityContextHolder.clearContext()
            response.status = HttpStatus.UNAUTHORIZED.value()
        }
    }

    private fun extractBearer(request: HttpServletRequest): String? {
        val header = request.getHeader("Authorization") ?: return null
        if (!header.startsWith("Bearer ")) return null
        return header.removePrefix("Bearer ").trim().ifBlank { null }
    }
}
