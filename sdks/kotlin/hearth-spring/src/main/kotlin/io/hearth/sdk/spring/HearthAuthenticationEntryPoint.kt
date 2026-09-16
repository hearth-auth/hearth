package io.hearth.sdk.spring

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint

/**
 * Answers an unauthenticated request with **401** and an RFC 6750 `WWW-Authenticate`
 * challenge, instead of Spring Security's default 403.
 *
 * Spring Security's `ExceptionHandlingConfigurer` only registers an entry point when
 * the chain configures `httpBasic`, `formLogin` or `oauth2ResourceServer`. A chain
 * that does none of those — which is exactly the shape a bearer-token API wants —
 * falls back to `Http403ForbiddenEntryPoint`, so a request carrying no credential at
 * all was answered "you may not", not "who are you?", and carried no header telling
 * the client how to authenticate (audit 2026-08-28 §25.22).
 *
 * [HearthSecurityAutoConfiguration] registers this as the default entry point of the
 * default filter chain. Declare your own `AuthenticationEntryPoint` bean, or your own
 * `SecurityFilterChain`, to replace it.
 *
 * The challenge is deliberately terse. `Bearer` alone is sent when no token was
 * presented; `Bearer error="invalid_token"` when one was presented and rejected,
 * per RFC 6750 §3.1. No `realm` parameter is emitted: it would leak the realm
 * identifier to an unauthenticated caller and clients do not act on it.
 */
class HearthAuthenticationEntryPoint : AuthenticationEntryPoint {

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException?,
    ) {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challengeFor(request))
        response.sendError(HttpStatus.UNAUTHORIZED.value(), "Unauthorized")
    }

    private fun challengeFor(request: HttpServletRequest): String =
        if (hasBearerCredential(request)) BEARER_INVALID_TOKEN else BEARER

    private fun hasBearerCredential(request: HttpServletRequest): Boolean {
        val header = request.getHeader(HttpHeaders.AUTHORIZATION) ?: return false
        if (!header.startsWith(BEARER_PREFIX)) return false
        return header.removePrefix(BEARER_PREFIX).trim().isNotBlank()
    }

    internal companion object {
        const val BEARER = "Bearer"
        const val BEARER_INVALID_TOKEN = """Bearer error="invalid_token""""
        const val BEARER_PREFIX = "Bearer "
    }
}
