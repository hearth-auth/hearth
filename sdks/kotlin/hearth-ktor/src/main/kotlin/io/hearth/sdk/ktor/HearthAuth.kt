package io.hearth.sdk.ktor

import io.hearth.sdk.HearthClient
import io.hearth.sdk.HearthException
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.auth.AuthenticationConfig
import io.ktor.server.auth.AuthenticationContext
import io.ktor.server.auth.AuthenticationFailedCause
import io.ktor.server.auth.AuthenticationProvider
import io.ktor.server.response.respond
import org.slf4j.LoggerFactory

private const val HEARTH_AUTH_KEY = "HearthAuth"

/**
 * Ktor [AuthenticationProvider] that validates Hearth JWT bearer tokens.
 *
 * **Request lifecycle:**
 * 1. Extracts the bearer token from `Authorization: Bearer <jwt>`.
 * 2. No token → registers a challenge that responds HTTP 401; the challenge fires only when
 *    the enclosing `authenticate(...)` block requires a principal.
 * 3. Token present → [HearthClient.verifyToken] validates signature and expiry via JWKS
 *    (cached after first fetch — no network round-trip on the hot path).
 * 4. Success → [HearthPrincipal] is set on the call; route handler runs normally.
 * 5. Failure (expired, bad signature, malformed) → 401 via the registered challenge.
 *
 * Register via the [hearth] extension function on [AuthenticationConfig]:
 *
 * ```kotlin
 * install(Authentication) {
 *     hearth("api") {
 *         issuerUrl = "https://auth.example.com"
 *         clientId  = "resource-server"
 *     }
 * }
 *
 * routing {
 *     authenticate("api") {
 *         get("/me") {
 *             val principal = call.principal<HearthPrincipal>()!!
 *             call.respondText(principal.claims.subject())
 *         }
 *     }
 * }
 * ```
 */
class HearthAuthProvider(config: HearthAuthConfig) : AuthenticationProvider(config) {

    private val log = LoggerFactory.getLogger(HearthAuthProvider::class.java)
    private val client: HearthClient = config.buildClient()

    override suspend fun onAuthenticate(context: AuthenticationContext) {
        val call = context.call

        val token = call.request.headers[HttpHeaders.Authorization]
            ?.takeIf { it.startsWith("Bearer ") }
            ?.removePrefix("Bearer ")
            ?.trim()
            ?.ifBlank { null }

        if (token == null) {
            context.challenge(HEARTH_AUTH_KEY, AuthenticationFailedCause.NoCredentials) {
                call.respond(HttpStatusCode.Unauthorized)
                it.complete()
            }
            return
        }

        try {
            val claims = client.verifyToken(token)
            context.principal(HearthPrincipal(rawToken = token, claims = claims))
        } catch (ex: HearthException) {
            log.debug("Hearth JWT verification failed: {}", ex.message)
            context.challenge(HEARTH_AUTH_KEY, AuthenticationFailedCause.InvalidCredentials) {
                call.respond(HttpStatusCode.Unauthorized)
                it.complete()
            }
        } catch (ex: Exception) {
            log.debug("Unexpected error during Hearth JWT verification: {}", ex.message)
            context.challenge(HEARTH_AUTH_KEY, AuthenticationFailedCause.InvalidCredentials) {
                call.respond(HttpStatusCode.Unauthorized)
                it.complete()
            }
        }
    }
}

/**
 * Registers a Hearth JWT authentication provider under the given [name].
 *
 * ```kotlin
 * install(Authentication) {
 *     hearth("api") {
 *         issuerUrl = "https://auth.example.com"
 *         clientId  = "resource-server"
 *     }
 * }
 *
 * // Guard routes:
 * authenticate("api") { /* protected routes */ }
 * ```
 *
 * Pass `name = null` (or omit it) to register as the default (unnamed) provider,
 * which is used by `authenticate { }` blocks without a provider name.
 */
fun AuthenticationConfig.hearth(
    name: String? = null,
    configure: HearthAuthConfig.() -> Unit,
) {
    val config = HearthAuthConfig(name).apply(configure)
    register(HearthAuthProvider(config))
}
