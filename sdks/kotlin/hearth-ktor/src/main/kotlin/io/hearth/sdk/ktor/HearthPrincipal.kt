package io.hearth.sdk.ktor

import io.hearth.sdk.Claims
import io.ktor.server.auth.Principal

/**
 * Ktor [Principal] populated by [HearthAuthProvider] after JWT signature verification.
 *
 * Retrieve it inside an [io.ktor.server.auth.authenticate] block:
 *
 * ```kotlin
 * authenticate("hearth") {
 *     get("/me") {
 *         val principal = call.principal<HearthPrincipal>()!!
 *         call.respondText(principal.claims.subject())
 *     }
 * }
 * ```
 *
 * `rawToken` can be forwarded downstream to other services as a delegation credential.
 */
data class HearthPrincipal(
    /** The raw bearer token string received in the `Authorization` header. */
    val rawToken: String,
    /** Verified and decoded JWT claims from [io.hearth.sdk.HearthClient.verifyToken]. */
    val claims: Claims,
) : Principal
