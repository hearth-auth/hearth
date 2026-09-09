package io.hearth.sdk

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * A suspend gate that returns `true` iff the token holder has the required permission
 * under the configured mode.
 *
 * Usage:
 * ```kotlin
 * val checker = requirePermission(
 *     "docs.write",
 *     RequirePermissionOptions(mode = AccessTokenAuthorizationMode.EMBEDDED, client = client),
 * )
 * if (!checker.check(bearerToken)) {
 *     // 403 Forbidden
 * }
 * ```
 *
 * **Ktor integration:**
 * ```kotlin
 * val checker = requirePermission("docs.write", RequirePermissionOptions(...))
 * get("/docs") {
 *     val token = call.request.header("Authorization")?.removePrefix("Bearer ") ?: ""
 *     if (!checker.check(token)) { call.respond(HttpStatusCode.Forbidden); return@get }
 *     // handle request
 * }
 * ```
 *
 * **Spring WebFlux integration:**
 * ```kotlin
 * val checker = requirePermission("docs.write", RequirePermissionOptions(...))
 * // In a HandlerFilterFunction:
 * val token = request.headers().firstHeader("Authorization")?.removePrefix("Bearer ") ?: ""
 * if (!checker.check(token)) return ServerResponse.status(403).build()
 * ```
 */
fun interface PermissionChecker {
    /** Returns true iff [token] grants the configured permission under the configured mode. */
    suspend fun check(token: String): Boolean
}

/** Options for [requirePermission]. */
data class RequirePermissionOptions(
    /**
     * Which permission delivery mode the resource server expects.
     *
     * MUST be set explicitly — the middleware MUST NOT auto-detect the mode from JWT claim
     * presence. Absence of a `permissions` claim in the token does not change behavior
     * (per HEA-922 design constraint).
     */
    val mode: AccessTokenAuthorizationMode,
    /** [HearthClient] instance used for network calls in Decision/Introspection modes. */
    val client: HearthClient,
    /** Constrain the decision to a specific organization. */
    val organizationId: String? = null,
    /** Constrain the decision to a specific resource. */
    val resource: String? = null,
)

/**
 * Returns a mode-aware [PermissionChecker] for the given [permission].
 *
 * Behavior by mode:
 * - **[AccessTokenAuthorizationMode.EMBEDDED]** — verifies the JWT via
 *   [HearthClient.verifyToken] (Ed25519 signature against the realm's cached JWKS, plus
 *   `exp`, `nbf`, `iss` and `aud`) and only then reads the `permissions` claim. No
 *   per-request network call once the JWKS is warm. Returns `false` when the token does
 *   not verify or the `permissions` claim is absent. DOES NOT fall back to a network call
 *   on claim absence (design constraint: absence of claims ≠ switch mode).
 * - **[AccessTokenAuthorizationMode.DECISION]** — calls [HearthClient.checkPermission] which
 *   POSTs to `POST /oauth/authorize`. Fail-closed: network or server errors return `false`.
 * - **[AccessTokenAuthorizationMode.INTROSPECTION]** — calls [HearthClient.introspect], validates
 *   the echoed `mode` field, then checks the returned `permissions` list.
 *   Throws [AuthorizationModeMismatchError] when the server echoes a mode that differs from
 *   [RequirePermissionOptions.mode]. An absent `mode` field is treated as `"embedded"`.
 *
 * @param permission Permission string to check (e.g. `"docs.write"`).
 * @param opts       Mode, client reference, and optional scoping parameters.
 */
fun requirePermission(permission: String, opts: RequirePermissionOptions): PermissionChecker =
    when (opts.mode) {
        AccessTokenAuthorizationMode.EMBEDDED -> PermissionChecker { token ->
            checkRequiredAction(token)
            // Verify BEFORE reading a claim. Decoding without verifying would let anyone
            // mint an unsigned token carrying whatever permissions they liked.
            try {
                opts.client.verifyToken(token).hasPermission(permission)
            } catch (_: HearthException) {
                false
            }
        }

        AccessTokenAuthorizationMode.DECISION -> PermissionChecker { token ->
            checkRequiredAction(token)
            opts.client.checkPermission(
                token = token,
                permission = permission,
                organizationId = opts.organizationId,
                resource = opts.resource,
            )
        }

        AccessTokenAuthorizationMode.INTROSPECTION -> PermissionChecker { token ->
            checkRequiredAction(token)
            val result = opts.client.introspect(token)

            // Validate echoed mode. Absent mode field defaults to "embedded" (pre-HEA-922 servers).
            val echoed = result.mode ?: AccessTokenAuthorizationMode.EMBEDDED.value
            if (echoed != opts.mode.value) {
                throw AuthorizationModeMismatchError(opts.mode.value, echoed)
            }

            result.active && result.permissions.contains(permission)
        }
    }

/**
 * Decodes the JWT payload locally and throws [RequiredActionError] when
 * `token_type === "required_action"` (sdk-spec §6 Rule 6).
 *
 * The signature is NOT verified here. That is safe because this gate can only ever
 * *reject*: a forged `token_type` costs the forger their own request and grants nothing.
 * Every path that can *grant* verifies first.
 */
internal fun checkRequiredAction(token: String) {
    if (token.isBlank()) return
    val parts = token.split(".")
    if (parts.size != 3) return
    try {
        val decoded = java.util.Base64.getUrlDecoder().decode(
            parts[1].padEnd((parts[1].length + 3) / 4 * 4, '=')
        )
        val obj = JSON.parseToJsonElement(String(decoded)) as? JsonObject ?: return
        val tokenType = (obj["token_type"] as? JsonPrimitive)?.contentOrNull ?: return
        if (tokenType == "required_action") {
            val actions = (obj["required_actions"] as? JsonArray)
                ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
                ?: emptyList()
            throw RequiredActionError(requiredActions = actions)
        }
    } catch (e: RequiredActionError) {
        throw e
    } catch (_: Exception) {
        // Malformed token — let downstream verification handle it
    }
}

/**
 * Decodes the JWT payload locally and returns the `permissions` list, or `null` when
 * the token is malformed or the claim is absent.
 *
 * The signature is NOT verified, so this MUST NOT back an authorization decision — the
 * EMBEDDED checker above goes through [HearthClient.verifyToken] instead. Retained for
 * callers that need to inspect their own freshly-issued token.
 */
internal fun decodeLocalPermissions(token: String): List<String>? {
    if (token.isBlank()) return null
    val parts = token.split(".")
    if (parts.size != 3) return null
    return try {
        val decoded = java.util.Base64.getUrlDecoder().decode(
            parts[1].padEnd((parts[1].length + 3) / 4 * 4, '=')
        )
        val obj = JSON.parseToJsonElement(String(decoded)) as? JsonObject ?: return null
        (obj["permissions"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
    } catch (_: Exception) {
        null
    }
}
