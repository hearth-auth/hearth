package io.hearth.sdk

/**
 * Base exception for all Hearth SDK errors.
 *
 * Tokens and secrets never appear in messages or causes per sdk-spec §11.
 */
open class HearthException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/** Missing required config or invalid issuer URL. */
class ConfigurationError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** OIDC discovery endpoint unreachable or returned invalid JSON. */
class DiscoveryError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWKS endpoint unreachable or returned invalid response. */
class JWKSFetchError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `exp` claim is in the past. */
class TokenExpiredError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `nbf` claim is in the future beyond allowed clock skew. */
class TokenNotYetValidError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** Signature invalid, malformed JWT, or algorithm mismatch. */
class TokenInvalidError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `iss` does not match configured issuer. */
class TokenIssuerError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** JWT `aud` does not contain expected audience. */
class TokenAudienceError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** Introspection endpoint unreachable or returned an error. */
class IntrospectionError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/** Hearth API returned a non-2xx response. */
class ApiError(
    val statusCode: Int,
    message: String,
    cause: Throwable? = null,
) : HearthException(message, cause)

/**
 * Thrown when the `mode` field echoed in an introspection response does not match
 * the SDK's configured expectation (HEA-922).
 *
 * Per design constraint: mode must be validated explicitly; the SDK MUST NOT silently
 * tolerate a server returning a different mode than the one configured for this resource server.
 */
class AuthorizationModeMismatchError(
    val expected: String,
    val actual: String,
    message: String = "Authorization mode mismatch: expected \"$expected\", got \"$actual\"",
) : HearthException(message)

/** POST /oauth/authorize endpoint unreachable or returned a non-2xx response. */
class AuthorizeError(message: String, cause: Throwable? = null) :
    HearthException(message, cause)

/**
 * Thrown when a token with `token_type === "required_action"` is presented as a regular
 * access token (sdk-spec §5, §6).
 *
 * This token is valid but scoped only to completing the pending required actions — it
 * MUST NOT be accepted for general API access.
 *
 * @param requiredActions Pending action names from the token's `required_actions` claim
 *                        (e.g. `["VERIFY_EMAIL", "UPDATE_PASSWORD"]`).
 * @param redirectUri     Optional URL to the Hearth interstitial page for the required actions.
 */
class RequiredActionError(
    val requiredActions: List<String>,
    val redirectUri: String? = null,
    message: String = "Token requires completion of required actions: $requiredActions",
    cause: Throwable? = null,
) : HearthException(message, cause)
