package io.hearth.sdk.ktor

import io.hearth.sdk.HearthClient
import io.ktor.server.auth.AuthenticationProvider

/**
 * Configuration for the Hearth Ktor authentication provider.
 *
 * Supply [issuerUrl] (and optionally [clientId] / [clientSecret] / [realmId]) to have
 * a [HearthClient] constructed automatically, or set [client] to inject a pre-built instance
 * (useful in tests and when sharing a single client across multiple providers).
 *
 * ```kotlin
 * install(Authentication) {
 *     hearth("api") {
 *         issuerUrl = "https://auth.example.com"
 *         clientId  = "resource-server"
 *     }
 * }
 * ```
 */
class HearthAuthConfig(name: String?) : AuthenticationProvider.Config(name) {

    /** Hearth issuer URL (e.g. `"https://auth.example.com"`). Required unless [client] is set. */
    var issuerUrl: String = ""

    /** OAuth 2.0 client identifier for this resource server. */
    var clientId: String? = null

    /** OAuth 2.0 client secret. */
    var clientSecret: String? = null

    /** Realm ID sent as `X-Realm-ID` on realm-scoped API calls. */
    var realmId: String? = null

    /** JWKS cache TTL in milliseconds. Defaults to 5 minutes. */
    var jwksTtlMs: Long = 300_000L

    /** HTTP connect and read timeout in milliseconds. Defaults to 10 seconds. */
    var httpTimeoutMs: Long = 10_000L

    /**
     * Pre-built [HearthClient] to use instead of constructing one from the properties above.
     *
     * Set this in tests (inject a mock) or when sharing a configured client across plugins.
     * When non-null, [issuerUrl] / [clientId] / [clientSecret] / [realmId] are ignored.
     */
    var client: HearthClient? = null

    internal fun buildClient(): HearthClient =
        client ?: HearthClient(
            issuerUrl = issuerUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            realmId = realmId,
            jwksTtl = jwksTtlMs,
            httpTimeoutMs = httpTimeoutMs,
        )
}
