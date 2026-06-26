package io.hearth.sdk.spring

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Spring Boot configuration properties for the Hearth SDK adapter.
 *
 * Bind via `application.yml`:
 * ```yaml
 * hearth:
 *   issuer-url: https://auth.example.com
 *   client-id: my-resource-server       # optional — not required for token verification
 *   client-secret: s3cr3t               # optional — required for introspection or client-credentials
 *   realm-id: my-realm                  # optional — required for permission-decision mode
 *   http-timeout-ms: 10000              # optional — defaults to 10 000 ms
 * ```
 *
 * Or `application.properties`:
 * ```properties
 * hearth.issuer-url=https://auth.example.com
 * hearth.realm-id=my-realm
 * ```
 */
@ConfigurationProperties("hearth")
data class HearthSecurityProperties(
    /**
     * Base URL of the Hearth identity server. **Required.**
     *
     * Auto-configuration is only activated when this property is non-empty.
     * The OIDC discovery document is fetched from `{issuerUrl}/.well-known/openid-configuration`.
     */
    val issuerUrl: String = "",

    /**
     * OAuth client ID.
     *
     * Optional for token verification (JWKS-only). Required when calling
     * introspection or client-credentials flows.
     */
    val clientId: String? = null,

    /**
     * OAuth client secret.
     *
     * Required for introspection (`POST /introspect`) and client-credentials flows.
     * Leave `null` when the resource server only performs JWKS-based verification.
     */
    val clientSecret: String? = null,

    /**
     * Hearth realm ID.
     *
     * Required for permission-decision mode (`POST /oauth/authorize`),
     * magic-link requests, and `GET /v1/me/permissions`.
     */
    val realmId: String? = null,

    /** JWKS key cache TTL in milliseconds. Uses the SDK default when `null`. */
    val jwksTtlMs: Long? = null,

    /** HTTP connect + read timeout in milliseconds. Defaults to 10 000. */
    val httpTimeoutMs: Long = 10_000L,
)
