package io.hearth.sdk.spring

import io.hearth.sdk.HearthClient
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

/**
 * Spring Boot auto-configuration for Hearth JWT authentication.
 *
 * **Activation conditions:**
 * - `hearth.issuer-url` is present in application properties.
 * - Running in a Servlet web application context (not WebFlux).
 * - `HearthClient` is on the classpath (i.e. `hearth-core` is a dependency).
 *
 * **Registered beans (each skipped when a custom bean of the same type already exists):**
 * - [HearthClient] — built from [HearthSecurityProperties]; declare your own `@Bean` to
 *   customise the client (e.g. override JWKS TTL, set a custom HTTP timeout).
 * - [HearthAuthenticationEntryPoint] — answers an unauthenticated request with 401 and an
 *   RFC 6750 `WWW-Authenticate` challenge.
 * - [HearthJwtAuthenticationFilter] — the filter itself; declare your own `@Bean` to wrap
 *   or replace it.
 * - [SecurityFilterChain] — a stateless bearer-token chain wiring the two together:
 *   CSRF off, no session, filter installed, every request authenticated, and the entry
 *   point above. Declaring **any** `SecurityFilterChain` bean of your own replaces it —
 *   wire `exceptionHandling { it.authenticationEntryPoint(hearthEntryPoint) }` into your
 *   chain when you do, or a missing token answers Spring Security's fallback 403 rather
 *   than 401 (audit 2026-08-28 §25.22).
 *
 * **Minimal configuration** (`application.yml`):
 * ```yaml
 * hearth:
 *   issuer-url: https://auth.example.com
 * ```
 *
 * With only that property set, every request must carry a valid Hearth bearer token and
 * a request without one gets `401` plus `WWW-Authenticate: Bearer`. Override the chain
 * only when you need public routes or per-route authorities:
 *
 * ```kotlin
 * @Bean
 * fun securityFilterChain(
 *     http: HttpSecurity,
 *     hearthFilter: HearthJwtAuthenticationFilter,
 *     hearthEntryPoint: AuthenticationEntryPoint,
 * ): SecurityFilterChain {
 *     http
 *         .csrf { it.disable() }
 *         .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
 *         .addFilterBefore(hearthFilter, UsernamePasswordAuthenticationFilter::class.java)
 *         .authorizeHttpRequests { auth ->
 *             auth.requestMatchers("/health", "/public").permitAll()
 *             auth.anyRequest().authenticated()
 *         }
 *         // Do not omit this: without an entry point Spring Security answers a
 *         // missing credential with 403.
 *         .exceptionHandling { it.authenticationEntryPoint(hearthEntryPoint) }
 *     return http.build()
 * }
 * ```
 */
@AutoConfiguration(beforeName = ["org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration"])
@ConditionalOnClass(HearthClient::class, SecurityFilterChain::class)
@ConditionalOnProperty("hearth.issuer-url")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(HearthSecurityProperties::class)
class HearthSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun hearthClient(props: HearthSecurityProperties): HearthClient =
        HearthClient(
            issuerUrl = props.issuerUrl,
            clientId = props.clientId,
            clientSecret = props.clientSecret,
            realmId = props.realmId,
            jwksTtl = props.jwksTtlMs,
            httpTimeoutMs = props.httpTimeoutMs,
        )

    /**
     * The default authentication entry point: 401 plus an RFC 6750 challenge.
     *
     * Spring Security registers no entry point for a chain that configures neither
     * `httpBasic` nor `formLogin` nor `oauth2ResourceServer`, and falls back to
     * `Http403ForbiddenEntryPoint`, so a bearer API answered a missing token with 403
     * (audit 2026-08-28 §25.22).
     */
    @Bean
    @ConditionalOnMissingBean(AuthenticationEntryPoint::class)
    fun hearthAuthenticationEntryPoint(): AuthenticationEntryPoint = HearthAuthenticationEntryPoint()

    @Bean
    @ConditionalOnMissingBean
    fun hearthJwtAuthenticationFilter(
        client: HearthClient,
        entryPointProvider: ObjectProvider<AuthenticationEntryPoint>,
    ): HearthJwtAuthenticationFilter = HearthJwtAuthenticationFilter(
        client,
        entryPointProvider.getIfAvailable { HearthAuthenticationEntryPoint() },
    )

    /**
     * Installs a stateless bearer-token chain when the application declares no
     * [SecurityFilterChain] of its own.
     *
     * `@EnableWebSecurity` is what supplies the [HttpSecurity] prototype the chain is
     * built from; without it this auto-configuration would have to wait for Spring
     * Boot's `SecurityAutoConfiguration`, whose own default chain offers form login
     * and HTTP Basic — so a tokenless call on a Hearth resource server was answered
     * with a login-page redirect or a bare 403 rather than 401
     * (audit 2026-08-28 §25.22).
     *
     * `@ConditionalOnMissingBean` is evaluated against the application's own beans,
     * which are registered before any auto-configuration, so declaring any
     * `SecurityFilterChain` replaces this whole configuration.
     */
    // The conditions are repeated here on purpose. This is a nested `@Configuration`,
    // so it is a component-scan candidate in its own right — an application that scans
    // `io.hearth.sdk.spring` picks it up directly rather than through the enclosing
    // auto-configuration, and the enclosing class's conditions do not travel with it.
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty("hearth.issuer-url")
    @ConditionalOnMissingBean(SecurityFilterChain::class)
    @EnableWebSecurity
    class DefaultSecurityFilterChainConfiguration {

        @Bean
        fun hearthSecurityFilterChain(
            http: HttpSecurity,
            filter: HearthJwtAuthenticationFilter,
            // ObjectProvider, not a hard dependency: under component scan the entry-point
            // bean may not be registered yet, and a chain that cannot be built is worse
            // than one built with the default entry point.
            entryPointProvider: ObjectProvider<AuthenticationEntryPoint>,
        ): SecurityFilterChain {
            val entryPoint = entryPointProvider.getIfAvailable { HearthAuthenticationEntryPoint() }
            http
                .csrf { it.disable() }
                .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter::class.java)
                .authorizeHttpRequests { it.anyRequest().authenticated() }
                .exceptionHandling { it.authenticationEntryPoint(entryPoint) }
            return http.build()
        }
    }
}
