package io.hearth.sdk.spring

import io.hearth.sdk.HearthClient
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean

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
 * - [HearthJwtAuthenticationFilter] — the filter itself; declare your own `@Bean` to wrap
 *   or replace it.
 *
 * **Minimal configuration** (`application.yml`):
 * ```yaml
 * hearth:
 *   issuer-url: https://auth.example.com
 * ```
 *
 * **Wire the filter into your security chain:**
 * ```kotlin
 * @Bean
 * fun securityFilterChain(
 *     http: HttpSecurity,
 *     hearthFilter: HearthJwtAuthenticationFilter,
 * ): SecurityFilterChain {
 *     http
 *         .csrf { it.disable() }
 *         .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
 *         .addFilterBefore(hearthFilter, UsernamePasswordAuthenticationFilter::class.java)
 *         .authorizeHttpRequests { it.anyRequest().authenticated() }
 *     return http.build()
 * }
 * ```
 */
@AutoConfiguration
@ConditionalOnClass(HearthClient::class)
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

    @Bean
    @ConditionalOnMissingBean
    fun hearthJwtAuthenticationFilter(client: HearthClient): HearthJwtAuthenticationFilter =
        HearthJwtAuthenticationFilter(client)
}
