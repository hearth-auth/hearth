---
title: Authenticate a Spring Boot app with Hearth
sidebar_label: Spring Boot
description: >
  Protect Spring Boot endpoints with Hearth-issued JWT tokens using HearthJwtAuthenticationFilter
  and Spring Boot auto-configuration. Covers SecurityFilterChain wiring, @AuthenticationPrincipal,
  HearthAuthentication claims, and granted-authority mapping.
---

# Authenticate a Spring Boot app with Hearth

This guide is for **Kotlin developers building Spring Boot services** who want to verify Hearth
bearer tokens with minimal boilerplate. The `hearth-spring` module ships
`HearthJwtAuthenticationFilter` — a `OncePerRequestFilter` that validates JWTs on every request —
together with Spring Boot auto-configuration that wires the filter automatically when
`hearth.issuer-url` is set in application properties.

:::note[Servlet only — Spring WebFlux is not supported]
`HearthSecurityAutoConfiguration` only activates in **Servlet-based** Spring Boot 3 apps
(Spring Security 6). If your service uses Spring WebFlux (Reactive), use
[`requirePermission()`](./kotlin.md#permission-checking-middleware) from `hearth-core` instead.
:::

:::note[Dedicated adapter vs Ktor]
This page covers the `hearth-spring` adapter. For **Ktor**, see the [Ktor adapter](./kotlin-ktor.md).
:::

## Install

Add `hearth-spring` to `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.hearth:hearth-spring:1.0.0")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-web")
}
```

**Requirements:** JVM 17+, Kotlin 1.9+, Spring Boot 3.x, Spring Security 6, Jakarta Servlet 6.

`hearth-spring` declares Spring Security and Spring Boot as `compileOnly` dependencies so your
Spring Boot version controls the runtime. `hearth-core` (the base Hearth SDK) is pulled in
transitively.

## Auto-configure with `application.yml`

Set `hearth.issuer-url` to activate auto-configuration:

```yaml
hearth:
  issuer-url: https://auth.example.com
  realm-id: my-realm    # optional — required for permission-decision and magic-link flows
```

With this property present, `HearthSecurityAutoConfiguration` registers:

- `HearthClient` — built from the properties above.
- `HearthJwtAuthenticationFilter` — ready to inject into your `SecurityFilterChain`.

Both beans use `@ConditionalOnMissingBean`, so declaring your own `@Bean` of either type
overrides the auto-configuration.

## Wire the filter into `SecurityFilterChain`

Inject `HearthJwtAuthenticationFilter` into your security configuration and add it before
`UsernamePasswordAuthenticationFilter`:

```kotlin
import io.hearth.sdk.spring.HearthJwtAuthenticationFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
class SecurityConfig {

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        hearthFilter: HearthJwtAuthenticationFilter,
    ): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(hearthFilter, UsernamePasswordAuthenticationFilter::class.java)
            .authorizeHttpRequests { auth ->
                auth.requestMatchers("/public/**").permitAll()
                auth.anyRequest().authenticated()
            }
        return http.build()
    }
}
```

Requests to `/public/**` pass through without a token. Every other request must carry a valid
Hearth bearer token or Spring Security returns `401 Unauthorized`.

## Access claims with `@AuthenticationPrincipal`

After the filter runs, a `HearthAuthentication` is stored in the `SecurityContextHolder`. Retrieve
it in any controller with `@AuthenticationPrincipal`:

```kotlin
import io.hearth.sdk.spring.HearthAuthentication
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class UserController {

    @GetMapping("/me")
    fun me(@AuthenticationPrincipal auth: HearthAuthentication): ResponseEntity<Map<String, Any>> =
        ResponseEntity.ok(mapOf(
            "sub"         to auth.claims.subject(),
            "roles"       to auth.claims.roles(),
            "permissions" to auth.claims.permissions(),
        ))
}
```

`auth.claims` exposes the full verified JWT payload. All claim methods (`subject()`, `roles()`,
`permissions()`, `inGroup()`, `hasRole()`, `hasPermission()`) read embedded JWT fields — no extra
network call.

## Enforce permissions with `hasAuthority`

`HearthAuthentication` maps JWT claims to Spring `GrantedAuthority` values automatically:

| JWT claim | Spring authority |
|-----------|-----------------|
| `roles: ["admin"]` | `ROLE_admin` |
| `permissions: ["docs.write"]` | `docs.write` (verbatim) |

Use these in `authorizeHttpRequests`:

```kotlin
.authorizeHttpRequests { auth ->
    auth.requestMatchers("/public/**").permitAll()
    auth.requestMatchers("/admin/**").hasRole("admin")           // checks ROLE_admin
    auth.requestMatchers("/docs/write").hasAuthority("docs.write")
    auth.anyRequest().authenticated()
}
```

## Per-handler permission check

For fine-grained checks inside a handler, read the claims directly:

```kotlin
@GetMapping("/documents")
fun listDocuments(@AuthenticationPrincipal auth: HearthAuthentication): ResponseEntity<*> {
    if (!auth.claims.hasPermission("docs.read")) {
        return ResponseEntity.status(403).build<Nothing>()
    }
    return ResponseEntity.ok(mapOf("docs" to emptyList<Any>()))
}
```

## Override the auto-configured client

Declare a `@Bean HearthClient` to customise the client (e.g. longer JWKS TTL, different timeout).
The auto-configured bean is skipped because of `@ConditionalOnMissingBean`:

```kotlin
import io.hearth.sdk.HearthClient
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class HearthConfig {

    @Bean
    fun hearthClient(): HearthClient = HearthClient(
        issuerUrl     = System.getenv("HEARTH_URL"),
        realmId       = System.getenv("HEARTH_REALM"),
        clientId      = System.getenv("HEARTH_CLIENT_ID"),
        clientSecret  = System.getenv("HEARTH_CLIENT_SECRET"),
        jwksTtl       = 600_000L,   // 10-minute JWKS cache
        httpTimeoutMs = 5_000L,
    )
}
```

## `application.yml` properties reference

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `hearth.issuer-url` | `String` | *(required)* | Hearth server base URL. Auto-configuration activates when set. |
| `hearth.client-id` | `String?` | `null` | OAuth client ID. Optional for verification-only use. |
| `hearth.client-secret` | `String?` | `null` | Client secret. Required for introspection or client-credentials. |
| `hearth.realm-id` | `String?` | `null` | Realm ID for permission-decision and magic-link flows. |
| `hearth.jwks-ttl-ms` | `Long?` | SDK default | JWKS cache TTL in milliseconds. |
| `hearth.http-timeout-ms` | `Long` | `10000` | HTTP connect + read timeout in milliseconds. |

## Authentication flow

| Request state | Filter behavior |
|--------------|----------------|
| No `Authorization: Bearer` header | Request passes through; Spring Security issues `401` for protected routes |
| Token with invalid signature | `SecurityContextHolder` cleared; `401 Unauthorized` returned immediately |
| Expired token | `SecurityContextHolder` cleared; `401 Unauthorized` returned immediately |
| Valid token | `HearthAuthentication` stored in `SecurityContextHolder`; filter chain continues |

## API reference

### `HearthJwtAuthenticationFilter`

```kotlin
class HearthJwtAuthenticationFilter(
    private val client: HearthClient,
) : OncePerRequestFilter()
```

Spring Security filter. Register with
`.addFilterBefore(filter, UsernamePasswordAuthenticationFilter::class.java)`.

### `HearthAuthentication`

```kotlin
class HearthAuthentication(
    private val rawToken: String,
    val claims: Claims,
) : AbstractAuthenticationToken(buildAuthorities(claims))
```

Spring `Authentication` token backed by a verified Hearth JWT. Retrieve with
`@AuthenticationPrincipal HearthAuthentication auth` or
`SecurityContextHolder.getContext().authentication as HearthAuthentication`.

Granted authorities:
- `ROLE_<role>` for each value in `claims.roles()`
- `<permission>` (verbatim) for each value in `claims.permissions()`

### `HearthSecurityAutoConfiguration`

Activates when all three conditions hold:
- `hearth.issuer-url` is set in application properties.
- The application context is a Servlet web application (not WebFlux).
- `HearthClient` is on the classpath.

Registers `HearthClient` and `HearthJwtAuthenticationFilter` as `@ConditionalOnMissingBean` beans.

## Next steps

- [Kotlin SDK quickstart](./kotlin.md) — `HearthClient`, PKCE login, RBAC checks, session revocation
- [Ktor adapter](./kotlin-ktor.md) — `HearthAuth` plugin and `HearthPrincipal` for Ktor
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Permission delivery modes](/docs/permission-delivery) — Embedded vs Introspection vs Decision
- [Kotlin SDK README](https://github.com/hearth-auth/hearth/blob/main/sdks/kotlin/README.md) — full API surface
