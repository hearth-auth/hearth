# hearth-spring

Spring Security filter and auto-configuration for [Hearth](https://github.com/hearth-auth/hearth) JWT authentication.

Validates `Authorization: Bearer <jwt>` headers using the Hearth JWKS endpoint and populates the Spring Security context with a `HearthAuthentication` token.

## Requirements

- Java 17+
- Spring Boot 3.x
- Spring Security 6.x

## Installation

Add to your Gradle build:

```kotlin
dependencies {
    implementation("io.hearth:hearth-spring:0.1.0")
    implementation("org.springframework.boot:spring-boot-starter-security")
}
```

## Quick Start

### 1. Configure `application.yml`

```yaml
hearth:
  issuer-url: https://auth.example.com   # required — base URL of your Hearth server
  realm-id: my-realm                      # optional — required for permission-decision mode
  client-id: my-resource-server           # optional — required for introspection
  client-secret: s3cr3t                   # optional — required for introspection
```

### 2. (Optional) Override the security chain

With `hearth.issuer-url` set you are already done. The adapter installs a stateless
bearer-token `SecurityFilterChain`: CSRF off, no session, the Hearth filter in place,
every request authenticated, and a `HearthAuthenticationEntryPoint` that answers a
missing or unusable token with **`401`** and `WWW-Authenticate: Bearer`.

Declare your own `SecurityFilterChain` only when you need public routes or per-route
authorities — doing so replaces the default entirely, **including the entry point**:

```kotlin
import io.hearth.sdk.spring.HearthJwtAuthenticationFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
class SecurityConfig {

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        hearthFilter: HearthJwtAuthenticationFilter,      // auto-configured from application.yml
        hearthEntryPoint: AuthenticationEntryPoint,       // auto-configured
    ): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(hearthFilter, UsernamePasswordAuthenticationFilter::class.java)
            .authorizeHttpRequests { auth ->
                auth.requestMatchers("/public/**").permitAll()
                auth.anyRequest().authenticated()
            }
            // Required. Spring Security registers an authentication entry point only
            // for `httpBasic`, `formLogin` or `oauth2ResourceServer`. A chain with
            // none of those falls back to `Http403ForbiddenEntryPoint`, so a request
            // carrying no token at all is answered `403` with no `WWW-Authenticate`
            // header instead of `401`.
            .exceptionHandling { it.authenticationEntryPoint(hearthEntryPoint) }
        return http.build()
    }
}
```

### 3. Access the token in controllers

```kotlin
import io.hearth.sdk.spring.HearthAuthentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class MeController {

    @GetMapping("/me")
    fun me(@AuthenticationPrincipal auth: HearthAuthentication): Map<String, Any> =
        mapOf(
            "sub"         to auth.claims.subject(),
            "roles"       to auth.claims.roles(),
            "permissions" to auth.claims.permissions(),
        )
}
```

## Permission Checks

Permission strings embedded in the JWT are exposed as Spring `GrantedAuthority` values, so you can use them in `authorizeHttpRequests`:

```kotlin
.authorizeHttpRequests { auth ->
    auth.requestMatchers("/admin/**").hasAuthority("admin.write")
    auth.requestMatchers("/docs/**").hasAuthority("docs.read")
    auth.anyRequest().authenticated()
}
```

Roles receive the standard Spring `ROLE_` prefix, enabling `hasRole("admin")` / `hasAuthority("ROLE_admin")`:

```kotlin
.requestMatchers("/management/**").hasRole("admin")
```

## Configuration Reference

| Property | Default | Description |
|---|---|---|
| `hearth.issuer-url` | — | **Required.** Base URL of your Hearth server. |
| `hearth.client-id` | `null` | OAuth client ID (required for introspection). |
| `hearth.client-secret` | `null` | OAuth client secret (required for introspection). |
| `hearth.realm-id` | `null` | Realm ID for permission-decision and magic-link flows. |
| `hearth.jwks-ttl-ms` | SDK default | JWKS key cache TTL in milliseconds. |
| `hearth.http-timeout-ms` | `10000` | HTTP connect/read timeout in milliseconds. |

## Overriding Auto-configuration

Declare your own `@Bean` to replace any auto-configured bean — the client, the entry
point, the filter, or the whole `SecurityFilterChain`:

```kotlin
@Bean
fun hearthClient(): HearthClient =
    HearthClient(
        issuerUrl = "https://auth.example.com",
        clientId = "my-app",
        jwksTtl = 300_000L,   // custom 5-minute JWKS cache
    )

@Bean
fun hearthJwtAuthenticationFilter(client: HearthClient): HearthJwtAuthenticationFilter =
    HearthJwtAuthenticationFilter(client)
```

## Filter Behaviour

| Scenario | Result |
|---|---|
| No `Authorization` header | Passes through — the chain's `AuthenticationEntryPoint` answers. The auto-configured `HearthAuthenticationEntryPoint` sends `401` + `WWW-Authenticate: Bearer`. A hand-written chain that omits it gets Spring Security's fallback `403`. |
| `Authorization: Bearer <valid-jwt>` | Sets `HearthAuthentication` in `SecurityContextHolder`, continues chain. |
| `Authorization: Bearer <expired-jwt>` | Clears context, returns `401` + `WWW-Authenticate: Bearer error="invalid_token"` immediately. |
| `Authorization: Bearer <invalid-jwt>` | Clears context, returns `401` + `WWW-Authenticate: Bearer error="invalid_token"` immediately. |

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
