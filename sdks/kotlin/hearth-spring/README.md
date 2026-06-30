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

### 2. Wire the filter into your security chain

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
        hearthFilter: HearthJwtAuthenticationFilter,   // auto-configured from application.yml
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

Declare your own `@Bean` to replace either auto-configured bean:

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
| No `Authorization` header | Passes through — Spring Security's `ExceptionTranslationFilter` issues 401 for protected routes. |
| `Authorization: Bearer <valid-jwt>` | Sets `HearthAuthentication` in `SecurityContextHolder`, continues chain. |
| `Authorization: Bearer <expired-jwt>` | Clears context, returns HTTP 401 immediately. |
| `Authorization: Bearer <invalid-jwt>` | Clears context, returns HTTP 401 immediately. |

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
