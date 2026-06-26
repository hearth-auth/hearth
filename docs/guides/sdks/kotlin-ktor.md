---
title: Authenticate a Ktor app with Hearth
sidebar_label: Ktor
description: >
  Protect Ktor routes with Hearth-issued JWT tokens using the dedicated HearthAuth plugin.
  Covers the hearth() DSL, HearthPrincipal, per-route permission enforcement, and
  injecting a shared HearthClient.
---

# Authenticate a Ktor app with Hearth

This guide is for **Kotlin developers building Ktor applications** who want to gate routes behind
Hearth-issued tokens. The `hearth-ktor` module ships a dedicated Ktor authentication plugin that
integrates with Ktor's `Authentication` plugin and exposes verified JWT claims as a typed
`HearthPrincipal` on every authenticated call.

:::note[Dedicated adapter vs generic middleware]
This page covers the `hearth-ktor` adapter, which hooks into Ktor's `Authentication` plugin DSL.
For **Spring Boot**, see the [Spring Security adapter](./kotlin-spring.md). For raw permission
checking in WebFlux or other JVM frameworks, use [`requirePermission()`](./kotlin.md#permission-checking-middleware)
from `hearth-core`.
:::

## Install

Add `hearth-ktor` alongside your Ktor server dependencies in `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.hearth:hearth-ktor:1.0.0")
    implementation("io.ktor:ktor-server-auth:2.3.12")
    implementation("io.ktor:ktor-server-core:2.3.12")
    // ... your choice of Ktor engine (CIO, Netty, etc.)
}
```

**Requirements:** JVM 17+, Kotlin 1.9+, Ktor 2.3.x, `kotlinx.coroutines` 1.7+.

`hearth-ktor` declares `ktor-server-auth` and `ktor-server-core` as `compileOnly` dependencies so
you control the Ktor version; `hearth-core` (the base Hearth SDK) is pulled in transitively.

## Register the Hearth plugin

Install the `Authentication` plugin and call the `hearth` DSL extension to register a provider.
Supply at minimum `issuerUrl` — the Hearth server's base URL:

```kotlin
import io.hearth.sdk.ktor.hearth
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication

fun Application.configureAuth() {
    install(Authentication) {
        hearth("hearth") {
            issuerUrl = System.getenv("HEARTH_ISSUER_URL")  // e.g. https://auth.example.com
            realmId   = System.getenv("HEARTH_REALM_ID")
        }
    }
}
```

The provider fetches the JWKS document from `{issuerUrl}/.well-known/openid-configuration` on
first use. Keys are cached by `kid`; a cache miss triggers one re-fetch before failing (transparent
key rotation). Pass `name = null` to register as the **default** (unnamed) provider, which is used
by `authenticate { }` blocks without an explicit name.

## Protect routes with `authenticate`

Wrap any route or route group with `authenticate("hearth")` to require a valid bearer token:

```kotlin
import io.hearth.sdk.ktor.HearthPrincipal
import io.hearth.sdk.ktor.hearth
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.configureRouting() {
    install(Authentication) {
        hearth("hearth") {
            issuerUrl = System.getenv("HEARTH_ISSUER_URL")
        }
    }

    routing {
        // Unprotected — no token required
        get("/health") { call.respondText("ok") }

        authenticate("hearth") {
            get("/me") {
                val principal = call.principal<HearthPrincipal>()!!
                call.respond(mapOf(
                    "sub"   to principal.claims.subject(),
                    "roles" to principal.claims.roles(),
                ))
            }
        }
    }
}
```

When `Authorization: Bearer <jwt>` is absent or the token fails verification, Ktor triggers the
registered challenge and returns `401 Unauthorized`. The handler body only runs when the token is
valid and `HearthPrincipal` is present.

## Access claims in a route handler

`call.principal<HearthPrincipal>()` gives you both the decoded claims and the raw bearer string:

```kotlin
authenticate("hearth") {
    get("/docs") {
        val p = call.principal<HearthPrincipal>()!!

        val subject = p.claims.subject()                // "sub" claim
        val roles   = p.claims.roles()                  // List<String>
        val perms   = p.claims.permissions()            // List<String>
        val inEng   = p.claims.inGroup("engineering")   // Boolean

        // Permission check — reads embedded JWT claims, no network call
        if (!p.claims.hasPermission("docs.read")) {
            call.respond(HttpStatusCode.Forbidden)
            return@get
        }

        call.respond(mapOf("docs" to emptyList<Any>()))
    }
}
```

`p.rawToken` holds the original bearer string. Forward it to downstream services as a delegation
credential without re-parsing.

## Inject a pre-built `HearthClient`

In tests or when sharing a single client across providers, set the `client` property directly.
When `client` is non-null, all other properties (`issuerUrl`, `clientId`, `clientSecret`,
`realmId`) are ignored:

```kotlin
import io.hearth.sdk.HearthClient
import io.hearth.sdk.ktor.hearth

val hearthClient = HearthClient(
    issuerUrl = "https://auth.example.com",
    realmId   = "my-realm",
)

install(Authentication) {
    hearth("api") {
        client = hearthClient   // shared instance; properties above are ignored
    }
}
```

## Configuration reference

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `issuerUrl` | `String` | `""` | Hearth server base URL. Required unless `client` is set. |
| `clientId` | `String?` | `null` | OAuth client ID. Optional for verification-only use. |
| `clientSecret` | `String?` | `null` | Client secret. Required for introspection or client-credentials. |
| `realmId` | `String?` | `null` | Realm ID sent as `X-Realm-ID` on realm-scoped API calls. |
| `jwksTtlMs` | `Long` | `300000` | JWKS cache TTL in milliseconds (5 minutes). |
| `httpTimeoutMs` | `Long` | `10000` | HTTP connect and read timeout in milliseconds. |
| `client` | `HearthClient?` | `null` | Pre-built client. When set, all other properties are ignored. |

## Authentication flow

| Request state | Ktor response |
|--------------|---------------|
| Missing `Authorization: Bearer` header | `401 Unauthorized` (via challenge) |
| Token with invalid signature | `401 Unauthorized` (via challenge) |
| Expired token | `401 Unauthorized` (via challenge) |
| Valid token, `hasPermission()` returns `false` | `403 Forbidden` (your route handler) |
| Valid token, all checks pass | Handler runs; `HearthPrincipal` available |

## API reference

### `hearth` DSL extension

```kotlin
fun AuthenticationConfig.hearth(
    name: String? = null,
    configure: HearthAuthConfig.() -> Unit,
)
```

Registers a `HearthAuthProvider` under `name`. Call inside `install(Authentication) { }`.

### `HearthPrincipal`

```kotlin
data class HearthPrincipal(
    val rawToken: String,
    val claims: Claims,
) : Principal
```

Retrieve with `call.principal<HearthPrincipal>()` inside an `authenticate` block. Returns `null`
outside an authenticated context.

### `HearthAuthConfig`

```kotlin
class HearthAuthConfig(name: String?) : AuthenticationProvider.Config(name) {
    var issuerUrl: String       // required unless `client` is set
    var clientId: String?
    var clientSecret: String?
    var realmId: String?
    var jwksTtlMs: Long         // default: 300_000
    var httpTimeoutMs: Long     // default: 10_000
    var client: HearthClient?   // overrides all properties above when non-null
}
```

## Next steps

- [Kotlin SDK quickstart](./kotlin.md) — `HearthClient`, PKCE login, RBAC checks, session revocation
- [Spring Security adapter](./kotlin-spring.md) — `HearthJwtAuthenticationFilter` and Spring Boot auto-configuration
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Permission delivery modes](/docs/permission-delivery) — Embedded vs Introspection vs Decision
- [Kotlin SDK README](https://github.com/hearth-auth/hearth/blob/main/sdks/kotlin/README.md) — full API surface
