# hearth-ktor

Ktor authentication plugin for [Hearth](https://github.com/hearth-auth/hearth) — validates JWT bearer tokens and exposes a typed `HearthPrincipal` on every authenticated call.

## Installation

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.hearth:hearth-ktor:0.1.0")

    // Bring your own Ktor version (2.3.x tested)
    implementation("io.ktor:ktor-server-auth:2.3.12")
    implementation("io.ktor:ktor-server-core:2.3.12")
}
```

## Quick Start

### 1. Register the provider

```kotlin
import io.hearth.sdk.ktor.HearthPrincipal
import io.hearth.sdk.ktor.hearth
import io.ktor.server.auth.Authentication
import io.ktor.server.application.install

install(Authentication) {
    hearth("api") {
        issuerUrl = "https://auth.example.com"   // required
        clientId  = "resource-server"            // recommended (validates `aud` claim)
    }
}
```

### 2. Protect routes

```kotlin
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.routing.routing
import io.ktor.server.routing.get

routing {
    // Public — no auth required
    get("/health") { call.respondText("ok") }

    // Protected — requires a valid Hearth JWT
    authenticate("api") {
        get("/me") {
            val p = call.principal<HearthPrincipal>()!!
            call.respondText(p.claims.subject())
        }

        get("/admin") {
            val p = call.principal<HearthPrincipal>()!!
            if (!p.claims.hasRole("admin")) {
                call.respond(HttpStatusCode.Forbidden)
                return@get
            }
            call.respondText("Welcome, admin")
        }
    }
}
```

## Configuration Reference

| Property | Type | Default | Description |
|---|---|---|---|
| `issuerUrl` | `String` | `""` | Hearth issuer base URL. Required unless `client` is set. |
| `clientId` | `String?` | `null` | OAuth 2.0 client ID; used for `aud` claim validation. |
| `clientSecret` | `String?` | `null` | OAuth 2.0 client secret. |
| `realmId` | `String?` | `null` | Realm ID for realm-scoped API calls. |
| `jwksTtlMs` | `Long` | `300_000` | JWKS cache TTL in milliseconds (5 min default). |
| `httpTimeoutMs` | `Long` | `10_000` | HTTP timeout in milliseconds (10 s default). |
| `client` | `HearthClient?` | `null` | Inject a pre-built client (useful in tests). |

## Accessing Claims

`HearthPrincipal` exposes the verified `Claims` object:

```kotlin
val p = call.principal<HearthPrincipal>()!!

p.claims.subject()           // "sub" claim
p.claims.roles()             // list of role strings
p.claims.permissions()       // list of permission strings
p.claims.groups()            // list of group slugs
p.claims.hasRole("admin")    // true/false
p.claims.hasPermission("docs.write")  // true/false
p.claims.inOrg("org-id")    // true/false
p.claims.get("custom_claim") // raw value or null

p.rawToken                   // original bearer token string (forward to downstream services)
```

## Multiple Providers

Register multiple named providers to protect different route groups with different issuers or clients:

```kotlin
install(Authentication) {
    hearth("api") {
        issuerUrl = "https://auth.example.com"
        clientId  = "resource-server"
    }
    hearth("admin") {
        issuerUrl = "https://auth.example.com"
        clientId  = "admin-panel"
    }
}

routing {
    authenticate("api")   { get("/api/data") { ... } }
    authenticate("admin") { get("/admin/users") { ... } }
}
```

## Testing

Inject a mock `HearthClient` to avoid network calls in tests:

```kotlin
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.ktor.server.testing.testApplication

@Test
fun `protected route returns subject`() = testApplication {
    val mockClaims = mockk<Claims> {
        every { subject() } returns "user-1"
        every { roles() } returns listOf("reader")
        every { permissions() } returns emptyList()
    }
    val mockClient = mockk<HearthClient> {
        coEvery { verifyToken("valid.jwt") } returns mockClaims
    }

    install(Authentication) {
        hearth("api") { client = mockClient }
    }
    routing {
        authenticate("api") {
            get("/me") { call.respondText(call.principal<HearthPrincipal>()!!.claims.subject()) }
        }
    }

    val resp = client.get("/me") {
        header(HttpHeaders.Authorization, "Bearer valid.jwt")
    }
    assertEquals(HttpStatusCode.OK, resp.status)
    assertEquals("user-1", resp.bodyAsText())
}
```

## License

Apache 2.0 — see [LICENSE](../../../LICENSE).
