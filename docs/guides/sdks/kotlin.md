---
title: Kotlin SDK quickstart
sidebar_label: Kotlin
description: Verify Hearth tokens and enforce RBAC in a Kotlin/JVM service. Covers coroutines, Spring WebFlux, Ktor, and the full C8 surface.
---

# Kotlin SDK quickstart

Add token verification and RBAC to a Kotlin/JVM application using the Hearth Kotlin SDK.

## Install

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.hearth-auth:hearth-sdk:1.0.0")
}
```

Or Maven:

```xml
<dependency>
    <groupId>io.hearth-auth</groupId>
    <artifactId>hearth-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

**Requirements:** JVM 17+, Kotlin 1.9+, `kotlinx.coroutines` 1.7+, OkHttp 4.x.

## Start Hearth locally

```bash
make dev
# → binds http://127.0.0.1:8420

curl -X POST http://127.0.0.1:8420/admin/bootstrap
# → { "realm_id": "…", "access_token": "…" }
```

## Initialize the client

```kotlin
import io.hearth.sdk.HearthClient

val client = HearthClient(
    issuerUrl    = "http://127.0.0.1:8420",  // server base URL
    realmId      = "<realm_id>",             // UUID sent as X-Realm-ID on scoped endpoints
    clientId     = "<client_id>",
    clientSecret = "<client_secret>",        // optional — required for M2M/introspection
)
```

All endpoint URLs are auto-discovered from `{issuerUrl}/.well-known/openid-configuration`
on first use. `HearthClient` is coroutine-safe and designed to be created once and shared.

## Auth code flow with PKCE

Use `beginLogin` / `completeLogin` to handle the OAuth callback in two calls:

```kotlin
import io.hearth.sdk.HearthClient

val client = HearthClient(
    issuerUrl    = "https://hearth.example.com",
    clientId     = "<client_id>",
    clientSecret = "<client_secret>",
    realmId      = "<realm_id>",
)

// Login handler — generate PKCE and build the authorization URL
suspend fun handleLogin(session: YourSessionStore): String {
    val result = client.beginLogin(
        redirectUri = "http://localhost:8080/callback",
        scopes      = "openid profile email",
    )
    // Persist state + codeVerifier in your session (one line you own)
    session["state"]        = result.state
    session["codeVerifier"] = result.codeVerifier
    return result.authorizationUrl  // redirect the browser here
}

// Callback handler — exchange the code for tokens
suspend fun handleCallback(code: String, returnedState: String, session: YourSessionStore): TokenResponse {
    check(returnedState == session["state"]) { "state mismatch" }
    return client.completeLogin(
        code         = code,
        codeVerifier = session["codeVerifier"]!!,
        redirectUri  = "http://localhost:8080/callback",
    )
    // tokens.accessToken, tokens.refreshToken, tokens.expiresIn
}
```

## Verify tokens

`verifyToken` performs full Ed25519/EdDSA local signature verification with JWKS caching:

```kotlin
import io.hearth.sdk.errors.TokenExpiredError
import io.hearth.sdk.errors.TokenInvalidError

try {
    val claims = client.verifyToken(accessToken)
    println("user: ${claims.subject()}")
    println("roles: ${claims.roles()}")
} catch (e: TokenExpiredError) {
    // 401 — ask the client to refresh
} catch (e: TokenInvalidError) {
    // 401 — reject the request
}
```

JWKS keys are cached by `kid`; a cache miss triggers one re-fetch before
failing (transparent key rotation). `verifyToken` never falls back to introspection.

## Synchronous RBAC checks

```kotlin
// Reads embedded JWT claims — no network call
val isAdmin = client.hasRole(accessToken, "admin")
val canWrite = claims.hasPermission("documents.write")
val inEng = claims.inGroup("engineering")
```

## Live permission refresh

```kotlin
// Hits GET /v1/me/permissions — reflects role/group changes since token issuance
val perms = client.mePermissions(accessToken)
// perms.roles, perms.groups, perms.permissions
```

## Machine-to-machine (client credentials)

```kotlin
val tokens = client.clientCredentials(scope = "read:reports")
// tokens.accessToken, tokens.expiresIn
```

## Device authorization flow

> **Platform note:** The Kotlin SDK uses `deviceAuthorization()` instead of `startDeviceFlow()`.
> `pollDeviceToken()` does not accept an interval parameter — manage the sleep loop yourself.
> See [§2.5 platform exceptions](../../specs/SDK.md#platform-exceptions).

```kotlin
import io.hearth.sdk.errors.TokenExpiredError

val resp = client.deviceAuthorization(scope = "openid")
println("Visit: ${resp.verificationUri}")
println("Code:  ${resp.userCode}")

var intervalMs = resp.interval * 1000L
var tokens: TokenResponse? = null
while (tokens == null) {
    delay(intervalMs)
    try {
        tokens = client.pollDeviceToken(resp.deviceCode)
        // null means authorization_pending or slow_down — increase interval and retry
        if (tokens == null) intervalMs += 5_000L
    } catch (e: TokenExpiredError) {
        error("device code expired before user approved")
    }
}
```

## Magic-link (passwordless)

> **Platform note:** The Kotlin SDK does not yet expose magic-link **initiation**.
> Use a raw HTTP POST until the method is added. For **completing** the flow once
> the user clicks the link and is redirected back with a magic token:

```kotlin
// Initiate via raw HTTP (temporary — C8 does not include initiation)
val body = """{"email":"user@example.com"}"""
// POST {baseUrl}/v1/{realmSlug}/auth/magic-link with Content-Type: application/json

// Complete the flow after the user clicks the link:
val tokens = client.exchangeMagicLink(magicToken)
// tokens.accessToken, tokens.expiresIn
```

## Session-version revocation

The Kotlin SDK includes `SessionVersionCache` — a coroutine-backed delta-feed
poller that enables sub-second session revocation on the hot path:

```kotlin
import io.hearth.sdk.SessionVersionCache

val svCache = SessionVersionCache(
    client    = client,
    accessToken = serviceToken,
)
svCache.start()  // starts background coroutine

// On every request (hot path — no network):
val isRevoked = !svCache.check(sessionId, sessionVersion)
```

`check()` is synchronous and uses `ConcurrentHashMap`. The background coroutine
calls the session-version delta feed every `pollIntervalMs` (default: 30 s)
and fails closed on staleness.

## WebAuthn / passkeys

```kotlin
// Registration
val options = client.startWebAuthnRegistration(accessToken)
// ... show options to client (browser WebAuthn API) ...
client.finishWebAuthnRegistration(accessToken, credential)

// Authentication
val authOptions = client.startWebAuthnAuthentication()
// ... show options to client ...
val tokens = client.finishWebAuthnAuthentication(credential)
```

## Admin API

```kotlin
import io.hearth.sdk.AdminClient

val admin = AdminClient(
    baseUrl     = "http://127.0.0.1:8420",
    realmId     = "<realm_id>",
    accessToken = adminToken,
)

val user = admin.createUser(CreateUserRequest(
    email = "alice@example.com",
    displayName = "Alice",
))

val page = admin.listUsers(limit = 50)
// page.items: List<User>, page.nextCursor: String?
```

## Error types

| Error | When thrown |
|-------|-------------|
| `ConfigurationError` | Missing or invalid config (e.g. blank `issuerUrl`) |
| `DiscoveryError` | OIDC discovery endpoint unreachable or invalid |
| `JWKSFetchError` | JWKS endpoint unreachable |
| `TokenExpiredError` | `exp` claim is in the past |
| `TokenInvalidError` | Signature invalid, malformed JWT, or algorithm mismatch |
| `TokenIssuerError` | `iss` does not match configured issuer |
| `TokenAudienceError` | `aud` does not contain expected audience |
| `IntrospectionError` | Introspection endpoint error |
| `RequiredActionError` | Token type is `required_action` — user must complete actions |

## Keycloak → Hearth mapping

| Keycloak concept | Hearth Kotlin SDK equivalent |
|-----------------|------------------------------|
| `KeycloakDeployment` adapter config | `HearthClient(issuerUrl, clientId, clientSecret)` |
| `AuthzClient` (UMA/RPT) | `client.checkPermission(token, permission, mode)` |
| Bearer token verifier | `client.verifyToken(token)` |
| Realm roles | `claims.hasRole("admin")` — reads `roles` claim |
| Client roles | Included in `roles` claim; use `hasRole()` |
| Groups | `claims.inGroup("engineering")` — reads `groups` claim |

## Permission-checking middleware

For frameworks without a dedicated adapter, use `requirePermission()` from `hearth-core` to build
a reusable, mode-aware permission gate. The function returns a `PermissionChecker` — a single-method
interface you call with a bearer token string:

```kotlin
import io.hearth.sdk.AccessTokenAuthorizationMode
import io.hearth.sdk.RequirePermissionOptions
import io.hearth.sdk.requirePermission

val docsReadChecker = requirePermission(
    "docs.read",
    RequirePermissionOptions(
        mode   = AccessTokenAuthorizationMode.EMBEDDED,
        client = client,
    ),
)

// In any suspend context — Ktor handler, WebFlux HandlerFilterFunction, etc.
val token = request.headers["Authorization"]?.removePrefix("Bearer ") ?: ""
if (!docsReadChecker.check(token)) {
    // respond 403 Forbidden
}
```

Behavior by mode:

| Mode | `AccessTokenAuthorizationMode` | How it works |
|------|-------------------------------|--------------|
| Embedded (default) | `EMBEDDED` | Decodes `permissions[]` claim locally. Zero network calls. Returns `false` when the claim is absent — never auto-falls-back to a network call. |
| Decision | `DECISION` | Calls `POST /oauth/authorize`. Fail-closed: network errors return `false`. |
| Introspection | `INTROSPECTION` | Calls `POST /realms/{id}/introspect` (RFC 7662). Validates the echoed `mode` field; throws `AuthorizationModeMismatchError` on mismatch. |

`PermissionChecker` is a `fun interface` — create one per permission, share it as a singleton, and
call `.check(token)` on the hot path. For Ktor and Spring Boot, prefer the dedicated adapters below
which handle token extraction and 401/403 responses automatically.

## Framework adapters

| Framework | Module | What it provides |
|-----------|--------|-----------------|
| Ktor | `hearth-ktor` | `hearth { }` DSL, `HearthPrincipal`, `authenticate` block integration |
| Spring Boot (Servlet) | `hearth-spring` | `HearthJwtAuthenticationFilter`, `HearthAuthentication`, Spring Boot auto-configuration |

- [Ktor adapter](./kotlin-ktor.md) — per-route `authenticate("hearth")` and `HearthPrincipal`
- [Spring Security adapter](./kotlin-spring.md) — `HearthJwtAuthenticationFilter` and `@AuthenticationPrincipal`

## Next steps

- [Ktor adapter](./kotlin-ktor.md) — `hearth {}` plugin and `HearthPrincipal` for Ktor
- [Spring Security adapter](./kotlin-spring.md) — filter and auto-config for Spring Boot 3
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [SDK migration from Keycloak](./migration-from-keycloak.md) — side-by-side code comparisons
- [Kotlin SDK README](https://github.com/hearth-auth/hearth/blob/main/sdks/kotlin/README.md) — full API surface
