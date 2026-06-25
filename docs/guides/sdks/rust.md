---
title: Rust SDK quickstart
sidebar_label: Rust
description: Verify Hearth tokens and enforce RBAC in a Rust service. Covers Axum Tower middleware, async permission checks, and the auth code + PKCE flow.
---

# Rust SDK quickstart

Add token verification and permission checks to a Rust service using `hearth-sdk`.

:::note[crates.io status]
`hearth-sdk` is not yet published to crates.io (trusted-publishing configuration pending). Install from the git repository as shown below.
:::

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
# Recommended: install from the git repository
hearth-sdk = { git = "https://github.com/hearth-auth/hearth", tag = "v1.0.0", package = "hearth-sdk" }

# For Axum / Tower middleware support, enable the feature:
# hearth-sdk = { git = "https://github.com/hearth-auth/hearth", tag = "v1.0.0", features = ["tower-middleware"] }
```

## Build the client

Use `HearthClientBuilder` to configure the client:

```rust
use hearth_sdk::HearthClientBuilder;

let client = HearthClientBuilder::new("https://hearth.example.com")
    .client_id("my-app")
    .client_secret("s3cr3t")
    .build();
```

All endpoint URLs are auto-discovered from `{issuer_url}/.well-known/openid-configuration`.

## Auth code flow with PKCE

The Rust SDK handles both the OAuth client-side (initiating authorization) and server-side (verifying incoming tokens). For a backend service that receives tokens from a browser, jump straight to [Verify tokens](#verify-tokens).

For a Rust CLI or desktop app that initiates the PKCE flow:

```rust
use hearth_sdk::{HearthClientBuilder, pkce::generate_pkce_pair};

let client = HearthClientBuilder::new("https://hearth.example.com")
    .client_id("my-app")
    .build();

let pkce = generate_pkce_pair();

// 1. Build the authorization URL (get authorization_endpoint from discovery)
let discovery = client.discovery().await?;
// ... build URL with pkce.challenge and redirect user ...

// 2. Exchange the code for tokens (on callback)
let tokens = client.exchange_code(hearth_sdk::TokenRequest {
    client_id:     "my-app".into(),
    code:          callback_code,
    redirect_uri:  "http://localhost:8080/callback".into(),
    code_verifier: Some(pkce.verifier),
}).await?;

// 3. Refresh before expiry
let refreshed = client.refresh_tokens("my-app", &tokens.refresh_token.unwrap()).await?;
```

## Verify tokens

`verify_token()` performs full Ed25519/EdDSA local signature verification:

```rust
use hearth_sdk::{HearthClientBuilder, HearthError};

let client = HearthClientBuilder::new("https://hearth.example.com")
    .client_id("my-app")
    .build();

let claims = client.verify_token(&access_token).await?;
println!("user: {}", claims.subject());

// Typed errors:
// HearthError::TokenExpired — exp in the past
// HearthError::TokenInvalid — bad signature or malformed JWT
// HearthError::TokenIssuer  — iss mismatch
// HearthError::TokenAudience — aud mismatch
```

`verify_token()` caches JWKS keys; a `kid` miss triggers one re-fetch before
failing (transparent key rotation). It never falls back to introspection.

## Machine-to-machine (client credentials)

```rust
let client = HearthClientBuilder::new("https://hearth.example.com")
    .client_id("my-service")
    .client_secret("s3cr3t")
    .build();

let tokens = client.client_credentials(None).await?;
// tokens.access_token, tokens.expires_in

// With scope:
let tokens = client.client_credentials(Some("read:users")).await?;
```

## Device authorization flow

```rust
let resp = client.start_device_flow(None).await?;
println!("Visit: {}", resp.verification_uri);
println!("Code:  {}", resp.user_code);

// Poll until approved or expired
loop {
    tokio::time::sleep(Duration::from_secs(resp.interval as u64)).await;
    match client.poll_device_token(&resp.device_code, resp.interval).await {
        Ok(tokens) => {
            println!("access_token: {}", tokens.access_token);
            break;
        }
        Err(HearthError::TokenExpired) => {
            eprintln!("device code expired");
            break;
        }
        Err(e) => return Err(e),
    }
}
```

## Magic-link (passwordless) initiation

> **Platform note:** The Rust SDK uses `initiate_magic_link()` (not `requestMagicLink`). See [§2.5 platform exceptions](../../specs/SDK.md#platform-exceptions).

```rust
client.initiate_magic_link("user@example.com").await?;
// Ok(()) whether or not the email is registered (enumeration resistance)
// Err(HearthError::RateLimitExceeded) on HTTP 429
```

## Synchronous RBAC checks

These decode the JWT locally — no network call, no lock:

```rust
let allowed  = HearthClient::has_permission(&access_token, "documents.write")?;
let is_admin = HearthClient::has_role(&access_token, "admin")?;
let in_eng   = HearthClient::in_group(&access_token, "engineering")?;
```

## Permission delivery modes

The Rust SDK supports all three Hearth permission delivery modes. Configure mode per call via `AccessTokenAuthorization`:

```rust
use hearth_sdk::{HearthClient, AccessTokenAuthorization, CheckPermissionOpts};

let client = HearthClient::new("https://hearth.example.com", "my-realm");

// Embedded — local JWT decode, no network (fastest)
let allowed = client.check_permission(
    &access_token,
    "documents.write",
    AccessTokenAuthorization::Embedded,
    CheckPermissionOpts::default(),
).await?;

// Decision — POST /oauth/authorize (live, fail-closed on errors)
let allowed = client.check_permission(
    &access_token,
    "documents.write",
    AccessTokenAuthorization::Decision,
    CheckPermissionOpts::default(),
).await?;

// Introspection — POST /introspect (RFC 7662), echoed mode validated
let allowed = client.check_permission(
    &access_token,
    "documents.write",
    AccessTokenAuthorization::Introspection,
    CheckPermissionOpts {
        client_credentials: Some(("my-client-id".into(), "my-client-secret".into())),
        ..Default::default()
    },
).await?;
```

## Tower middleware (Axum)

Enable the `tower-middleware` feature, then apply `RequirePermissionLayer` to any Axum router:

```toml
hearth-sdk = { git = "https://github.com/hearth-auth/hearth", tag = "v1.0.0", features = ["tower-middleware"] }
```

```rust
use hearth_sdk::{HearthClient, AccessTokenAuthorization, CheckPermissionOpts};
use hearth_sdk::middleware::RequirePermissionLayer;

let client = HearthClient::new("https://hearth.example.com", "my-realm");

let app = axum::Router::new()
    .route("/docs", axum::routing::post(create_doc))
    .layer(RequirePermissionLayer::new(
        client,
        "documents.write",
        AccessTokenAuthorization::Embedded,
        CheckPermissionOpts::default(),
    ));
```

| Outcome | HTTP status |
|---------|-------------|
| Missing `Authorization` header | `401 Unauthorized` |
| Permission denied or mode mismatch | `403 Forbidden` |
| Decision endpoint unreachable (fail-closed) | `503 Service Unavailable` |
| Allowed | Forwarded to downstream handler |

## API reference

| Method | Description |
|--------|-------------|
| `HearthClientBuilder::new(issuer_url)` | Start building a client (preferred) |
| `HearthClientBuilder::client_id(id)` | Set OAuth client ID |
| `HearthClientBuilder::client_secret(secret)` | Set OAuth client secret |
| `HearthClientBuilder::build()` | Finalize and return `HearthClient` |
| `verify_token(token)` | Full EdDSA JWKS-backed signature verification (§2) |
| `client_credentials(scope?)` | Client Credentials grant (RFC 6749 §4.4) |
| `start_device_flow(scope?)` | Begin Device Authorization Flow (RFC 8628) |
| `poll_device_token(device_code, interval)` | Poll for device flow completion |
| `initiate_magic_link(email)` | Initiate passwordless magic-link email ⚠ |
| `has_permission(token, permission)` | Sync local JWT decode — no network |
| `has_role(token, role)` | Sync local JWT decode — no network |
| `in_group(token, group_slug)` | Sync local JWT decode — no network |
| `check_permission(token, perm, mode, opts)` | Async, mode-aware permission check |
| `introspect(token)` | RFC 7662 introspection |
| `authorize(request)` | Begin OAuth authorization code flow |
| `exchange_code(request)` | Exchange auth code for tokens |
| `refresh_tokens(client_id, refresh_token)` | Refresh an access token |
| `userinfo(access_token)` | Fetch OIDC UserInfo claims |
| `jwks()` | Fetch realm JWKS |

> ⚠ `initiate_magic_link` is the Rust name for the spec's `requestMagicLink`. See [§2.5 platform exceptions](../../specs/SDK.md#platform-exceptions).

## Error types

| Type | When raised |
|------|-------------|
| `ConfigurationError` | Missing or invalid config |
| `DiscoveryError` | OIDC discovery endpoint unreachable |
| `JWKSFetchError` | JWKS endpoint unreachable or invalid |
| `TokenExpiredError` | `exp` in the past |
| `TokenInvalidError` | Signature invalid or malformed JWT |
| `TokenIssuerError` | `iss` mismatch |
| `TokenAudienceError` | `aud` mismatch |
| `IntrospectionError` | Introspection endpoint error |
| `ModeMismatch` | Server echoed a different mode than configured |
| `AuthorizationFailed` | Decision endpoint error (fail-closed) |

## Next steps

- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [Rust crate reference](https://github.com/hearth-auth/hearth/blob/main/sdks/rust/README.md) — full API surface
