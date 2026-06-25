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

## Auth code flow with PKCE

The Rust SDK handles both the OAuth client-side (initiating authorization) and server-side (verifying incoming tokens). For a backend service that receives tokens from a browser, jump straight to [Verify tokens](#verify-tokens).

For a Rust server that also initiates the PKCE flow (e.g. a CLI or desktop app):

```rust
use hearth_sdk::HearthClient;

let client = HearthClient::new("https://hearth.example.com", "my-realm");

// 1. Start authorization
let auth_resp = client.authorize(hearth_sdk::AuthorizeRequest {
    client_id:             "my-app".into(),
    redirect_uri:          "http://localhost:8080/callback".into(),
    scope:                 "openid profile email".into(),
    state:                 "random-csrf-token".into(),
    code_challenge:        pkce_challenge,
    code_challenge_method: "S256".into(),
    user_id:               None, // omit in production; used in dev mode only
    ..Default::default()
}).await?;

// 2. Exchange the code for tokens (on callback)
let tokens = client.exchange_code(hearth_sdk::TokenRequest {
    client_id:     "my-app".into(),
    code:          auth_resp.code,
    redirect_uri:  "http://localhost:8080/callback".into(),
    code_verifier: pkce_verifier,
}).await?;

// 3. Refresh before expiry
let refreshed = client.refresh_tokens("my-app", &tokens.refresh_token).await?;
```

## Verify tokens

```rust
use hearth_sdk::{HearthClient, AccessTokenAuthorization, CheckPermissionOpts};

let client = HearthClient::new("https://hearth.example.com", "my-realm");

// Synchronous local check — zero network calls, no lock
let allowed = client.has_permission(&access_token, "documents.write");
let is_admin = client.has_role(&access_token, "admin");
let in_eng   = client.in_group(&access_token, "engineering");
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
| `HearthClient::new(base_url, realm_id)` | Construct a new client |
| `has_permission(token, permission)` | Sync local JWT decode — no network |
| `has_role(token, role)` | Sync local JWT decode — no network |
| `in_group(token, group_slug)` | Sync local JWT decode — no network |
| `check_permission(token, perm, mode, opts)` | Async, mode-aware permission check |
| `introspect(token, client_id, client_secret)` | RFC 7662 introspection |
| `authorize(request)` | Begin OAuth authorization code flow |
| `exchange_code(request)` | Exchange auth code for tokens |
| `refresh_tokens(client_id, refresh_token)` | Refresh an access token |
| `userinfo(access_token)` | Fetch OIDC UserInfo claims |
| `jwks()` | Fetch realm JWKS |

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
