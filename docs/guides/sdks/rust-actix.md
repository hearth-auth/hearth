---
title: Authenticate an Actix-web app with Hearth
sidebar_label: Actix-web
description: >
  Protect Actix-web routes with Hearth tokens using the dedicated Actix-web middleware adapter.
  Covers HearthActixMiddleware, the RequirePermission extractor, permission delivery modes, and
  composing multiple permission layers.
---

# Authenticate an Actix-web app with Hearth

This guide is for **Rust developers building Actix-web services** who want to gate routes behind
Hearth-issued tokens with per-permission enforcement. The `hearth-sdk` crate ships a dedicated
Actix-web adapter — `hearth_sdk::actix` — that integrates with Actix's `Transform`/`Service` model
and exposes verified JWT claims as a typed `FromRequest` extractor.

:::note[Dedicated adapter vs Tower middleware]
This page covers the `hearth_sdk::actix` adapter (`actix-middleware` feature), which uses Actix-web's
native `Transform` trait. For **Axum** or any other Tower-compatible framework, use
[`RequirePermissionLayer`](./rust.md#tower-middleware-axum) from `hearth_sdk::middleware` instead.
:::

:::note[crates.io status]
`hearth-sdk` is not yet published to crates.io (trusted-publishing configuration pending). Install
from the git repository as shown below.
:::

## Install

Enable the `actix-middleware` feature in your `Cargo.toml`:

```toml
[dependencies]
hearth-sdk = { git = "https://github.com/hearth-auth/hearth", tag = "v1.0.0", features = ["actix-middleware"] }
actix-web = "4"
tokio = { version = "1", features = ["full"] }
```

`actix-middleware` adds `actix-web 4` as a dependency. It is disabled by default so services that
do not use Actix pay no compile cost.

## Concepts

### Permission delivery modes

Every route protection call requires an explicit **mode** — the SDK never infers mode from token
contents. Choose the mode that matches your deployment:

| Mode | `AccessTokenAuthorization` variant | What happens |
|------|------------------------------------|-------------|
| Embedded | `Embedded` | JWT decoded locally; `permissions[]` claim checked. No network call. Fastest path. |
| Introspection | `Introspection` | `POST /introspect` called; echoed mode validated; live permissions checked. |
| Decision | `Decision` | `POST /oauth/authorize` called; `allowed` field read. Fail-closed on network errors. |

### HTTP error responses

| Situation | Status |
|-----------|--------|
| Missing or malformed `Authorization: Bearer` header | `401 Unauthorized` |
| Permission denied or mode mismatch | `403 Forbidden` |
| Decision endpoint unreachable (fail-closed) | `503 Service Unavailable` |
| Allowed | Forwarded to downstream handler |

## Protect a route with `HearthActixMiddleware`

Create a `HearthClient`, then wrap a resource or scope with `HearthActixMiddleware::new`:

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use hearth_sdk::{AccessTokenAuthorization, CheckPermissionOpts, HearthClient};
use hearth_sdk::actix::{HearthActixMiddleware, RequirePermission};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = HearthClient::new("https://hearth.example.com", "my-realm");

    HttpServer::new(move || {
        App::new()
            .service(
                web::resource("/docs")
                    .wrap(HearthActixMiddleware::new(
                        client.clone(),
                        "documents.write",
                        AccessTokenAuthorization::Embedded,
                        CheckPermissionOpts::default(),
                    ))
                    .route(web::post().to(create_doc)),
            )
            // Unprotected route — no middleware
            .route("/health", web::get().to(health))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn create_doc(auth: RequirePermission) -> HttpResponse {
    // auth.claims is the verified JWT payload — decoded locally after the
    // middleware confirms the bearer token. No extra network call here.
    HttpResponse::Ok().json(serde_json::json!({
        "created_by": auth.claims.subject(),
        "roles": auth.claims.roles(),
    }))
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}
```

`HearthActixMiddleware` enforces **one permission per instance**. The `RequirePermission` extractor
in the handler function signature provides the decoded `Claims` — it returns `401 Unauthorized`
automatically if the route is called without the middleware in place.

## Access token claims in a handler

`RequirePermission` exposes a single public field, `claims: Claims`, which gives you structured
access to the verified JWT payload:

```rust
use actix_web::HttpResponse;
use hearth_sdk::actix::RequirePermission;

async fn create_doc(auth: RequirePermission) -> HttpResponse {
    let subject  = auth.claims.subject();                          // "sub" claim
    let org_id   = auth.claims.organizationId();                   // Option<&str>
    let org_grps = auth.claims.orgGroups();                        // Vec<String>

    // Boolean checks — no network call, decoded from embedded claims
    let is_admin   = auth.claims.hasRole("admin");
    let can_write  = auth.claims.hasPermission("documents.write");
    let in_eng     = auth.claims.inGroup("engineering");

    HttpResponse::Ok().json(serde_json::json!({
        "user":     subject,
        "is_admin": is_admin,
    }))
}
```

The claims have already been signature-verified by the middleware before your handler is invoked.

## Compose multiple permission layers

Each `HearthActixMiddleware` enforces one permission. Stack layers to require multiple permissions
on the same resource — Actix evaluates them inside-out, so both must pass:

```rust
use hearth_sdk::actix::HearthActixMiddleware;
use hearth_sdk::{AccessTokenAuthorization, CheckPermissionOpts};

web::resource("/admin/documents")
    .wrap(HearthActixMiddleware::new(
        client.clone(),
        "documents.write",
        AccessTokenAuthorization::Embedded,
        CheckPermissionOpts::default(),
    ))
    .wrap(HearthActixMiddleware::new(
        client.clone(),
        "admin.access",
        AccessTokenAuthorization::Embedded,
        CheckPermissionOpts::default(),
    ))
    .route(web::post().to(admin_create_doc))
```

Both `documents.write` and `admin.access` must be present in the token's `permissions[]` claim.

## Use `Decision` mode for live authorization

`Embedded` mode checks the `permissions[]` claim baked into the token at issuance. When your
deployment uses Hearth's Decision mode (live permission evaluation via `POST /oauth/authorize`),
configure the middleware with `Decision` instead:

```rust
HearthActixMiddleware::new(
    client.clone(),
    "documents.write",
    AccessTokenAuthorization::Decision,
    CheckPermissionOpts::default(),
)
```

On a network error reaching the Decision endpoint, the middleware returns `503 Service Unavailable`
(fail-closed) — the request is never forwarded to the handler. A `403 Forbidden` means the token
is valid but the permission was denied.

## Use `Introspection` mode with client credentials

`Introspection` mode calls `POST /introspect` (RFC 7662) to validate the token live. Provide the
client credentials so the introspection endpoint can authenticate the call:

```rust
use hearth_sdk::{AccessTokenAuthorization, CheckPermissionOpts};

HearthActixMiddleware::new(
    client.clone(),
    "documents.write",
    AccessTokenAuthorization::Introspection,
    CheckPermissionOpts {
        client_credentials: Some((
            "my-client-id".to_string(),
            "my-client-secret".to_string(),
        )),
        ..Default::default()
    },
)
```

The middleware validates that the introspection response echoes the same mode that was configured.
A mode mismatch returns `403 Forbidden`.

## Return Hearth errors from handlers

`HearthActixError` implements `actix_web::ResponseError`, so handlers that call Hearth SDK methods
can propagate errors with `?`:

```rust
use actix_web::{HttpResponse, web};
use hearth_sdk::actix::{HearthActixError, RequirePermission};
use hearth_sdk::HearthClient;

async fn check_admin(
    auth: RequirePermission,
    client: web::Data<HearthClient>,
) -> Result<HttpResponse, HearthActixError> {
    if !auth.claims.hasRole("admin") {
        return Err(HearthActixError::Forbidden);
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user": auth.claims.subject(),
        "admin": true,
    })))
}
```

`HearthActixError` variants map to HTTP status codes automatically:
- `Unauthorized` → `401`
- `Forbidden` → `403`
- `ServiceUnavailable` → `503`

## Protect an entire scope

Wrap a `web::scope` instead of a single resource to protect all routes under a path prefix:

```rust
App::new()
    .service(
        web::scope("/api/v1")
            .wrap(HearthActixMiddleware::new(
                client.clone(),
                "api.access",
                AccessTokenAuthorization::Embedded,
                CheckPermissionOpts::default(),
            ))
            .route("/users", web::get().to(list_users))
            .route("/users/{id}", web::get().to(get_user))
            .route("/documents", web::post().to(create_doc)),
    )
    // Routes outside the scope are unprotected
    .route("/health", web::get().to(health))
```

Every route under `/api/v1` requires the `api.access` permission. Routes outside the scope are
unaffected.

## API reference

### `HearthActixMiddleware`

```rust
HearthActixMiddleware::new(
    client: HearthClient,
    permission: impl Into<String>,
    expected_mode: AccessTokenAuthorization,
    opts: CheckPermissionOpts,
) -> HearthActixMiddleware
```

Actix-web `Transform` factory. Wrap any `Resource` or `Scope` with `.wrap(...)`.

### `RequirePermission`

```rust
pub struct RequirePermission {
    pub claims: Claims,
}
```

Actix-web `FromRequest` extractor. Add as a handler parameter on routes protected by
`HearthActixMiddleware`. Returns `401 Unauthorized` when no verified token is in the request
extensions (i.e. the route lacks the middleware).

### `HearthActixError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum HearthActixError {
    /// Missing or invalid bearer token.
    Unauthorized,
    /// Token is valid but permission was denied, or mode mismatch detected.
    Forbidden,
    /// Hearth authorization service unreachable (fail-closed).
    ServiceUnavailable,
}
```

Implements `actix_web::ResponseError`. Use with `?` in handlers that call `HearthClient` methods.

## Next steps

- [Rust SDK quickstart](./rust.md) — `verify_token`, PKCE auth code flow, Tower/Axum middleware, RBAC checks
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Permission delivery modes](/docs/permission-delivery) — Embedded vs Introspection vs Decision
- [Rust crate reference](https://github.com/hearth-auth/hearth/blob/main/sdks/rust/README.md) — full API surface
