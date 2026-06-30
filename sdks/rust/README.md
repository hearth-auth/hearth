# Hearth Rust SDK

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/specs/SDK.md).

Rust SDK for the [Hearth](https://github.com/hearth-auth/hearth) identity platform.

## Installation

> **crates.io status:** `hearth-sdk` is not yet published to crates.io (trusted-publishing
> configuration pending, [HEA-1478](/HEA/issues/HEA-1478)). Install from git or a local path clone.

Add to your `Cargo.toml`:

```toml
[dependencies]
# Install from the git repository (recommended):
hearth-sdk = { git = "https://github.com/hearth-auth/hearth", tag = "v1.0.0", package = "hearth-sdk" }

# Or from a local path clone of the monorepo:
# hearth-sdk = { path = "/path/to/hearth/sdks/rust" }

# Enable Tower middleware for resource-server use:
# hearth-sdk = { git = "https://github.com/hearth-auth/hearth", tag = "v1.0.0", features = ["tower-middleware"] }
```

## Quickstart

```rust
use hearth_sdk::HearthClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HearthClient::new("https://hearth.example.com", "my-realm");

    // Exchange an auth code for tokens
    let tokens = client.exchange_code("code", "client_id", "client_secret", "https://...", None).await?;

    // Local RBAC predicate (no network call)
    let allowed = HearthClient::has_permission(&tokens.access_token, "documents.read")?;

    Ok(())
}
```

## Permission Delivery Modes

Hearth supports three modes for how authorization data reaches your resource server.
The mode must match the `access_token_authorization` field configured on the OAuth client.

| Mode | How it works | Network calls |
|------|--------------|---------------|
| `Embedded` (default) | RBAC claims baked into the JWT at issuance | None |
| `Introspection` | JWT carries only identity; resource server calls `/introspect` | Per-request |
| `Decision` | JWT carries only identity; resource server calls `POST /oauth/authorize` | Per-request |

> **Design constraint**: the SDK never infers mode from whether `permissions` is present
> in the token. Mode must always be configured explicitly (HEA-921).

### Programmatic check

```rust
use hearth_sdk::{HearthClient, AccessTokenAuthorization, CheckPermissionOpts};

let client = HearthClient::new("https://hearth.example.com", "my-realm");

// Embedded — local check, no network
let allowed = client.check_permission(
    &access_token,
    "documents.write",
    AccessTokenAuthorization::Embedded,
    CheckPermissionOpts::default(),
).await?;

// Decision — calls POST /oauth/authorize
let allowed = client.check_permission(
    &access_token,
    "documents.write",
    AccessTokenAuthorization::Decision,
    CheckPermissionOpts::default(),
).await?;

// Introspection — calls POST /introspect with client credentials
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

### Tower middleware (feature `tower-middleware`)

```rust
use hearth_sdk::{HearthClient, AccessTokenAuthorization, CheckPermissionOpts};
use hearth_sdk::middleware::RequirePermissionLayer;

let client = HearthClient::new("https://hearth.example.com", "my-realm");

let app = axum::Router::new()
    .route("/docs", axum::routing::post(create_doc))
    .layer(RequirePermissionLayer::new(
        client,
        "documents.write",
        AccessTokenAuthorization::Decision,
        CheckPermissionOpts::default(),
    ));
```

HTTP responses from the middleware:

| Outcome | Status |
|---------|--------|
| Missing `Authorization` header | `401 Unauthorized` |
| Permission denied or mode mismatch | `403 Forbidden` |
| Decision endpoint unreachable (fail-closed) | `503 Service Unavailable` |
| Allowed | Forwarded to downstream handler |

### Raw introspection

```rust
let resp = client.introspect(&access_token, "client-id", "client-secret").await?;
if resp.active {
    println!("Mode: {:?}", resp.mode);
    println!("Permissions: {:?}", resp.permissions);
}
```

## API Reference

### `HearthClient`

| Method | Description |
|--------|-------------|
| `HearthClient::new(base_url, realm_id)` | Construct a new client |
| `check_permission(token, permission, mode, opts)` | Mode-aware async permission check |
| `introspect(token, client_id, client_secret)` | Call `POST /introspect` (RFC 7662) |
| `has_permission(token, permission)` | Local JWT decode check (sync) |
| `has_role(token, role)` | Local JWT decode check (sync) |
| `in_group(token, group_slug)` | Local JWT decode check (sync) |
| `authorize(...)` | Begin OAuth authorization code flow |
| `exchange_code(...)` | Exchange auth code for tokens |
| `refresh_tokens(...)` | Refresh an access token |
| `userinfo(access_token)` | Fetch OIDC UserInfo |
| `jwks()` | Fetch realm JWKS |

### Claims API (spec §4)

| Method | Returns |
|--------|---------|
| `subject()` | `&str` |
| `issuer()` | `&str` |
| `audiences()` | `Vec<String>` |
| `expiry()` | `Option<i64>` |
| `issuedAt()` | `Option<i64>` |
| `jwtID()` | `Option<&str>` |
| `scopes()` | `Vec<String>` |
| `hasScope(s)` | `bool` |
| `hasRole(r)` | `bool` |
| `hasPermission(p)` | `bool` |
| `get(claim)` | `Option<&serde_json::Value>` |

### Error Types (spec §5)

| Type | When raised |
|------|-------------|
| `ConfigurationError` | Missing or invalid config |
| `DiscoveryError` | OIDC discovery endpoint unreachable |
| `JWKSFetchError` | JWKS endpoint unreachable or invalid |
| `TokenExpiredError` | `exp` in the past |
| `TokenNotYetValidError` | `nbf` in the future |
| `TokenInvalidError` | Signature invalid or malformed JWT |
| `TokenIssuerError` | `iss` mismatch |
| `TokenAudienceError` | `aud` mismatch |
| `IntrospectionError` | Introspection endpoint error |
| `ModeMismatch` | Server echoed a different mode than configured |
| `AuthorizationFailed` | Decision endpoint network/parse error (fail-closed) |

## Troubleshooting

**`DiscoveryError` on startup** — verify the base URL is reachable and returns a valid `/.well-known/openid-configuration` document.

**`ModeMismatch` on introspection** — the token was issued by a client configured for a different `access_token_authorization` mode. Ensure the SDK's `expected_mode` matches the OAuth client's server-side configuration.

**`AuthorizationFailed` (503 from middleware)** — the Decision-mode `/oauth/authorize` endpoint is unreachable. Check connectivity to the Hearth server. The SDK is fail-closed: when in doubt, access is denied.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Refresh the token or re-authenticate.

**`TokenInvalidError`** — the JWT signature is malformed. Persistent failures indicate a key mismatch.

**`TokenAudienceError`** — the token's `aud` claim does not match. Verify `client_id` configuration.

## Spec Conformance

This SDK is audited against the [Hearth SDK Common Specification](../../docs/specs/SDK.md). CI enforces conformance on every PR via `scripts/check-sdk-conformance.sh`.

---

## Agent Authentication (M5)

Enable `agent_auth.capabilities.identity = true` (and `advanced = true` for AATs + transaction tokens) in `hearth.yaml`. The Rust SDK surfaces the agent-auth REST endpoints via the same `HearthClient` low-level methods.

Key endpoints (all require an admin bearer token):

| Operation | Method | Path |
|-----------|--------|------|
| Create agent | `POST` | `/v1/agents` |
| Issue API key | `POST` | `/v1/agents/{id}/credentials/keys` |
| Agent Card | `GET` | `/.well-known/agent.json?agent_id=…` |
| Issue AAT | `POST` | `/v1/aats` |
| Derive child AAT | `POST` | `/v1/aats/derive` |
| Issue txn token | `POST` | `/v1/transaction-tokens` |
| Consume txn token | `POST` | `/v1/transaction-tokens/consume` |

For DPoP proof construction in Rust, use the `ring` crate (`ECDSA_P256_SHA256_FIXED_SIGNING`). The proof JWT header must set `typ: "dpop+jwt"` and include the public key as a JWK. See `tests/dpop.rs` in the main crate for a working example.

For the full surface (DPoP flow, RFC 8693 exchange, AAT lifecycle, draft-tracking owner), see the [TypeScript SDK README](../typescript/README.md#agent-authentication-m5).

## License

MIT
