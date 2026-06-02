# Changelog

All notable changes to `hearth-rust` are documented here.

## [Unreleased]

### Added
- **Mode-aware permission enforcement** (HEA-927): `HearthClient::check_permission(token, permission, mode, opts)`
  resolves permissions according to an explicit `AccessTokenAuthorization` mode —
  `Embedded` (local JWT decode), `Introspection` (live `/introspect` call), or
  `Decision` (per-request `POST /oauth/authorize`). Mode is always explicit; the SDK
  never infers mode from token contents.
- **`HearthClient::introspect(token, client_id, client_secret)`**: calls `POST /introspect`
  (RFC 7662) and returns the full `IntrospectionResponse` including live `permissions`,
  `roles`, `groups`, and the echoed `mode`.
- **`AccessTokenAuthorization` enum**: mirrors the server-side field on `OAuthClient`;
  `Embedded` (default), `Introspection`, `Decision`.
- **`IntrospectionResponse` type**: full RFC 7662 response with Hearth extensions
  (`mode`, `permissions`, `roles`, `groups`).
- **`PermissionCheckResponse` type**: `{ allowed: bool }` from `POST /oauth/authorize`.
- **`CheckPermissionOpts`**: options for `check_permission` — `organization_id`, `resource`,
  `client_credentials` (required for `Introspection` mode).
- **`OAuthClient.access_token_authorization`** field added to the SDK type.
- **`HearthClient` is now `Clone`** — cheap ref-count increment on the inner reqwest client.
- **`HearthError::ModeMismatch`**: returned when the server echoes a mode different from
  the SDK's `expected_mode`; never silently falls back.
- **`HearthError::AuthorizationFailed`**: returned on Decision-mode network errors;
  fail-closed.
- **`tower-middleware` feature**: adds `middleware::RequirePermissionLayer` — a Tower
  [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that enforces a single
  permission on every request.  Returns `401` (missing token), `403` (denied or mode
  mismatch), or `503` (decision endpoint unreachable).  Requires `tower` + `http` deps
  (enabled automatically with the feature).

### Changed
- Crate version bumped to `0.2.0`.

### Added (earlier)
- Initial SDK implementation conforming to the [Hearth SDK Common Specification](../../docs/specs/SDK.md).
- All 9 required error types from spec §5 added to `HearthError` enum: `ConfigurationError`, `DiscoveryError`, `JWKSFetchError`, `TokenExpiredError`, `TokenNotYetValidError`, `TokenInvalidError`, `TokenIssuerError`, `TokenAudienceError`, `IntrospectionError`.
- `Claims` struct (spec §4) with typed accessors: `subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`, `scopes`, `hasScope`, `hasRole`, `hasPermission`.
