# Changelog

All notable changes to `hearth-go` are documented here.

## [Unreleased]

### Added
- **`Client.CheckPermission(ctx, token, req)`** — calls `POST /oauth/authorize` (the
  decision endpoint, HEA-921/HEA-922) and returns whether the token holder has
  the requested permission. Fail-closed: network errors return `allowed=false` (HEA-925).
- **`Client.Introspect(ctx, req)`** — calls `POST /introspect` (RFC 7662) and returns
  the live claim set including the echoed `mode` field (HEA-925).
- **`RequirePermission(c, permission, cfg)`** — mode-aware `http.Handler` middleware
  factory. Supports three strategies controlled by `cfg.ExpectedMode`:
  - `ModeEmbedded` — decodes JWT claims locally; no network call.
  - `ModeIntrospection` — calls `/introspect`; verifies echoed mode matches
    `ExpectedMode` and rejects with `ModeMismatchError` on mismatch.
  - `ModeDecision` — calls `/oauth/authorize`; fail-closed on network errors.
  The middleware **never** silently falls back from decision/introspection to
  local checks based on whether `permissions` is present in the token (HEA-925).
- **`AccessTokenAuthorizationMode`** type with constants `ModeEmbedded`,
  `ModeIntrospection`, `ModeDecision`.
- **`ModeMismatchError`** — returned when introspection echoes a mode that differs
  from the configured `ExpectedMode`.
- **`AuthorizationDeniedError`** — returned when `CheckPermission` is called directly
  and the decision endpoint returns `allowed=false`.
- **`IntrospectRequest` / `IntrospectResponse`** types.
- **`CheckPermissionRequest` / `CheckPermissionResponse`** types.
- **`MiddlewareConfig`** type for configuring `RequirePermission`.

### Changed
- SDK brought into conformance with the [Hearth SDK Common Specification](../../docs/specs/SDK.md).
- All 9 required error types from spec §5 are now exported.
- Full Claims API (spec §4) implemented on verified token objects.
- JWKS caching follows the 5-rule contract from spec §2.
- README updated with installation, quickstart, and troubleshooting sections (spec §10).
