# Changelog

All notable changes to the Hearth Kotlin/JVM SDK are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- **EdDSA/Ed25519 signature verification** — `TokenVerifier` now correctly verifies JWTs signed
  with Hearth's Ed25519 key. The verifier now uses `Ed25519Verifier(OctetKeyPair)` directly,
  bypassing a `java.security.EdECPublicKey` round-trip that silently corrupted the public-key
  bytes on some JVM/provider combinations (HEA-1563).
- **`iat` future validation** — tokens with an issued-at time more than the allowed clock skew
  (5 s) in the future now correctly throw `TokenNotYetValidError`. `DefaultJWTClaimsVerifier`
  only checked presence, not value; the check is now applied explicitly (HEA-1563).
- **JWKS re-fetch not triggered by claims errors** — a `TokenInvalidError` from claims validation
  (e.g. missing required claim) no longer triggers an unnecessary JWKS re-fetch. Re-fetch is
  reserved for key-miss and signature-mismatch cases (HEA-1563).

### Added

- **Permission delivery modes** (`AccessTokenAuthorizationMode`) — `EMBEDDED`, `INTROSPECTION`,
  and `DECISION` enum, mirroring the modes introduced on the server in HEA-922 (HEA-928).
- **`HearthClient.checkPermission()`** — calls `POST /oauth/authorize` to get a per-request
  permission decision from the server (Decision mode). Fail-closed: any error returns `false`.
  Requires the new `realmId` constructor parameter.
- **`requirePermission()`** — mode-aware `PermissionChecker` factory. Returns a coroutine-safe
  gate that evaluates a permission under the configured mode without silent fallback between modes.
  Documented with Ktor and Spring WebFlux integration patterns (HEA-928).
- **`HearthClient.realmId`** constructor parameter — `X-Realm-ID` header value for
  realm-scoped endpoints.
- **`HearthClient.expectedMode`** constructor parameter — when set, `introspect()` validates
  the `mode` field echoed in the server response and throws `AuthorizationModeMismatchError`
  on mismatch.
- **`IntrospectionResult.mode`** and **`IntrospectionResult.permissions`** — new fields
  parsed from the introspection response (HEA-922 server extensions).
- **`AuthorizationModeMismatchError`** — thrown when the server echoes a mode that differs
  from the SDK's configured expectation.
- **`AuthorizeError`** — thrown when `POST /oauth/authorize` is unreachable or returns non-2xx.

## [0.1.0] — Initial release

- OIDC discovery and JWKS caching
- Ed25519 JWT verification (`verifyToken`)
- RFC 7662 token introspection (`introspect`)
- Authorization Code + PKCE, Refresh Token, Client Credentials, Device Flow, Magic Link
- RBAC helpers: `hasPermission()`, `hasRole()` (local JWT decode)
- Admin API: user and realm CRUD, OAuth client registration
- Full coroutines-first API (`suspend` functions throughout)
