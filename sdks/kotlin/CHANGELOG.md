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

- **`hearth-spring` subproject** — Spring Security filter adapter (`HearthJwtAuthenticationFilter`,
  `HearthAuthentication`, `HearthSecurityAutoConfiguration`, `HearthSecurityProperties`).
  Validates Hearth JWTs and populates the Spring `SecurityContextHolder` with verified claims.
  Spring Boot 3.x auto-configuration activates when `hearth.issuer-url` is set (HEA-1597).
- **PKCE generation helper** (`generatePkce()`) — returns a `PkceResult` with a 32-byte CSPRNG
  verifier (base64url, no padding) and its S256 challenge. Hearth mandates PKCE for all
  authorization-code flows (RFC 9700 §2.1.1) (HEA-1565).
- **`HearthClient.mePermissions()`** — calls `GET /v1/me/permissions` and returns the
  freshly-resolved RBAC claim set for the bearer-token user (`roles`, `groups`, `permissions`,
  `scope`). Reflects server-side changes since the token was issued, unlike the local
  `hasPermission`/`hasRole` helpers (HEA-1565).
- **Session-version cache** (`SessionVersionCache`, `SessionVersionConfig`, `SvCheckResult`) —
  polls `GET /oauth/session-versions/snapshot` on start then polls `GET /oauth/session-versions`
  for deltas at `pollIntervalMs` intervals. Provides fast synchronous `check()` calls on the
  hot path without any per-request network hop. Fail-closed: cache staleness returns `STALE`
  per the configured `onStale` policy (HEA-1565).
- **WebAuthn / Passkey support** — four new methods on `HearthClient`:
  - `startWebAuthnRegistration(accessToken)` → `POST /webauthn/register/begin`
  - `finishWebAuthnRegistration(accessToken, request)` → `POST /webauthn/register/complete`
  - `startWebAuthnAuthentication(userId?)` → `POST /webauthn/auth/begin`
  - `finishWebAuthnAuthentication(request)` → `POST /webauthn/auth/complete`
  Matching types added: `WebAuthnRegistrationBeginResponse`, `WebAuthnRegistrationCompleteRequest`,
  `WebAuthnRegistrationCompleteResponse`, `WebAuthnAuthenticationBeginResponse`,
  `WebAuthnAllowCredential`, `WebAuthnAuthenticationCompleteRequest` (HEA-1565).
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
