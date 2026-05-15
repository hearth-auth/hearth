# Changelog

All notable changes to `@hearth/browser` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-05-15

### Added

- `HearthClient` — unified entry point with OIDC auto-discovery from `issuer_url`
- PKCE authorization code flow: `login()`, `handleCallback()`, `getTokens()`, `refresh()`, `logout()`
- Client-side `verifyToken(token)` — RS256/ES256 JWT verification via JWKS with 5-rule cache contract
- `introspect(token)` — RFC 7662 token introspection
- Claims API — `VerifiedToken` with typed accessors and `hasScope()` helper
- Full error taxonomy: `HearthError`, `ConfigurationError`, `DiscoveryError`, `JwksFetchError`, `TokenVerificationError`, `TokenExpiredError`, `TokenClaimsError`, `IntrospectionError`, `MiddlewareError` — all with cause chaining
- Storage abstraction: `sessionStorage` (default), `localStorage`, in-memory, and custom adapters
- Cross-tab token sync via `BroadcastChannel`
- Configurable `storageKeyPrefix` for multi-tenant isolation
- Silent refresh without user interaction
- WebAuthn helpers: `startRegistration()`, `startAuthentication()`
- Account console APIs: profile, sessions, MFA devices, data export
- `createAccountConsoleRoute()` — route loader/actions wrapper
- Integration tests: JWKS key rotation, clock skew boundary, ≥ 80% coverage gate
- GitHub Actions CI workflow

### Security

- PKCE `code_verifier` generated via `crypto.getRandomValues` (256-bit entropy)
- State parameter validated on callback to prevent CSRF
- `HearthError` messages sanitized — raw token values and secrets are never included
- `jose` dependency pinned with exact version + SHA digest
- Dependabot enabled for `sdks/browser/`
