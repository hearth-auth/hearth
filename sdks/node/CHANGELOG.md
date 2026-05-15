# Changelog

All notable changes to `@hearth/node` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-05-15

### Added

- `HearthClient` — unified entry point with OIDC auto-discovery from `issuer_url`
- `verifyToken(token)` — RS256/ES256 JWT verification via JWKS with 5-rule cache contract
- `introspect(token)` — RFC 7662 token introspection with full `IntrospectionResult` shape
- Claims API — `VerifiedToken` with typed accessors (`subject()`, `issuer()`, `audience()`, `issuedAt()`, `expiresAt()`, `notBefore()`, `scope()`, `scopes()`, `get()`, `raw()`) and `hasScope()`, `hasRole()`, `hasPermission()` helpers
- Full error taxonomy: `HearthError`, `ConfigurationError`, `DiscoveryError`, `JwksFetchError`, `TokenVerificationError`, `TokenExpiredError`, `TokenClaimsError`, `IntrospectionError`, `MiddlewareError` — all with cause chaining
- Express and Fastify middleware with Bearer extraction, 401/403 semantics, and `WWW-Authenticate` header
- `WebhookVerifier` — HMAC-SHA256 webhook signature verification with timestamp freshness
- `HearthObservability` — Prometheus metrics, `/healthz`, `/readyz`, and `/metrics` endpoints
- Integration tests: JWKS key rotation, clock skew boundary, ≥ 80% coverage gate
- GitHub Actions CI workflow

### Security

- `HearthError` messages sanitized — raw token values and secrets are never included
- `hasScope()`, `hasRole()`, `hasPermission()` use timing-safe comparison
- `jose` dependency pinned with exact version
- Dependabot enabled for `sdks/node/`
