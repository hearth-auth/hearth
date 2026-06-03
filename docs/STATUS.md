# Hearth — Implementation Status

> **Generated from repo state on 2026-06-02. Update this file when new surfaces ship.**
>
> This document is a reference, not a roadmap. It lists only what currently exists in the
> repository. Aspirational or planned features are listed under **Roadmap** at the bottom
> and are explicitly marked as not yet implemented.

---

## Core Server

| Component | Status | Location |
|-----------|--------|----------|
| Single-binary Rust server | ✅ Shipped | `src/main.rs`, `src/lib.rs` |
| Embedded storage engine (WAL + memtable + SSTs) | ✅ Shipped | `src/storage/` |
| Identity engine (users, sessions, credentials) | ✅ Shipped | `src/identity/` |
| Claims-based RBAC (roles, groups, permissions) | ✅ Shipped | `src/rbac/` |
| Admin REST API | ✅ Shipped | `src/protocol/http.rs` |
| Admin UI (Axum-rendered templates) | ✅ Shipped | `src/protocol/web/`, `templates/ui/` |
| gRPC service surface | ✅ Shipped | `src/protocol/grpc/`, `proto/` |
| Raft consensus / cluster mode | ✅ Shipped | `src/cluster/` |
| Audit log with SHA-256 hash chain | ✅ Shipped | `src/audit/` |
| Multi-tenancy (realms) | ✅ Shipped | `src/identity/` |
| Organizations (B2B groups) | ✅ Shipped | `src/identity/` |
| Dev mode (in-memory store + mailcatcher) | ✅ Shipped | `--dev` flag |

---

## Authentication Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| OIDC Core 1.0 | ✅ Shipped | Discovery, UserInfo, ID token with nonce |
| OAuth 2.0 Authorization Code + PKCE | ✅ Shipped | PKCE S256 enforced for public clients |
| OAuth 2.0 Client Credentials | ✅ Shipped | |
| OAuth 2.0 Device Authorization Grant | ✅ Shipped | |
| OAuth 2.0 Token Introspection (RFC 7662) | ✅ Shipped | |
| OAuth 2.0 Token Revocation (RFC 7009) | ✅ Shipped | |
| Refresh token rotation | ✅ Shipped | Theft detection via family tracking |
| Dynamic Client Registration (RFC 7591 / 7592) | ✅ Shipped | |
| DPoP sender-constrained tokens (RFC 9449) | ✅ Shipped | `src/identity/dpop.rs` |
| TOTP / MFA | ✅ Shipped | Enrollment, recovery codes, brute-force lockout |
| WebAuthn / Passkeys | ✅ Shipped | Registration, authentication, multi-credential |
| Magic link / Passwordless | ✅ Shipped | Rate limited, enumeration resistant |
| TLS termination (Rustls, TLS 1.3) | ✅ Shipped | HTTP→HTTPS redirect, mTLS |
| FAPI 2.0 (PAR, JAR, JARM, realm enforcement) | ❌ Not implemented | See [docs/guides/fapi2.md](guides/fapi2.md) — roadmap |

---

## Email Transports

| Transport | Status | Config key |
|-----------|--------|------------|
| Log (dev default) | ✅ Shipped | `email.transport: log` |
| SMTP | ✅ Shipped | `email.transport: smtp` |
| SendGrid | ✅ Shipped | `email.transport: sendgrid` |
| Postmark | ✅ Shipped | `email.transport: postmark` |
| Mailgun (US + EU region) | ✅ Shipped | `email.transport: mailgun` |

---

## Keycloak Migration

| Feature | Status | Location |
|---------|--------|----------|
| `hearth migrate keycloak` CLI subcommand | ✅ Shipped | `src/main.rs` |
| PBKDF2-SHA256 credential import | ✅ Shipped | `src/identity/migration/credentials.rs` |
| Realm / user / client import | ✅ Shipped | `src/identity/migration/keycloak.rs` |
| Integration tests (7 scenarios) | ✅ Shipped | `tests/migration_keycloak.rs` |

---

## Client SDKs

| SDK | Status | Location |
|-----|--------|----------|
| TypeScript / browser | ✅ Shipped | `sdks/typescript/` |
| Node.js | ✅ Shipped | `sdks/node/` |
| Go | ✅ Shipped | `sdks/go/` |
| PHP | ✅ Shipped | `sdks/php/` |
| Python | ✅ Shipped | `sdks/python/` |
| Rust | ✅ Shipped | `sdks/rust/` |
| Kotlin / JVM | ✅ Shipped | `sdks/kotlin/` |

---

## Deployment

| Method | Status | Location |
|--------|--------|----------|
| Docker (single container) | ✅ Shipped | `Dockerfile` |
| Docker Compose (dev + prod) | ✅ Shipped | `deploy/docker-compose.yml`, `compose.dev.yaml` |
| Helm chart (Kubernetes) | ✅ Shipped | `deploy/helm/hearth/` |
| systemd unit | ✅ Shipped | `deploy/systemd/hearth.service` |

---

## Roadmap (not yet implemented)

The following surfaces are documented as design specs but have **no implementation** in `src/`:

| Feature | Design doc |
|---------|------------|
| FAPI 2.0 full protocol enforcement (PAR / JAR / JARM / realm profile) | [docs/guides/fapi2.md](guides/fapi2.md) |
| Agent entity, Agent Card, A2A / MCP protocol surfaces | [docs/specs/AGENT_AUTH.md](specs/AGENT_AUTH.md) |
| Delegation chains and scope attenuation | [docs/specs/AGENT_AUTH.md](specs/AGENT_AUTH.md) |
| Attenuating Authorization Tokens (AATs) | [docs/specs/AGENT_AUTH.md](specs/AGENT_AUTH.md) |
| Human-in-the-loop agent approval lifecycle | [docs/specs/AGENT_AUTH.md](specs/AGENT_AUTH.md) |
| SAML 2.0 SP / IdP | — |
| SCIM 2.0 provisioning | — |
| FIDO2 / CTAP2 platform authenticator (beyond basic WebAuthn) | — |
