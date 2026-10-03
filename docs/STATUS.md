# Hearth — Implementation Status

> **Re-derived from repo state on 2026-10-02 (OpenSpec `scope-trim-trusted-core`, task 13.3),
> checked against [`3e382f87`](https://github.com/hearth-auth/hearth/commit/3e382f87).
> Update this file when new surfaces ship.**
>
> This document is a reference, not a roadmap. It lists only what exists in the repository.
> Every ✅ row names a path that exists at that commit. Rows marked ❌ were removed in 3.0.0
> by the scope trim. Planned work is under **Roadmap** at the bottom.

---

## Core Server

| Component | Status | Location |
|-----------|--------|----------|
| Single-binary Rust server | ✅ Shipped | `src/main.rs`, `src/lib.rs` |
| Embedded storage engine (WAL + memtable + SSTs) | ✅ Shipped | `src/storage/` |
| Identity engine (users, sessions, credentials) | ✅ Shipped | `src/identity/` |
| Claims-based RBAC (roles, groups, permissions) | ✅ Shipped | `src/rbac/` |
| Admin REST API | ✅ Shipped | `src/protocol/http.rs` (router), `src/protocol/http/admin.rs` (handlers) |
| Admin UI (Axum-rendered templates) | ✅ Shipped | `src/protocol/web/`, `templates/ui/` |
| Public gRPC API | ❌ Removed in 3.0.0 | Every admin operation is on the REST API under `/admin`. Raft's internal peer transport still uses gRPC (`proto/hearth/cluster/v1/`) (OpenSpec `scope-trim-trusted-core`) |
| Raft consensus / cluster mode | ✅ Shipped | `src/cluster/` — see the caveat below |
| Audit log with keyed HMAC-SHA256 hash chain | ✅ Shipped | `src/audit/engine.rs` |
| Multi-tenancy (realms) | ✅ Shipped | `src/identity/types/realm.rs` |
| Organizations (B2B groups) | ✅ Shipped | `src/identity/types/org.rs`, `src/protocol/web/admin/orgs.rs` |
| Dev mode (in-memory store + mailcatcher) | ✅ Shipped | `--dev` flag; `src/identity/email/mailcatcher.rs` |
| Removed config keys stop startup with a named error | ✅ Shipped | `src/config/removed.rs` |
| Pre-token webhook (`on_error` defaults to `fail_closed`) | ✅ Shipped | `src/identity/pre_token_webhook.rs`, `src/identity/types/realm.rs` |
| Webhook subscriptions (signed delivery) | ✅ Shipped | `src/webhook/` |
| LDAP / Active Directory federation | ❌ Removed in 3.0.0 | Never wired to config or login. Use SCIM, OIDC/SAML federation or the importers (OpenSpec `scope-trim-trusted-core`) |
| Abuse extras (IP reputation, signal providers / bot signals, email reputation, login tarpit) | ❌ Removed in 3.0.0 | Their config keys now stop startup (OpenSpec `scope-trim-trusted-core`) |

> **Cluster-mode caveat.** The Raft implementation ships and replicates, but "shipped" here
> means the code exists and is exercised by the `cluster-chaos` CI job — it is not a statement
> that multi-node operation has been audited end to end. Four security-relevant controls were
> found stranded on followers and fixed by a replicated control epoch
> ([`reports/follower-bypass-enumeration-2026-09-21.md`](../reports/follower-bypass-enumeration-2026-09-21.md));
> a systematic enumeration against a live three-node cluster has **not** been done. Treat
> single-node as the audited deployment shape.

---

## Authentication Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| OIDC Core 1.0 | ✅ Shipped | Discovery, UserInfo, ID token with nonce (`src/identity/oidc.rs`) |
| OAuth 2.0 Authorization Code + PKCE | ✅ Shipped | PKCE S256 enforced for public clients (`src/identity/engine/oauth.rs`) |
| OAuth 2.0 Client Credentials | ✅ Shipped | `src/identity/engine/oauth.rs` |
| OAuth 2.0 Device Authorization Grant | ✅ Shipped | `src/identity/engine/oauth.rs` |
| OAuth 2.0 Token Introspection (RFC 7662) | ✅ Shipped | `src/protocol/http/oauth.rs` |
| OAuth 2.0 Token Revocation (RFC 7009) | ✅ Shipped | `src/protocol/http/oauth.rs` |
| Refresh token rotation | ✅ Shipped | Theft detection via family tracking (`src/identity/engine/oauth.rs`) |
| Dynamic Client Registration (RFC 7591) | ✅ Shipped | `POST /register` (`src/protocol/http/oauth.rs`). RFC 7592 management is roadmap |
| DPoP sender-constrained tokens (RFC 9449) | ✅ Shipped | `src/identity/dpop.rs` |
| DPoP-bound clients (`dpop_bound_access_tokens`, RFC 9449 §5.2) | ✅ Shipped | The client must send a DPoP proof on every token request (`src/identity/engine/oauth.rs`) |
| ROPC password grant (`grant_type=password`) | ❌ Removed in 3.0.0 | Clients that list `password` are refused (OpenSpec `scope-trim-trusted-core`) |
| Step-up MFA grant | ❌ Removed in 3.0.0 | OpenSpec `scope-trim-trusted-core` |
| MFA policy (required by default) | ✅ Shipped | One resolver, `effective_mfa_requirement` (`src/identity/engine/mod.rs`, `src/identity/mfa_policy.rs`). A realm can opt out with `mfa_required: false`; startup then warns |
| Organization MFA requirement | ✅ Shipped | Org `mfa_required` tightens the realm policy, never loosens it (`src/identity/types/org.rs`) |
| TOTP + recovery codes | ✅ Shipped | Enrollment and recovery codes (`src/identity/totp.rs`); single-use codes and brute-force lockout (`src/identity/engine/mfa_single_use.rs`). Satisfies MFA |
| WebAuthn / Passkeys | ✅ Shipped | Registration, authentication, multi-credential (`src/identity/webauthn.rs`). Satisfies MFA |
| Magic link / Passwordless | ✅ Shipped | Rate limited, enumeration resistant (`src/identity/magic_link.rs`). Email OTP and magic links do not satisfy MFA |
| SMS OTP + phone enrolment | ❌ Removed in 3.0.0 | `sms` config now stops startup (OpenSpec `scope-trim-trusted-core`) |
| Risk scoring / adaptive MFA / device fingerprinting | ❌ Removed in 3.0.0 | MFA is a plain policy, never a score (OpenSpec `scope-trim-trusted-core`) |
| TLS termination (Rustls, TLS 1.3) | ✅ Shipped | HTTP→HTTPS redirect, mTLS (`src/protocol/tls.rs`) |
| Pushed Authorization Requests (PAR, RFC 9126) | ✅ Shipped | `POST /as/par`, `POST /realms/{realm}/as/par` (`src/protocol/http/oauth.rs`) |
| JWT Authorization Requests (JAR, RFC 9101) | ✅ Shipped | `verify_jar` consumed on `/authorize` and PAR (`src/identity/engine/oauth.rs`) |
| JWT Authorization Response Mode (JARM) | ❌ Removed in 3.0.0 | `response_mode` is `query` or `fragment`; `*.jwt` modes answer `unsupported_response_mode` (OpenSpec `scope-trim-trusted-core`) |
| RS256 ID tokens | ✅ Shipped | `id_token_signed_response_alg` per client (`RS256`/`EdDSA`; DCR defaults to RS256); per-realm RSA-3072 key, rotated with the realm key, published in the realm JWKS (`src/identity/engine/id_token_keys.rs`). Access tokens stay EdDSA-only |
| FAPI 2.0 Security Profile | ❌ Removed in 3.0.0 | Use `dpop_bound_access_tokens` for sender-constrained clients (OpenSpec `scope-trim-trusted-core`) |
| RFC 8693 token exchange / RFC 8707 resource indicators | ✅ Shipped | `src/identity/engine/oauth.rs`; see [docs/specs/AGENT_AUTH.md](specs/AGENT_AUTH.md) |
| SAML 2.0 — SP (inbound federation, strict profile) | ✅ Shipped | `src/identity/federation/saml/sp.rs`; spec [docs/specs/SAML.md](specs/SAML.md) |
| SAML 2.0 — IdP (Hearth asserts to third-party SPs) | ❌ Removed in 3.0.0 | `realms.<name>.saml_service_providers` now stops startup (OpenSpec `scope-trim-trusted-core`) |
| SCIM 2.0 provisioning (Users, Groups, ServiceProviderConfig) | ✅ Shipped | `src/protocol/scim/` |
| Agent identity — Agent Card, DPoP, delegation, AATs, approvals | ✅ Shipped | `src/protocol/http/agents.rs`, `src/identity/engine/{aat,approval,txn,cross_realm,spiffe}.rs` |

---

## Email Transports

All transports live in `src/identity/email/`.

| Transport | Status | Config key |
|-----------|--------|------------|
| Log (default) | ✅ Shipped | `email.transport: log` |
| Mailcatcher (`--dev` default; view at `/dev/mail`) | ✅ Shipped | `email.transport: mailcatcher` |
| SMTP | ✅ Shipped | `email.transport: smtp` |
| SendGrid | ✅ Shipped | `email.transport: sendgrid` |
| Postmark | ✅ Shipped | `email.transport: postmark` |
| Mailgun (US + EU region) | ✅ Shipped | `email.transport: mailgun` |
| Mailtrap | ✅ Shipped | `email.transport: mailtrap` |

---

## Keycloak Migration

| Feature | Status | Location |
|---------|--------|----------|
| `hearth migrate keycloak` CLI subcommand | ✅ Shipped | `src/main.rs` |
| PBKDF2-SHA256 credential import | ✅ Shipped | `src/identity/migration/credentials.rs` |
| Realm / user / client import | ✅ Shipped | `src/identity/migration/keycloak.rs` |
| Integration tests (9 scenarios) | ✅ Shipped | `tests/migration_keycloak.rs` |

---

## Client SDKs

| SDK | Status | Location |
|-----|--------|----------|
| TypeScript `@hearth-auth/sdk` (browser, Node.js server, Next.js) | ✅ Shipped | `sdks/typescript/` |
| Go | ✅ Shipped | `sdks/go/` |
| PHP | ✅ Shipped | `sdks/php/` |
| Python | ✅ Shipped | `sdks/python/` |
| Node.js (`@hearth-auth/node`) | ❌ Removed in 3.0.0 | Merged into `@hearth-auth/sdk` (OpenSpec `scope-trim-trusted-core`) |
| Kotlin, Rust | ❌ Removed in 3.0.0 | No longer supported (OpenSpec `scope-trim-trusted-core`) |

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

Each row was checked at `3e382f87`: the named symbol or route does not exist in `src/`.
Features removed in 3.0.0 are not roadmap items.

| Feature | Evidence it is absent | Design doc |
|---------|----------------------|------------|
| SDKs on standard JOSE/OIDC libraries, OpenAPI-generated admin clients, SDK conformance harness | Planned, not started | OpenSpec [`sdk-standard-libraries`](../openspec/changes/sdk-standard-libraries/proposal.md) |
| RFC 7592 Dynamic Client Registration **management** (`GET`/`PUT`/`DELETE /register/{client_id}`) | No `/register/{client_id}` route is registered; registration (`POST /register`, RFC 7591) ships | [docs/specs/OIDC.md](specs/OIDC.md) §1 |
| SAML encrypted assertions / encrypted NameIDs (`EncryptedAssertion`, `EncryptedID`) | No decryption path; neither name appears in `src/` | [docs/specs/SAML.md](specs/SAML.md) §7 |
| SAML HTTP-Artifact and SOAP/PAOS (ECP) bindings | No artifact-resolution or SOAP endpoint; the strings `artifact`, `PAOS` and `SOAP` appear nowhere under `src/identity/federation/saml/` | [docs/specs/SAML.md](specs/SAML.md) §2 |
