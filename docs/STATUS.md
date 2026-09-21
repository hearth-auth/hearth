# Hearth — Implementation Status

> **Re-derived from repo state on 2026-09-21 (documentation-truth sweep, audit 2026-08-28 §6 /
> §9 item 4). Update this file when new surfaces ship.**
>
> This document is a reference, not a roadmap. It lists only what currently exists in the
> repository. Aspirational or planned features are listed under **Roadmap** at the bottom
> and are explicitly marked as not yet implemented.
>
> The 2026-06-02 revision of this file had rotted badly: it listed SAML 2.0, SCIM 2.0, the
> whole agent-identity surface and FAPI 2.0 as unimplemented roadmap items when all four were
> already in `src/`. Every row below was re-checked against a named path at
> [`333c74e6`](https://github.com/hearth-auth/hearth/commit/333c74e6); rows whose evidence
> could not be produced were deleted rather than restated.

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
| gRPC service surface | ✅ Shipped | `src/protocol/grpc/`, `proto/` |
| Raft consensus / cluster mode | ✅ Shipped | `src/cluster/` — see the caveat below |
| Audit log with SHA-256 hash chain | ✅ Shipped | `src/audit/` |
| Multi-tenancy (realms) | ✅ Shipped | `src/identity/` |
| Organizations (B2B groups) | ✅ Shipped | `src/identity/` |
| Dev mode (in-memory store + mailcatcher) | ✅ Shipped | `--dev` flag |
| LDAP / Active Directory federation | ⚠️ Not operator-reachable | `src/identity/ldap/` — see the LDAP caveat below |
| Webhook subscriptions (signed delivery) | ✅ Shipped | `src/webhook/` |

> **Cluster-mode caveat.** The Raft implementation ships and replicates, but "shipped" here
> means the code exists and is exercised by the `cluster-chaos` CI job — it is not a statement
> that multi-node operation has been audited end to end. Four security-relevant controls were
> found stranded on followers and fixed by a replicated control epoch
> ([`reports/follower-bypass-enumeration-2026-09-21.md`](../reports/follower-bypass-enumeration-2026-09-21.md));
> a systematic enumeration against a live three-node cluster has **not** been done. Treat
> single-node as the audited deployment shape.

> **LDAP caveat.** `src/identity/ldap/` is a complete connector — user search, password-bind
> authentication, attribute mapping, `modifyTimestamp` and `uSNChanged` delta sync, LDAPS
> enforcement — and it is exercised against a real OpenLDAP service container by the
> `ldap-integration` CI job. It is **not reachable by an operator**: there is no `ldap:` block
> in `hearth.yaml`, no admin API, and no caller anywhere in `src/` outside the module itself.
> `docs/guides/federation.md` has said "wiring in progress" all along; this row said "Shipped",
> which was wrong. See [`reports/subsystem-audit-ldap-grpc-email-2026-09-21.md`](../reports/subsystem-audit-ldap-grpc-email-2026-09-21.md).

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
| Dynamic Client Registration (RFC 7591) | ✅ Shipped | RFC 7592 management endpoints (`GET/PUT/DELETE /register/{client_id}`) are roadmap — zero implementation in `src/` |
| DPoP sender-constrained tokens (RFC 9449) | ✅ Shipped | `src/identity/dpop.rs` |
| TOTP / MFA | ✅ Shipped | Enrollment, recovery codes, brute-force lockout |
| WebAuthn / Passkeys | ✅ Shipped | Registration, authentication, multi-credential |
| Magic link / Passwordless | ✅ Shipped | Rate limited, enumeration resistant |
| TLS termination (Rustls, TLS 1.3) | ✅ Shipped | HTTP→HTTPS redirect, mTLS |
| Pushed Authorization Requests (PAR, RFC 9126) | ✅ Shipped | `POST /as/par`, `POST /realms/{realm}/as/par` (`src/protocol/http/oauth.rs`) |
| JWT Authorization Requests (JAR, RFC 9101) | ✅ Shipped | `verify_jar` consumed on `/authorize` and PAR (`src/identity/engine/oauth.rs`) |
| JWT Authorization Response Mode (JARM) | ✅ Shipped | `authorization_signed_response_alg` per client; `sign_jarm_error_jwt` (`src/identity/mod.rs`) |
| FAPI 2.0 Security Profile (per-client + per-realm) | ✅ Shipped | `ClientProfile::Fapi2`, `RealmConfig::fapi_profile` (`src/identity/oidc.rs`); normative spec [docs/specs/OIDC.md](specs/OIDC.md) |
| RFC 8693 token exchange / RFC 8707 resource indicators | ✅ Shipped | `src/identity/engine/oauth.rs`; see [docs/specs/AGENT_AUTH.md](specs/AGENT_AUTH.md) |
| SAML 2.0 — SP (inbound federation) | ✅ Shipped | `src/identity/federation/saml/sp.rs`; spec [docs/specs/SAML.md](specs/SAML.md) |
| SAML 2.0 — IdP (Hearth asserts to third-party SPs) | ✅ Shipped | `src/identity/federation/saml/idp.rs`; routes `/realms/{realm}/saml/{metadata,sso,sso/init,slo-idp}` |
| SCIM 2.0 provisioning (Users, Groups, ServiceProviderConfig) | ✅ Shipped | `src/protocol/scim/` |
| Agent identity — Agent Card, DPoP, delegation, AATs, approvals | ✅ Shipped | `src/protocol/http/agents.rs`, `src/identity/engine/{aat,approval,txn,cross_realm,spiffe}.rs` |

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
| Integration tests (9 scenarios) | ✅ Shipped | `tests/migration_keycloak.rs` |

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

Every row below was re-checked at `333c74e6`: the named symbol or route does not exist in
`src/`. Rows that previously sat here — FAPI 2.0, the whole agent-identity surface, SAML 2.0
and SCIM 2.0 — were **already implemented** when they were listed as roadmap and have been
moved into the shipped tables above.

| Feature | Evidence it is absent | Design doc |
|---------|----------------------|------------|
| RFC 7592 Dynamic Client Registration **management** (`GET`/`PUT`/`DELETE /register/{client_id}`) | No `/register/{client_id}` route is registered; registration (`POST /register`, RFC 7591) ships | [docs/specs/OIDC.md](specs/OIDC.md) §1 |
| SAML encrypted assertions / encrypted NameIDs (`EncryptedAssertion`, `EncryptedID`) | No decryption path; `xmlenc` is recognised only for the SHA-256 digest identifier | [docs/specs/SAML.md](specs/SAML.md) §7 |
| SAML HTTP-Artifact and SOAP/PAOS (ECP) bindings | No artifact-resolution or SOAP endpoint is registered, and the strings `artifact`, `PAOS` and `SOAP` appear nowhere under `src/identity/federation/saml/` | [docs/specs/SAML.md](specs/SAML.md) §2 |
