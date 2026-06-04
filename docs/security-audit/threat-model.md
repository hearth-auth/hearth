# Hearth — STRIDE Threat Model

**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Version:** 1.0  
**Date:** 2026-06-03  
**Author:** CTO (internal, pre-external-review baseline)  
**Status:** Published — awaiting external reviewer validation (see [security-review-2026-06-03.md](./security-review-2026-06-03.md))  
**Scope:** Auth surface — login flows, token issuance/validation, admin API, multi-tenancy boundary, OAuth/OIDC endpoints

---

## 1. Scope

This document covers the authentication and authorization surface of Hearth:

| Component | Source location |
|---|---|
| Password authentication | `src/identity/credentials.rs`, `src/identity/engine.rs` |
| MFA (TOTP/SMS) | `src/protocol/web/sms_challenge.rs`, identity engine |
| Magic-link flow | `src/protocol/web/handlers.rs`, identity engine |
| Passkey / WebAuthn / FIDO2 | `src/identity/webauthn.rs`, `src/protocol/web/` |
| Token issuance & validation | `src/identity/tokens.rs` |
| Session management | `src/identity/engine.rs` |
| Admin API | `src/protocol/admin_auth.rs`, `src/protocol/web/admin/` |
| Multi-tenancy (realm isolation) | `src/core/` (RealmId newtype), storage layer key prefix |
| OAuth 2.0 / OIDC (AS + RP) | `src/identity/federation/oidc.rs`, `src/protocol/web/federation.rs`, `src/protocol/web/oauth_consent.rs` |
| SAML 2.0 SP/IdP | `src/identity/federation/saml/`, `src/protocol/web/saml.rs` |
| SCIM 2.0 | `src/protocol/scim/` |
| RBAC engine | `src/rbac/` |
| Audit log | `src/audit/` |
| Storage encryption | `src/storage/encryption.rs` |

---

## 2. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  TB-1: Public Internet                                               │
│                                                                      │
│   End User Browser ──HTTPS──▶  Hearth TLS Termination               │
│   OIDC Client App  ──HTTPS──▶  (rustls, TLS 1.2+)                  │
│   Admin Operator   ──HTTPS──▶                                       │
│   External IdP     ──HTTPS──▶  (SAML callback, OIDC backchannel)    │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │ TB-2: TLS → Protocol Layer
┌───────────────────────────────────▼─────────────────────────────────┐
│  Protocol Layer (src/protocol/)                                      │
│  - Web handlers (Axum HTTP)                                          │
│  - gRPC adapter                                                      │
│  - SCIM adapter                                                      │
│  - Admin auth middleware (src/protocol/admin_auth.rs)                │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │ TB-3: Protocol → Identity Engine
┌───────────────────────────────────▼─────────────────────────────────┐
│  Identity Engine (src/identity/)                                     │
│  - Session management (engine.rs)                                    │
│  - Credential verification (credentials.rs)                          │
│  - Token issuance (tokens.rs)                                        │
│  - WebAuthn ceremonies (webauthn.rs)                                 │
│  - Federation (oidc.rs, saml/)                                       │
│       │ lateral call at token issuance                               │
│       ▼                                                              │
│  RBAC Engine (src/rbac/)                                             │
│  - Permission resolution                                             │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │ TB-4: Identity → Storage
┌───────────────────────────────────▼─────────────────────────────────┐
│  Storage Engine (src/storage/)                                       │
│  - WAL (fsync before ACK)                                            │
│  - AES-256-GCM 3-tier envelope encryption                           │
│  - Realm-prefixed key space                                          │
└─────────────────────────────────────────────────────────────────────┘

TB-5: Realm A ↔ Realm B  (logical isolation within storage, enforced
       by RealmId prefix on all keys; resolution NEVER crosses realms)

TB-6: Hearth ↔ External IdP  (SAML assertion, OIDC ID token delivery
       — adversarial assertions cross this boundary)
```

---

## 3. Assets

| ID | Asset | Confidentiality | Integrity | Availability |
|----|-------|-----------------|-----------|--------------|
| A-1 | Ed25519 private signing key | Critical | Critical | High |
| A-2 | AES-256-GCM envelope (DEK/KEK/MEK) | Critical | Critical | High |
| A-3 | User credential hashes (Argon2id) | High | High | High |
| A-4 | Active session store (session ID → user/realm) | High | Critical | Critical |
| A-5 | Issued JWTs (in flight, short-lived) | High | Critical | Medium |
| A-6 | Magic-link tokens (single-use, TTL) | High | Critical | Low |
| A-7 | WebAuthn credential IDs and public keys | Medium | Critical | High |
| A-8 | Admin API credentials/tokens | Critical | Critical | High |
| A-9 | Realm data (users, groups, roles, permissions) | High | High | High |
| A-10 | Audit log (hash-chained) | Low | Critical | High |
| A-11 | OAuth authorization codes | High | Critical | Low |
| A-12 | OIDC client secrets / PKCE verifiers | High | Critical | Low |
| A-13 | SAML SP private key / IdP metadata | Critical | Critical | High |

---

## 4. Data Flow Diagrams

### 4.1 Password Login Flow

```
Client ─[POST /auth/login {email, password}]─▶ Protocol Layer (TB-1→TB-2)
  │
  ▼
Identity Engine: lookup_user(realm, email) → User record
  │
  ▼
credentials.rs: Argon2id verify(input, stored_hash) (spawn_blocking)
  │ (fail-fast constant-time rejection on wrong password)
  ▼
[if MFA enrolled] → MFA challenge issued; session in PENDING_MFA state
  │
  ▼
[if pass] engine.rs: create_session() → SessionId
  │
  ▼
tokens.rs: issue_access_token() → calls rbac::resolve_permissions()
  │                              → Ed25519 sign (ring)
  ▼
Response: {access_token, refresh_token, session_id}
```

### 4.2 Magic-Link Flow

```
Client ─[POST /auth/magic-link {email}]─▶ Protocol Layer
  │
  ▼
Identity Engine: generate_magic_token() → cryptographically random token,
                 stored with TTL, single-use flag, realm + email binding
  │
  ▼
Email dispatch (mailcatcher in dev, real SMTP in prod)
  │
  ▼
Client ─[GET /auth/magic-link?token=<T>]─▶ Protocol Layer
  │
  ▼
Identity Engine: consume_magic_token(T) → validate TTL, realm, used=false
  │             → atomically mark used, create session
  ▼
tokens.rs: issue_access_token()
```

### 4.3 WebAuthn / Passkey Flow

```
Registration:
  Client ─[POST /auth/webauthn/register/begin]─▶ Engine: generate challenge
  Client ─[POST /auth/webauthn/register/finish {attestation}]─▶
    webauthn.rs: verify_attestation() → store credential_id + public_key

Authentication:
  Client ─[POST /auth/webauthn/authenticate/begin]─▶ Engine: generate challenge
  Client ─[POST /auth/webauthn/authenticate/finish {assertion}]─▶
    webauthn.rs: verify_assertion(challenge, credential_id, sig) → create session
```

### 4.4 OAuth 2.0 / OIDC Authorization Code + PKCE

```
Client ─[GET /oauth/authorize?response_type=code&code_challenge=<CC>&...]─▶
  Protocol: validate redirect_uri against registered client URIs
  Engine: store {code_challenge, code_challenge_method, state, nonce, client_id}
  → User login (any auth method above)
  → Consent screen (oauth_consent.rs)
  → issue authorization code (short TTL, single-use)

Client ─[POST /oauth/token {code, code_verifier}]─▶
  Engine: verify PKCE: SHA-256(code_verifier) == code_challenge
  Engine: issue {access_token, id_token, refresh_token}
```

### 4.5 Token Validation (Hot Path)

```
Service ─[Authorization: Bearer <JWT>]─▶ any protected endpoint
  Protocol: extract JWT, pass to validate_token()
  tokens.rs: verify Ed25519 signature (ring, no heap alloc)
  → check exp, iss, aud, tid (realm)
  → read permissions from claims (no RBAC re-resolution)
  → return SessionId + claims struct
```

### 4.6 Admin API

```
Operator ─[POST /admin/... + Authorization: Bearer <admin_token>]─▶
  admin_auth.rs: verify admin token (constant-time SHA-256 comparison)
  rate limiter check
  → admin handler (users, realms, rbac, clients, webhooks, migrations)
```

---

## 5. STRIDE Analysis

Each threat is assigned:
- **ID** — stable reference
- **STRIDE category** — S/T/R/I/D/E
- **Component / trust boundary** — where the threat materializes
- **Severity** — Critical / High / Medium / Low
- **Mitigation status** — Implemented / Partial / Gap

### 5.1 Login Flows

| ID | Category | Threat | Severity | Mitigation | Status |
|----|----------|--------|----------|------------|--------|
| TM-001 | S | Attacker submits valid email + brute-forced password | High | Rate limiting + account lockout (verify implementation in `engine.rs`); Argon2id slows offline attempts if hashes leaked | Partial — rate limit implementation needs external verification |
| TM-002 | S | Credential stuffing from leaked third-party databases | High | Argon2id with per-realm salts; breach-check integration (`HEA-96`) | Implemented |
| TM-003 | S | Magic-link token interception via email in transit | High | Tokens are single-use + short TTL + realm-bound; email transport is TLS; attacker must intercept email AND be first to use it | Implemented |
| TM-004 | S | Magic-link token prediction | Critical | Token must be cryptographically random (verify entropy source in `engine.rs`) | Partial — entropy source needs external verification |
| TM-005 | T | Magic-link token reuse after consumption | High | Atomic single-use flag; consumed tokens immediately invalidated | Implemented — verify atomicity under concurrent requests |
| TM-006 | T | WebAuthn challenge replay | High | Challenges are single-use, stored server-side with TTL; `webauthn.rs` must verify challenge matches | Implemented — verify server-side challenge binding |
| TM-007 | I | Timing side-channel in password comparison | High | Argon2id returns constant-time pass/fail; `credentials.rs` must not branch on intermediate values | Implemented (Argon2id is constant-time on wrong pass) |
| TM-008 | I | Username enumeration via differential response timing | Medium | Login response must have indistinguishable timing for valid vs invalid email | Gap — needs measurement |
| TM-009 | D | Argon2id resource exhaustion (memory amplification) | High | Rate limiting per IP + per realm; Argon2id is intentionally expensive (19 MiB/attempt) | Partial — rate limit must be verified |
| TM-010 | D | Magic-link flooding (email abuse) | Medium | Rate limit on `/auth/magic-link` per email per realm | Partial — needs verification |
| TM-011 | E | MFA bypass — downgrade to password-only | Critical | Session state machine must enforce MFA for enrolled users; `PENDING_MFA` state cannot issue tokens | Implemented — needs external verification |
| TM-012 | E | MFA TOTP code reuse within 30-second window | High | TOTP codes must be single-use within their time step | Gap — verify in `engine.rs` |

### 5.2 Token Issuance and Validation

| ID | Category | Threat | Severity | Mitigation | Status |
|----|----------|--------|----------|------------|--------|
| TM-020 | S | `alg:none` JWT attack | Critical | Token parsing explicitly rejects any `alg` other than `EdDSA`; fuzz target `jwt_parse` covers this | Implemented |
| TM-021 | S | JWT algorithm confusion (e.g., EdDSA→HS256 with public key as HMAC secret) | Critical | Only Ed25519/EdDSA supported; no symmetric JWT algorithms accepted | Implemented |
| TM-022 | T | JWT payload tampering (invalid signature) | Critical | Ed25519 signature verification via `ring`; all claims verified before use | Implemented |
| TM-023 | T | JWT `tid` (realm) claim spoofing to access cross-realm data | Critical | `tid` is verified against the calling realm; RealmId typed newtype prevents mix-ups | Implemented |
| TM-024 | I | JWT payload leaking sensitive data | Medium | Tokens must not embed passwords, raw secrets, or PII beyond necessary identity claims | Implemented by policy — needs external code review |
| TM-025 | I | Signing key extraction from memory | High | Ed25519 key wrapped in Zeroize-on-drop type; key material not logged | Implemented — verify in `tokens.rs` |
| TM-026 | T | Stale permission window — escalated permissions not revoked until next token refresh | High | Permissions are embedded at issuance; revocation requires session revocation or waiting for TTL expiry. Documented trade-off. Emergency path: session revocation immediately invalidates | Accepted risk — session revocation is the emergency control |
| TM-027 | D | Token validation DoS via malformed JWT causing panic | High | Fuzz target `jwt_parse` covers parser panics; no unsafe in protocol layer | Implemented — verify fuzz corpus coverage |
| TM-028 | R | Token replay after session revocation | High | Token validation must check session revocation store, not just signature validity | Gap — verify `validate_token()` checks session liveness |
| TM-029 | E | Refresh token used after session revocation | Critical | Refresh tokens must be tied to session ID; revoked sessions must reject refresh | Implemented — verify binding in `engine.rs` |

### 5.3 Admin API

| ID | Category | Threat | Severity | Mitigation | Status |
|----|----------|--------|----------|------------|--------|
| TM-030 | S | Admin token brute force | Critical | Admin tokens are long-random (verify entropy); rate limiting in `admin_auth.rs` | Partial — rate limit and entropy need verification |
| TM-031 | S | Admin API accessible without authentication in dev mode | Critical | `--dev` mode must NOT disable admin auth; bootstrap endpoint (`/admin/bootstrap`) creates first token and is disabled after first use | Implemented — dev mode auth bypass would be critical gap |
| TM-032 | T | SSRF via admin webhook configuration | High | Webhook URLs must be validated against allowlist or restricted IP ranges | Gap — `src/protocol/web/admin/webhooks.rs` needs SSRF review |
| TM-033 | T | Admin API accepting arbitrary realm operations without realm scope check | Critical | Admin tokens scoped to realm; cross-realm admin must require super-admin scope | Needs external verification |
| TM-034 | I | Admin API error messages leaking internal details | Medium | Error responses must not include stack traces, internal IDs, or config values | Needs external verification |
| TM-035 | D | Admin API rate limiting bypass via distributed IPs | Medium | Rate limiting per token identity preferred over IP-only | Partial — needs design review |
| TM-036 | E | Privilege escalation via admin migration endpoint | Critical | `migrations.rs` must require super-admin and validate input strictly | Gap — migration endpoint is high-risk; needs focused review |
| TM-037 | R | Admin operations not captured in audit log | High | All admin mutations must emit audit events; audit log is hash-chained | Implemented — audit coverage needs verification |

### 5.4 Multi-Tenancy Boundary

| ID | Category | Threat | Severity | Mitigation | Status |
|----|----------|--------|----------|------------|--------|
| TM-040 | S | Realm ID injection — attacker supplies a different realm ID in a request | Critical | RealmId is a typed newtype resolved from the authenticated token's `tid` claim or verified request context; not taken directly from user-controlled input | Implemented — verify no handlers take raw realm from query params |
| TM-041 | T | Cross-realm data write via storage key prefix bypass | Critical | All storage keys are prefixed with RealmId; storage layer enforces prefix in all operations | Implemented — prefix enforcement needs external audit |
| TM-042 | I | Cross-realm data read via iterator scan leak | High | Scans are bounded to a single realm key prefix | Implemented — verify no unbounded scans |
| TM-043 | E | Realm resolution in OIDC/SAML flows leaking cross-realm existence | Medium | Realm slugs are public in host-based routing; user enumeration within a realm is the threat, not cross-realm | Accepted — realm names are public by design |
| TM-044 | E | Super-admin token granting access to all realms | High | Super-admin scope must be explicitly and separately provisioned; no implicit realm-all grant | Needs external verification |

### 5.5 OAuth 2.0 / OIDC Endpoints

| ID | Category | Threat | Severity | Mitigation | Status |
|----|----------|--------|----------|------------|--------|
| TM-050 | S | Open redirect via unvalidated `redirect_uri` | Critical | `redirect_uri` must exactly match one of the registered URIs for the client (no prefix/wildcard matching) | Implemented — verify exact-match logic in `oidc.rs` |
| TM-051 | S | PKCE downgrade — authorization request without `code_challenge` accepted | Critical | PKCE is mandatory for all public clients; server rejects requests without `code_challenge` | Implemented (`HEA-501`) |
| TM-052 | T | Authorization code injection — code issued to attacker's redirect, replayed against victim | High | PKCE with `code_verifier` binding prevents this; `state` parameter enforces CSRF protection | Implemented |
| TM-053 | T | CSRF on authorization endpoint — forged auth initiation | High | `state` parameter required and verified by client; Hearth validates state if AS mode | Implemented |
| TM-054 | I | Authorization code leak in referrer header or URL logging | Medium | Codes must have short TTL (<= 60 s) and be single-use | Implemented (single-use) — TTL needs verification |
| TM-055 | I | ID token claim disclosure — sensitive scopes returned without consent | Medium | Consent screen (`oauth_consent.rs`) must gate sensitive scopes | Implemented — consent gate needs review |
| TM-056 | D | Authorization code endpoint abuse — triggering expensive auth flows | Medium | Rate limiting per client_id + per user | Partial — needs verification |
| TM-057 | E | OIDC ID token accepted as API bearer token | High | `aud` claim must be validated; ID tokens and access tokens are structurally distinguished | Needs verification |
| TM-058 | S | SAML assertion replay | Critical | `InResponseTo` binding, assertion TTL, single-use assertion ID cache | Implemented — cache persistence and eviction needs review |
| TM-059 | T | SAML XML signature wrapping (XSW) attack | Critical | Fuzz target `saml_xml_parse` covers XSW variants; strict XML canonical parsing | Implemented — fuzz coverage and canonical parsing needs external review |
| TM-060 | T | SAML SP metadata poisoning — attacker replaces IdP metadata with rogue cert | Critical | IdP metadata loaded from operator-controlled config only; no runtime metadata fetch without signature verification | Needs external verification |

### 5.6 Storage and At-Rest

| ID | Category | Threat | Severity | Mitigation | Status |
|----|----------|--------|----------|------------|--------|
| TM-070 | I | Credential hash extraction via storage file read | High | AES-256-GCM 3-tier envelope encryption; keys not stored on-disk | Implemented |
| TM-071 | T | WAL replay attack | High | WAL entries are authenticated; each entry is cryptographically bound to sequence number | Needs external verification |
| TM-072 | T | Audit log tampering to remove evidence | High | Hash-chained audit log; any deletion or modification breaks the chain | Implemented |

---

## 6. Residual Risk Summary

| Severity | Count | Items requiring external review |
|----------|-------|----------------------------------|
| Critical | 14 | TM-004, TM-011, TM-020, TM-021, TM-023, TM-029, TM-031, TM-033, TM-036, TM-040, TM-041, TM-050, TM-058, TM-059 |
| High | 19 | TM-001, TM-003, TM-006, TM-007, TM-009, TM-022, TM-025, TM-026, TM-027, TM-028, TM-030, TM-032, TM-037, TM-042, TM-044, TM-055, TM-057, TM-060, TM-072 |
| Medium | 8 | TM-008, TM-010, TM-024, TM-034, TM-035, TM-043, TM-054, TM-056 |
| **Gaps (no mitigation)** | **5** | **TM-008, TM-012, TM-028, TM-032, TM-036** |

**Explicit gaps requiring immediate remediation or formal risk acceptance before 1.0:**

1. **TM-008** — Username enumeration timing side-channel
2. **TM-012** — TOTP single-use enforcement
3. **TM-028** — Token replay after session revocation (validate_token must check session liveness)
4. **TM-032** — SSRF via admin webhook URL configuration
5. **TM-036** — Migration endpoint privilege escalation risk

---

## 7. Mitigations Already Implemented (Summary)

| Control | Implementation | Notes |
|---------|----------------|-------|
| Ed25519-only JWT signing | `ring` 0.17, `tokens.rs` | No HS256/RS256/alg:none |
| Argon2id password hashing | OWASP params (19 MiB, 2 iter, p=1), `credentials.rs` | Off hot path via spawn_blocking |
| PKCE mandatory (public clients) | `oidc.rs` | HEA-501 |
| AES-256-GCM at-rest encryption | 3-tier envelope, `storage/encryption.rs` | Active in 1.0 |
| Realm-prefixed storage key isolation | All storage operations | RealmId newtype |
| Hash-chained audit log | `src/audit/` | Tamper detection |
| Fuzz corpus (8 targets) | `fuzz/fuzz_targets/` | jwt_parse, saml_xml_parse, webauthn_cbor_parse, etc. |
| TLS 1.2/1.3 via rustls | `src/protocol/tls.rs` | No OpenSSL |
| Constant-time SCIM token comparison | `ring` + `subtle` crate | |
| `cargo-audit` + `cargo deny` | CI | Dependency CVE tracking |
| Zeroize-on-drop for secrets | `Zeroize` trait | Key material, credentials |
| No unsafe in protocol/identity layers | Enforced by architecture spec | |

---

## 8. External Review Priorities

The following areas represent the highest-risk items for an independent reviewer to focus on, in order:

1. **SAML XSW and assertion replay** (TM-058, TM-059) — XML parsing is notoriously difficult to get right; `saml_xml_parse` fuzz target must be validated for completeness.
2. **Session revocation + token liveness** (TM-028, TM-029) — hot path bypasses session revocation if `validate_token()` only checks signature.
3. **Admin API attack surface** (TM-030–TM-037) — particularly SSRF in webhooks and migration endpoint privilege escalation.
4. **MFA bypass and TOTP reuse** (TM-011, TM-012) — state machine enforcement is critical; any bypass here collapses MFA entirely.
5. **Open redirect in OIDC** (TM-050) — exact redirect_uri matching is easy to get wrong (trailing slash, port normalization, fragment handling).
6. **Cross-realm isolation** (TM-040–TM-044) — any handler accepting user-supplied realm context must be audited exhaustively.

---

*This document is a living baseline. It should be updated when new authentication flows, endpoints, or storage mechanisms are introduced. It feeds directly into the external security review scope defined in [security-review-2026-06-03.md](./security-review-2026-06-03.md).*
