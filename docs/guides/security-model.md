# Hearth Security Model

**Audience:** Security engineers, operators evaluating Hearth for production, and architects
integrating Hearth into a zero-trust environment. This document explains the mental model
behind Hearth's trust decisions — why the boundaries exist where they do and what threats
each layer defends against.

**Related documents:**
- [SECURITY.md](../../SECURITY.md) — cryptographic primitive choices, CVD process, encryption-at-rest key hierarchy
- [docs/guides/security-hardening.md](./security-hardening.md) — operational configuration for production deployments
- [docs/specs/ARCHITECTURE.md](../specs/ARCHITECTURE.md) — normative layer rules including §8 Security

---

## 1. Trust Boundaries

Hearth's architecture enforces four nested trust domains. Each boundary is a point where
all inputs are treated as untrusted until validated. No layer assumes that an upstream layer
performed validation.

```
┌──────────────────────────────────────────────────────────────────┐
│  Internet (untrusted)                                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  TLS termination                                           │  │
│  │  (rustls 0.23 — TLS 1.2/1.3, optional mTLS)              │  │
│  │                                                            │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │  Protocol layer  (src/protocol/)                     │  │  │
│  │  │  Wire validation, rate limiting, auth extraction     │  │  │
│  │  │                                                      │  │  │
│  │  │  ┌────────────────────────────────────────────────┐  │  │  │
│  │  │  │  Identity layer  (src/identity/)               │  │  │  │
│  │  │  │  Domain validation, credential verification,   │  │  │  │
│  │  │  │  session and token management                  │  │  │  │
│  │  │  │                                                │  │  │  │
│  │  │  │  ┌──────────────────────────────────────────┐  │  │  │  │
│  │  │  │  │  Storage layer  (src/storage/)           │  │  │  │  │
│  │  │  │  │  Realm-scoped, WAL-durable, AES-256-GCM  │  │  │  │  │
│  │  │  │  │  encrypted; structural invariant checks  │  │  │  │  │
│  │  │  │  └──────────────────────────────────────────┘  │  │  │  │
│  │  │  └────────────────────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.1 What Hearth trusts unconditionally

| Source | Why it is trusted |
|--------|-------------------|
| WAL records that pass CRC verification | Written by Hearth itself; CRC mismatch causes replay to discard the record |
| Per-realm Ed25519 signing keys | Generated internally at realm creation; stored encrypted in `hearth.keys` under the host key; never operator-supplied in the default configuration |
| Sessions stored in the hot tier | Hearth issued them; hot-path token validation is a session lookup, not a signature re-verification |
| Layer-to-layer calls flowing downward | The dependency graph is enforced at compile time — no layer imports from above |
| Realm isolation enforced at the storage API | `RealmId` is a newtype parameter on every storage operation; the compiler prevents its omission |

### 1.2 What Hearth validates at every boundary

**TLS/transport layer**

Hearth handles TLS termination directly via `rustls` 0.23 when `server.tls_cert_path` and
`server.tls_key_path` are configured. Alternatively, operators may terminate TLS at a load
balancer and configure `server.trusted_proxies` + `server.trust_forwarded_proto`.
Optional mutual TLS (`server.tls_require_client_cert`) allows a second authenticator
at the transport layer for machine-to-machine paths.

**Protocol layer** (`src/protocol/`)

Every inbound HTTP request is validated for:

- Maximum request body size (enforced as middleware; large bodies are rejected before parsing)
- Required HTTP headers and content types
- String length limits and null byte rejection
- Unicode NFC normalization on usernames and email addresses
- Per-IP rate limits (configurable; defaults to 10 failed login attempts per 60-second window)
- Request queue depth (HTTP 503 when the backpressure limit is reached)
- Request timeout (requests exceeding the configured deadline are cancelled)

Bearer tokens and session cookies are extracted and passed to the identity layer as opaque
values — the protocol layer does not make trust decisions about their contents.

**Identity layer** (`src/identity/`)

The identity layer validates independently of the protocol layer:

- Email format and password policy
- Realm existence and active status (suspended realms reject all auth operations)
- Session expiry and revocation status
- Per-account lockout state (WAL-persisted; survives restarts)
- PKCE `code_verifier` against the stored `code_challenge` for OAuth 2.0 authorization code flows
- `state` parameter round-trip for CSRF protection in OAuth flows
- SAML assertion signatures (Exclusive C14N 1.0 + SHA-256 + RSA-SHA256; SHA-1 rejected unconditionally)
- OIDC federation tokens validated against the external IdP's JWKS endpoint
- `AssertionConsumerServiceURL` in SAML `AuthnRequest` messages validated against pre-registered URLs

**Storage layer** (`src/storage/`)

The storage layer enforces structural invariants:

- Every operation requires a `RealmId` parameter — this is a compile-time requirement, not a runtime check
- All keys are prefixed with the realm ID; all scans are bounded to a single realm's key space
- Key length and value size bounds are checked before WAL append

### 1.3 The system realm and administrative trust

Hearth uses a **system realm** (`RealmId::nil()` — the nil UUID, reserved and never used for
application realms) as a separate trust domain for administrative operations:

- All Hearth administrator users authenticate against the system realm
- Administrator sessions carry system-realm tokens; they are scoped to the system realm's signing key
- Admin API calls that operate on application realms use a `TargetRealm` parameter
- This means compromising an application realm's administrator does not grant access to the system realm — the session tokens are signed by different keys and stored in a different realm namespace

The system realm itself is invisible to application-realm users. It does not appear in realm
listing APIs and cannot be deleted.

### 1.4 Federation trust

When Hearth acts as an OIDC relying party or SAML service provider, it delegates the
authentication decision to the external identity provider. Hearth validates the IdP's
cryptographic assertions but cannot independently verify the IdP's authentication quality
(multi-factor enforcement, account security posture, etc.).

**Operator responsibility:** When federating with an external IdP, Hearth's security model
inherits the weaknesses of that IdP's authentication assurance. Pin OIDC federation providers
to a tenant-specific `issuer` (see `federation.providers.<name>.issuer` in
`hearth.example.yaml`); leaving it blank allows tokens from any tenant of that provider.

---

## 2. Threat Model Summary

### 2.1 Protected assets

| Asset | Protection mechanism |
|-------|---------------------|
| Credential store (password hashes) | Argon2id (OWASP params: 19 MiB, 2 iterations, p=1); encrypted at rest via AES-256-GCM 3-tier envelope |
| Per-realm signing keys (Ed25519) | Wrapped in `ZeroizingPkcs8`; stored in `hearth.keys` encrypted by the host key; never appear in logs, debug output, or error messages |
| Session store | WAL-persisted; encrypted at rest; hot-tier lookup with zero heap allocation on read path |
| Audit log | SHA-256 hash chain over all events; append-only through all APIs; immutable once written |
| In-memory sensitive values | `CleartextPassword`, `PepperKey`, `TotpSecret`, `IdpClientSecret`, and `ApiKey` implement `ZeroizeOnDrop`; none implement `Debug`, `Display`, or `Serialize` in ways that reveal contents |

### 2.2 Attacker categories and defenses

**Unauthenticated external attacker**

The primary goals are credential theft, token forgery, and denial of service.

- *Credential stuffing / brute force*: Per-IP rate limiting (10 attempts/60s window,
  in-memory) and per-account lockout after 5 consecutive failures (5-minute lockout,
  WAL-persisted so it survives server restarts). Account lockout counters are wiped only by
  successful authentication.
- *Token forgery*: Ed25519 (EdDSA) only — no HS256, no `alg:none`. Because token validation
  is performed via session lookup rather than signature re-verification on the hot path, a
  valid signature on a revoked session is not accepted.
- *Replay attacks*: JTI (JWT ID) is included in all tokens; revoked JTIs are recorded in a
  blocklist. Client credentials tokens (which are sessionless) use a JTI-based blocklist in
  storage. Refresh tokens are single-use; presenting a previously-used refresh token is
  treated as theft and triggers family revocation.
- *PKCE bypass*: All public OAuth 2.0 clients must supply a `code_challenge`. The
  authorization server rejects authorization requests without one.
- *Password enumeration*: Hash verification uses `subtle::ConstantTimeEq` for constant-time
  comparison. Error responses do not distinguish between "user not found" and "wrong password".
- *DoS via request flooding*: Tower `Buffer` enforces a configurable request queue depth
  (HTTP 503 when full); Tower `Timeout` cancels requests that exceed the deadline.

**Authenticated user**

- *Cross-realm data leakage*: Every storage operation is parameterized by `RealmId` (a
  newtype — not a raw string). The compiler rejects operations without a realm context.
  All storage keys are prefixed with the realm ID. Property-based tests generate random
  cross-realm operation sequences to verify zero leakage (10,000+ cases in CI).
- *Horizontal privilege escalation*: Permissions are resolved at token-issue time by the
  RBAC engine and embedded in the JWT. The RBAC engine resolves against the user's role and
  group assignments stored in the realm; it cannot escalate beyond what was assigned.
- *Session hijacking after token expiry*: Sessions have a configurable `session_ttl`; the
  hot path checks expiration. Revoked sessions are rejected on lookup.

**Compromised realm administrator**

A realm admin with full API access to an application realm cannot:

- Read or modify data in other application realms (storage key prefix isolation enforced at
  compile time)
- Access or rotate the signing keys of other realms
- Authenticate to the system realm — admin users exist only in the system realm, and
  application-realm admin tokens are scoped to that application realm's signing key

A compromised realm admin can: create/delete users in that realm, revoke sessions, modify
client configurations, and read the audit log for that realm.

**Compromised host (disk/memory access without root)**

- All data written to disk (WAL and SST files) is encrypted using AES-256-GCM with a
  three-tier key hierarchy: host key → realm KEK → per-file DEK. A read of raw disk files
  yields ciphertext only.
- Signing key material is stored in `hearth.keys` encrypted by the host key (loaded from
  `HEARTH_MASTER_KEY` or auto-generated to `hearth.host_key`). Losing the host key makes
  all on-disk data permanently unrecoverable.
- In-memory signing key bytes are wrapped in `ZeroizingPkcs8`, which overwrites memory on drop.

### 2.3 Primary attack vectors

| Vector | Defense |
|--------|---------|
| Credential stuffing | Argon2id slow-hash; per-IP rate limit; per-account WAL-persisted lockout |
| Token forgery | Ed25519 only; no HS256; no `alg:none`; per-realm keys |
| Cross-realm data leakage | Compile-time `RealmId` enforcement; key prefix isolation; bounded scans |
| Replay attacks | JTI blocklist; single-use refresh tokens with theft detection |
| Enumeration timing attacks | Constant-time comparisons via `subtle`; uniform error responses |
| PKCE / OAuth flow manipulation | Mandatory PKCE for public clients; `state` round-trip CSRF protection; ACS URL pre-registration for SAML |
| Audit log tampering | SHA-256 hash chain; append-only storage API; no delete path |
| Key material exposure | `ZeroizeOnDrop` types; no `Debug`/`Display` for secrets; encrypted key registry |

### 2.4 Out-of-scope threats

The following are **not** within Hearth's threat model and are outside the scope of its
security controls:

| Out-of-scope threat | Reason |
|--------------------|--------|
| Physical access to the server | An attacker with physical access who can read `HEARTH_MASTER_KEY` from environment can decrypt all at-rest data. This is an OS/infrastructure concern. |
| Kernel or root compromise | A root-level attacker can read process memory directly. Memory-safe Rust and `ZeroizeOnDrop` reduce the exposure window but cannot eliminate it against a privileged attacker. |
| Supply-chain attacks on dependencies | Hearth uses `cargo deny` for license and advisory scanning. Dependency vulnerabilities are tracked and addressed upstream. They are not in scope for Hearth-specific security reports. |
| Social engineering and phishing | Authentication policy (MFA requirements, passkey enforcement) reduces exposure but cannot prevent a user from being deceived outside of Hearth's control plane. |
| IdP account compromise (federation) | When Hearth federates with an external IdP, the IdP's authentication decision is trusted. Hearth cannot detect or mitigate a compromised account at the IdP. |

### 2.5 WebAuthn attestation scope

Hearth supports `none` and `packed` self-attestation only. TPM and FIDO MDS attestation
chain validation are not implemented. This means Hearth cannot enforce policies that require
specific hardware authenticator models or certifications (e.g., FIPS 140-3 Level 2). If your
deployment's threat model requires attestation-level authenticator verification, this is a
known limitation. See [docs/guides/security-hardening.md](./security-hardening.md) for further discussion.

---

## 3. Cross-references

| Topic | Where to look |
|-------|--------------|
| Cryptographic primitive choices (algorithms, libraries, key sizes) | [SECURITY.md § Cryptographic Choices](../../SECURITY.md#cryptographic-choices) |
| Coordinated vulnerability disclosure process | [SECURITY.md § Reporting a Vulnerability](../../SECURITY.md#reporting-a-vulnerability) |
| Encryption at rest — host key, KEK, DEK hierarchy | [SECURITY.md § Encryption at Rest](../../SECURITY.md#encryption-at-rest) |
| Operational hardening (session TTL, SAML algorithm suite, secret rotation) | [docs/guides/security-hardening.md](./security-hardening.md) |
| Normative multi-tenancy isolation rules | [docs/specs/ARCHITECTURE.md § 7](../specs/ARCHITECTURE.md) |
| RBAC, roles, groups, permission embedding in JWT | [docs/specs/AUTHORIZATION.md](../specs/AUTHORIZATION.md) |
| OIDC / OAuth 2.0 / FAPI 2.0 security profile | [docs/specs/OIDC.md](../specs/OIDC.md) |
