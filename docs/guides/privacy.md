# Hearth — Operator PII Handling & Privacy Data Catalog

This document is the authoritative data catalog for Hearth operators: what identity
data the server stores, where it lives in the storage engine, how it is protected
at rest, which API surfaces expose it, and what Hearth explicitly does **not** store.

It satisfies the §15.2 compliance gate and provides the lawful-basis narrative
operators need when writing their own GDPR/CCPA privacy notices.

---

## 1. Data Categories and Storage Locations

All data is stored in the realm-scoped WAL/SST engine.  Every key is prefixed
with the owning `RealmId`, except signing keys which live in the **system realm**
(`RealmId::nil()`).  Key patterns use pseudo-BNF notation below.

### 1.1 User Records

| Category | Storage Key | Format | Notes |
|----------|-------------|--------|-------|
| Email address | `usr:email:{normalized_email}` | Normalized UTF-8 string (in the key itself) | Index maps email → `UserId` |
| Full user record | `usr:id:{user_uuid}` | JSON | Contains: `email`, `display_name`, `first_name`, `last_name`, `status`, `email_verified`, `phone_verified`, `attributes`, `created_at`, `updated_at` |
| Custom attributes | inside `usr:id:…` value | JSON map (`BTreeMap<String,String>`) | Operator-defined key/value pairs per realm |

### 1.2 Credentials

| Category | Storage Key | Format | Notes |
|----------|-------------|--------|-------|
| Hashed password | `cred:user:{user_uuid}` | JSON | `algorithm` (enum) + `hash` (PHC string) + `pepper_version` — **hash only; plaintext never stored** |
| Credential history | `cred:history:{user_uuid}` | JSON array of PHC strings | Previous hashes retained to prevent password reuse; hash only |

### 1.3 Sessions

| Category | Storage Key | Format | Notes |
|----------|-------------|--------|-------|
| Session record | `ses:id:{session_uuid}` | JSON | Contains: `user_id`, `realm_id`, `ip_address` (nullable), `user_agent_raw` (nullable), `device_label` (nullable), `idle_deadline`, `absolute_deadline` |
| Session user-index | `ses:user:{user_uuid}:{session_uuid}` | empty / TTL marker | Lookup index; no PII in value |
| Session-version counter | `ssv:sid:{session_uuid}` | little-endian u64 | Used to invalidate JWTs without storing them; no PII |

### 1.4 MFA Secrets

| Category | Storage Key | Format | Notes |
|----------|-------------|--------|-------|
| TOTP secret + recovery codes | `mfa:totp:{user_uuid}` | JSON | Contains base32 TOTP shared secret and recovery-code **hashes** (Argon2id); plaintext codes returned once at enrollment, never persisted |
| WebAuthn credential | `webauthn:cred:{user_uuid}:{credential_id_b64url}` | JSON | Credential ID, public key (COSE), counter, AAGUID, attestation statement, `rp_id`, `user_handle`, created_at |
| WebAuthn discoverable index | `webauthn:disc:{credential_id_b64url}` | JSON (`UserId`) | Maps credential ID → user; supports username-less assertion |
| SMS OTP (in-flight) | `sms:pending_otp:{nonce_hex}` | JSON | Hashed OTP code + expiry; nonce is 128-bit CSPRNG; short-lived (minutes) |
| SMS resend throttle | `sms:resend_count:{phone_number}` | count/expiry | Phone number appears in key for throttling; 15-min sliding window |

### 1.5 OAuth / OIDC Artifacts

| Category | Storage Key | Format | Notes |
|----------|-------------|--------|-------|
| OAuth client registration | `oauth:client:{client_uuid}` | JSON | `client_name`, `redirect_uris`, `client_secret_hash` (Argon2id; plaintext never stored), grant types, allowed scopes |
| Authorization code | `oauth:code:{sha256_hex_of_code}` | JSON | Plaintext code never stored; key is SHA-256 of the code issued to the client |
| Refresh token (grant family) | `oauth:family:{family_id}` | JSON | `current_refresh_hash` (SHA-256 of current token) + `session_id`; plaintext refresh token never stored |
| OAuth consent | `oauth:consent:{user_uuid}:{client_uuid}` | JSON | Granted scopes; no raw credentials |
| Device code | `oauth:device:{device_code_hash}` | JSON | Hash of device code |
| Revoked JTI blocklist | `oauth:revjti:{jti}` | TTL marker | For sessionless client-credentials revocation; no PII in value |
| In-flight auth request | `oauth:pending_auth:{ticket_uuid}` | JSON | 10-min TTL; contains authorization parameters |

### 1.6 One-Time Tokens (All Hash-Only)

| Category | Storage Key | Notes |
|----------|-------------|-------|
| Email verification | `email:verify:{sha256_hex}` | SHA-256 of plaintext token |
| Email-change pending | `email:change:{sha256_hex}` | SHA-256 of plaintext token |
| Password reset | `rst:token:{sha256_hex}` | SHA-256 of plaintext token |
| Magic link | `magic:link:{sha256_hex}` | SHA-256 of plaintext token |

In every case, only the hash is persisted.  The plaintext token is returned to
the user once via email, then discarded.

### 1.7 Device Fingerprints

| Category | Storage Key | Format | Notes |
|----------|-------------|--------|-------|
| Device fingerprint | `dfp:user:{user_uuid}:{hmac_sha256_hex}` | 8-byte i64 (Unix-seconds expiry) | Key is HMAC-SHA256 of raw signals (IP + UA); **raw IP and user-agent are never written to storage** |

### 1.8 Organizations and Memberships

| Category | Storage Key | Format | Notes |
|----------|-------------|--------|-------|
| Organization record | `org:id:{org_uuid}` | JSON | Name, slug, description, status, config |
| Membership (org→user) | `orgm:org:{org_uuid}:user:{user_uuid}` | JSON | Role, `invited_by`, `joined_at` |
| Membership (user→org) | `orgm:user:{user_uuid}:org:{org_uuid}` | JSON | Bidirectional index for O(1) lookups |
| Invitation | `orgi:id:{inv_uuid}` | JSON | **Invitee email address** (PII), `token_hash` (SHA-256), org_id, status, expires_at |
| Invitation token index | `orgi:token:{sha256_hex}` | JSON (`InvitationId`) | Hash-only; plaintext token delivered by email |
| Invitation email dedup | `orgi:org:{org_uuid}:email:{email}` | empty | Email appears in key for idempotency; no additional data |

### 1.9 Realm Signing Keys

| Category | Storage Key | Scope | Notes |
|----------|-------------|-------|-------|
| Active signing key (Ed25519) | `realm:key:{realm_uuid}` | **System realm** | PKCS#8 DER; protected by `ZeroizingPkcs8` in memory |
| Retiring signing keys | `realm:retiring:{realm_uuid}:{deadline}:{key_id}` | **System realm** | Grace-period keys kept for in-flight token validation |

Signing keys are **never realm-scoped** — they live in the system realm
(`RealmId::nil()`) and are inaccessible to tenant realm scans.

### 1.10 Audit Events

Stored as a SHA-256 hash chain under `audit:evt:{realm_uuid}:{seq}:{idx}` (see
[§6](#6-audit-log-data) for field details).

---

## 2. At-Rest Protection

### 2.1 What is Hashed

| Data | Algorithm | Notes |
|------|-----------|-------|
| Passwords | Argon2id, 19 MiB memory, 2 iterations, 1 parallelism | OWASP 2023 parameters; stored in PHC format |
| Passwords (Bcrypt import) | Bcrypt (`$2y$`/`$2b$`) | Verify-only; upgraded to Argon2id on next `change_password` |
| Passwords (Keycloak import) | PBKDF2-HMAC-SHA256 | Verify-only; upgraded to Argon2id on next `change_password` |
| OAuth client secrets | Argon2id | Same parameters as passwords |
| TOTP recovery codes | Argon2id | Plaintext returned once at enrollment |
| Refresh tokens | SHA-256 | Stored as `current_refresh_hash` inside grant family |
| Authorization codes | SHA-256 | Key = `oauth:code:{sha256}` |
| One-time tokens (verify, reset, magic) | SHA-256 | Keys only; no value stored |
| Invitation tokens | SHA-256 | `token_hash` field in `Invitation` record |

All hash comparisons use constant-time equality (`subtle::ConstantTimeEq`).

### 2.2 What is Encrypted

Hearth does **not** apply application-level encryption to WAL/SST files.
Operators requiring encryption-at-rest MUST use OS-level or disk-level
encryption (e.g., dm-crypt/LUKS, encrypted volumes, or cloud provider disk
encryption).  The WAL itself provides integrity via CRC-32 framing but not
confidentiality.

### 2.3 What is Plaintext in Storage

| Data | Location | Rationale |
|------|----------|-----------|
| Email address | `usr:id:…` value and `usr:email:…` key | Required for login lookup; must be readable |
| Display name, first/last name | `usr:id:…` | Required for ID token claims |
| Session IP address and user-agent | `ses:id:…` | Required for session management UI and audit |
| TOTP shared secret | `mfa:totp:…` (base32 string) | Required for server-side TOTP validation (RFC 6238 requires knowing the secret) |
| WebAuthn public key | `webauthn:cred:…` | Public key by definition; required for assertion verification |
| Organization name, slug | `org:id:…` | Non-sensitive metadata |
| Invitee email | `orgi:id:…` | Required to match against arriving users |

### 2.4 Zeroize-on-Drop for In-Memory Sensitive Types

The following types implement `Zeroize`/`ZeroizeOnDrop` and will overwrite
their memory when dropped.  They do **not** implement `Debug`, `Display`, or
`Serialize` in ways that reveal their contents.

| Type | Sensitive data protected |
|------|--------------------------|
| `CleartextPassword` | Raw password bytes during hashing |
| `PepperKey` | Server-side HMAC-SHA256 pepper bytes |
| `TotpSecret` | TOTP shared secret bytes during provisioning/verification |
| `ZeroizingPkcs8` (inside `SigningKey`) | Ed25519 PKCS#8 DER signing key material |
| `IdpClientSecret` | IdP OAuth client secret for federation |
| `ApiKey` (email transport) | SendGrid / Postmark / Mailgun API keys |

---

## 3. Access Controls

All admin endpoints require a valid `Authorization: Bearer <token>` with
`admin` role in the realm (or a system-level admin token from
`POST /admin/bootstrap` in dev mode).

### 3.1 User PII Endpoints

| Endpoint | PII Exposed | Auth Required |
|----------|-------------|---------------|
| `GET /admin/realms/{rid}/users` | `email`, `display_name`, `first_name`, `last_name`, `status`, `created_at` | Admin bearer token |
| `GET /admin/realms/{rid}/users/{id}` | Full user record including all name fields, `attributes`, `email_verified` | Admin bearer token |
| `POST /admin/realms/{rid}/users` | Accepts email + name + optional password (hashed before storage) | Admin bearer token |
| `PATCH /admin/realms/{rid}/users/{id}` | Updates user fields | Admin bearer token |
| `DELETE /admin/realms/{rid}/users/{id}` | Triggers deletion + 90-day email tombstone (see §5) | Admin bearer token |
| `GET /admin/realms/{rid}/users/{id}/sessions` | Session list including `ip_address` and `user_agent_raw` | Admin bearer token |
| `DELETE /admin/realms/{rid}/users/{id}/sessions/{sid}` | Session revocation | Admin bearer token |
| `GET /admin/realms/{rid}/users/{id}/credentials` | Credential metadata: algorithm, created_at — **hash value is `[REDACTED]` in all serialized output** | Admin bearer token |
| `POST /admin/realms/{rid}/users/{id}/set-password` | Accepts plaintext password; hashes immediately, discards plaintext | Admin bearer token |

### 3.2 Organization and Invitation Endpoints

| Endpoint | PII Exposed | Auth Required |
|----------|-------------|---------------|
| `GET /admin/realms/{rid}/orgs` | Organization names, slugs | Admin bearer token |
| `GET /admin/realms/{rid}/orgs/{id}/members` | User IDs + membership roles | Admin bearer token |
| `GET /admin/realms/{rid}/orgs/{id}/invitations` | Invitee **email addresses**, invitation status, expiry | Admin bearer token |

### 3.3 Authenticated User Self-Service Endpoints

| Endpoint | PII Exposed | Auth Required |
|----------|-------------|---------------|
| `GET /v1/me` | Caller's own profile | Valid session token |
| `GET /v1/me/permissions` | Caller's own RBAC permissions | Valid session token |
| `GET /v1/me/sessions` | Caller's own session list (includes IP/UA) | Valid session token |

### 3.4 Audit Log Endpoints

| Endpoint | PII Exposed | Auth Required |
|----------|-------------|---------------|
| `GET /admin/realms/{rid}/audit-log` | `actor` (user ID), `resource_id`, `metadata` (may include IP — see §6) | Admin bearer token |

---

## 4. What Hearth Does NOT Store

| Item | Notes |
|------|-------|
| Plaintext passwords | Never written to WAL, logs, or any in-process data structure that outlives the hashing operation |
| Plaintext OAuth / OIDC tokens | Bearer tokens are JWTs validated by signature + WAL-side counter; refresh tokens, auth codes, and one-time tokens stored as SHA-256 hashes only |
| Plaintext TOTP recovery codes | Returned once at enrollment, then discarded; only Argon2id hashes stored |
| Plaintext invitation tokens | SHA-256 hash stored; plaintext delivered by email only |
| Raw IP address or user-agent in device fingerprint | HMAC-SHA256 of `(IP + UA)` stored; the raw strings are not written to storage |
| Signing key material outside the system realm | Signing keys are scoped exclusively to the system realm WAL; tenant realm scans cannot reach them |
| Secrets in log output | `tracing` instrumentation is explicitly forbidden from logging passwords, tokens, keys, or PII at any log level |

---

## 5. 90-Day Email Tombstone (A-20)

When a user account is deleted (`DELETE /admin/realms/{rid}/users/{id}` or
equivalent), Hearth writes a **`StoredEmailReservation`** record:

```
Key:   email:reserved:{normalized_email}
Value: { "normalized_email": "...", "deleted_at": <timestamp>, "expires_at": <timestamp> }
```

`expires_at` is set to **90 days after `deleted_at`**.  During this window,
any attempt to register a new account with the same email address is rejected.

### Purpose (Abuse Prevention)

The tombstone exists to prevent account-cycling abuse:

- An adversary registers, sends abuse, deletes, and immediately re-registers
  the same email to avoid blocklists.
- The 90-day hold closes this window and preserves the audit trail linking
  historical events to the deleted identity.

### Lawful Basis Options for Operators

Operators running Hearth in GDPR- or CCPA-regulated contexts MUST document a
lawful basis for retaining the deleted user's email address for up to 90 days.
Common choices:

| Basis | When appropriate |
|-------|-----------------|
| **Legitimate interests** (GDPR Art. 6(1)(f)) | Fraud and abuse prevention; re-registration attack mitigation; data integrity during legal hold periods |
| **Legal obligation** (GDPR Art. 6(1)(c)) | Where applicable law requires audit retention for a defined period |
| **Compliance with a contractual obligation** | Where ToS or an applicable contract requires post-deletion processing |

Operators SHOULD disclose the tombstone retention in their privacy notice:
> "When you delete your account, we retain a pseudonymised record of your
> registered email address for up to 90 days for fraud and abuse prevention
> purposes. This record cannot be used to contact you or to restore your
> account."

After `expires_at`, the tombstone record is eligible for compaction and will
be physically removed from storage in the next compaction pass.

### Behavior on Realm Deletion

When a realm is deleted (`DELETE /admin/realms/{id}` or via `hearth migrate`),
the cascade sweep **explicitly purges `email:reserved:` keys** as part of the
same atomic sequence that removes users, sessions, credentials, and OAuth
artifacts.  No email tombstone survives a realm deletion — the residual PII
lifetime is bounded by the realm's lifetime, not by the 90-day window.

Operators performing a full tenant offboard (realm deletion) can therefore
assert **zero email-address residual** after the cascade completes.  The two
integration tests `delete_realm_leaves_no_residual_pii` and
`delete_user_leaves_no_residual_pii` (in `tests/users.rs`) codify and verify
this guarantee.

### Related Tombstones (Non-PII)

Two other post-delete reservation records exist and are handled symmetrically:

| Key prefix | Written by | Content | Cleaned by |
|------------|-----------|---------|-----------|
| `slug:org:{realm}:{slug}` | `delete_organization` | Org slug string (A-5 cooldown) | `delete_realm` cascade |
| `slug:realm:{slug}` | `delete_realm` | Realm name string (A-5 cooldown) | Stays in system realm |
| `dfp:user:{uuid}:{hmac}` | Login / `record_device_fingerprint` | HMAC-SHA256 of IP+UA — **no raw PII** | `delete_user` + `delete_realm` cascade |

Neither org-slug reservations nor device fingerprint entries contain plaintext
PII and do not require a separate lawful basis.  They are documented here for
completeness so operators can verify storage cleanliness via prefix scans.

---

## 6. Audit Log Data

### 6.1 AuditEvent Schema

```
{
  "id":              UUID,
  "realm_id":        UUID,
  "actor":           String,   // user ID or "system" — PII (user identifier)
  "action":          String,   // AuditAction enum variant (see §6.2)
  "resource_type":   String,   // e.g. "user", "session", "realm", "org"
  "resource_id":     String,   // UUID of the affected entity — PII (target identifier)
  "timestamp":       i64,      // Unix microseconds
  "metadata":        Object?,  // free-form JSON — see §6.3
  "integrity_hash":  String    // SHA-256 chain link
}
```

The audit log forms a **hash chain**: each event's `integrity_hash` is
`SHA-256(prev_hash || event_payload)`, seeded from `"genesis"` per realm.
This makes tampering detectable.

**Default retention:** 90 days (configurable via `audit.retention_days` in
`hearth.yaml`; see [`auditing.md`](auditing.md)).  Log pruning intentionally
breaks the hash chain for pruned entries.

### 6.2 AuditAction Variants

The following action types are recorded.  PII-sensitive actions are marked **★**.

| Category | Action | PII in record |
|----------|--------|--------------|
| Users | `UserCreated` ★ | `actor` = admin ID, `resource_id` = new user ID |
| | `UserUpdated` ★ | Same; `metadata` may include changed field names |
| | `UserDeleted` ★ | `resource_id` = deleted user ID |
| | `CredentialSet` ★ | `resource_id` = user ID; no credential data in metadata |
| | `EmailVerified` ★ | `resource_id` = user ID |
| Sessions | `SessionCreated` ★ | `resource_id` = session ID; `metadata` may include `{"ip": "…"}` |
| | `SessionRevoked` ★ | `resource_id` = session ID |
| | `SessionsRevoked` ★ | `metadata` = `{"user_id":"…","count":N,"trigger":"…"}` |
| | `SessionEvicted` | `metadata` = `{"user_id":"…","session_id":"…","reason":"…"}` |
| Tokens | `TokenIssued` | `resource_id` = session ID; no token material |
| | `TokenRefreshed` | `resource_id` = session ID |
| Realms | `RealmCreated/Updated/Deleted` | `resource_id` = realm ID |
| RBAC | `RoleAssigned/Revoked` ★ | `resource_id` = user ID; `metadata` = `{"role":"…"}` |
| | `GroupMemberAdded/Removed` ★ | `metadata` = `{"group_id":"…","member_id":"…"}` |
| | `GroupMemberRoleChanged` ★ | `metadata` = `{"previous_role":"…","new_role":"…"}` |
| OAuth | `ConsentGranted/Denied/Revoked` ★ | `resource_id` = user ID; `metadata` = `{"client_id":"…"}` |
| Federation | `FederationJitProvisioned` ★ | `resource_id` = new user ID |
| | `SamlLoginInitiated/Completed/Rejected` | `resource_id` = session or ticket ID |
| Orgs | `OrgCreated/Updated/Deleted` | `resource_id` = org ID |

### 6.3 PII in the Metadata Field

`metadata` is a free-form `serde_json::Value`.  No automatic field-level
redaction is applied before storage.  The fields currently documented in the
codebase that may contain PII are:

| Metadata key | PII type | Appears in |
|--------------|----------|-----------|
| `ip` | IP address | `SessionCreated` |
| `user_id` | User identifier | `SessionsRevoked`, `SessionEvicted` |
| `session_id` | Session identifier | `SessionEvicted` |
| `member_id` | User identifier | `GroupMemberAdded/Removed/RoleChanged` |
| `object_id` | Entity identifier | Authz/RBAC events |
| `client_id` | OAuth client ID | Consent events |

Operators who need to redact specific fields before archival should implement
a post-processing pipeline on the audit query endpoint.  Hearth itself does not
redact metadata.

---

## 7. Summary Table

| Data item | Stored? | Form | Where |
|-----------|---------|------|-------|
| Email address | Yes | Plaintext (normalized) | `usr:id:…`, `usr:email:…` key |
| Password | Yes | Argon2id PHC hash | `cred:user:…` |
| Plaintext password | **No** | — | Discarded after hashing |
| TOTP secret | Yes | Plaintext base32 | `mfa:totp:…` |
| TOTP recovery codes | Yes | Argon2id hashes | `mfa:totp:…` |
| WebAuthn public key | Yes | COSE JSON | `webauthn:cred:…` |
| Session token (JWT) | **No** | — | JWT verified by signature + WAL counter |
| Session record (IP, UA) | Yes | Plaintext JSON | `ses:id:…` |
| OAuth client secret | Yes | Argon2id hash | `oauth:client:…` |
| OAuth bearer / refresh tokens | **No** | — | Only SHA-256 hash of refresh stored |
| Auth codes, magic links, reset tokens | Yes (hash only) | SHA-256 | Key-addressed |
| Device fingerprint (raw IP/UA) | **No** | — | Only HMAC-SHA256 stored |
| Deleted-user email tombstone | Yes | Plaintext (in key + value) | `email:reserved:…` — 90 days |
| Audit events | Yes | JSON | `audit:evt:…` — configurable retention (default 90 days) |
| Org membership | Yes | JSON | `orgm:…` (bidirectional indexes) |
| Invitation email | Yes | Plaintext | `orgi:id:…`, `orgi:org:…` key |
| Realm signing key | Yes | PKCS#8 DER | System realm only; Zeroize-on-drop in memory |
| Plaintext tokens / secrets in logs | **No** | — | `tracing` policy prohibits PII at any level |

---

## 8. Related Documents

- [`docs/guides/auditing.md`](auditing.md) — Configuring audit log retention, querying events, integrity verification
- [`docs/guides/security-hardening.md`](security-hardening.md) — TLS, mTLS, cipher hardening, HTTP headers
- [`docs/guides/ABUSE.md`](ABUSE.md) — Rate limiting, credential-attack mitigations, abuse-prevention controls
- [`docs/specs/ARCHITECTURE.md`](../specs/ARCHITECTURE.md) — §15.2 approved crates; storage engine guarantees
- [`docs/specs/AUTHORIZATION.md`](../specs/AUTHORIZATION.md) — RBAC roles, permissions, JWT claims schema
- [`docs/specs/CONFIGURATION.md`](../specs/CONFIGURATION.md) — Full `hearth.yaml` reference including `audit.retention_days` and `security.rate_limiting`
