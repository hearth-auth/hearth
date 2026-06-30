# Hearth — Data Retention Guide

**Audience:** operators with compliance obligations (SOC 2, ISO 27001, GDPR, HIPAA, CCPA).
**Goal:** Understand every data category Hearth stores, its default retention window, how to configure it, and the minimum-retention requirements your compliance framework may impose.

:::note[Related docs]
[Privacy Data Catalog](privacy.md) — storage locations and PII handling. [Audit Log Guide](auditing.md) — querying, exporting, and managing audit events. [Security Hardening](security-hardening.md) — at-rest encryption and key management.
:::

---

## Summary table

| Data category | Default retention | Configurable? | Automated cleanup? |
|---|---|---|---|
| Audit log events | 90 days | Yes (per-realm via API) | Yes (background pruner) |
| Sessions | 24 hours | Yes (`auth.session_ttl`) | Yes (TTL on write) |
| Access tokens | 15 minutes | Yes (`token.access_token_ttl`) | Yes (TTL; verified on use) |
| Refresh tokens | 7 days | Yes (`token.refresh_token_ttl`) | Yes (TTL; deleted on rotation) |
| Authorization codes | 10 minutes | Yes (`oidc.authorization_code_ttl`) | Yes (TTL on write) |
| Revoked JTI blocklist | Matches originating token TTL | No | Yes (storage TTL) |
| User records | Indefinite | No | No — explicit deletion only |
| Hashed passwords | Lifetime of user account | No | Deleted with user |
| Credential history | Lifetime of user account | No | Deleted with user |
| MFA secrets (TOTP/WebAuthn) | Lifetime of enrollment | No | Deleted with user or on unenroll |
| Email tombstone | 90 days after deletion | No | Yes (storage TTL) |
| Device fingerprints | 30 days (rolling) | Yes (`adaptive_mfa.recognition_window_days`) | Yes (background sweeper) |
| One-time tokens (reset/magic link) | 1 hour / 30 minutes | Yes (per-realm, capped) | Yes (TTL on write) |
| Audit log on realm deletion | Destroyed immediately | N/A | N/A — export first |

---

## 1. Audit log retention

### How it works

Every realm has an independent audit log protected by a SHA-256 hash chain. Retention is controlled per-realm via the Admin API. Events older than the configured window are pruned automatically by a background maintenance job; manual pruning is also available.

### Default

`90` days. A value of `0` means unlimited — events are never automatically pruned.

### Configuring retention

**Read the current policy:**

```bash
curl https://auth.example.com/admin/api/realms/{realm}/audit/config \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# → { "retention_days": 90 }
```

**Set a custom retention window (example: 1 year):**

```bash
curl -X PUT https://auth.example.com/admin/api/realms/{realm}/audit/config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 365}'
```

**Disable automatic pruning (unlimited retention):**

```bash
curl -X PUT https://auth.example.com/admin/api/realms/{realm}/audit/config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 0}'
```

**Force an immediate prune** (delete events beyond the current window right now):

```bash
curl -X POST https://auth.example.com/admin/api/realms/{realm}/audit/prune \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# → { "deleted": 1432 }
```

### Compliance benchmarks

| Framework | Minimum audit log retention | Recommended Hearth setting |
|---|---|---|
| SOC 2 Type II | 90 days | `"retention_days": 90` *(default)* |
| ISO 27001 | 1 year | `"retention_days": 365` |
| PCI DSS 4.0 | 1 year (12 months online) | `"retention_days": 365` |
| HIPAA | 6 years from date of creation | `"retention_days": 0` + external archive |
| GDPR | No fixed minimum — retain only as long as necessary | Document your lawful basis in the privacy notice |

:::note[HIPAA]
6-year retention exceeds what is practical to store entirely in the Hearth engine. Set `retention_days: 0` to disable pruning, and implement a scheduled export to long-term cold storage (S3 Glacier, Azure Archive, etc.). See [Audit Log Guide → Exporting events](auditing.md#exporting-events) for the NDJSON export endpoint.
:::

### Per-realm vs. global

Retention is configured per realm. If you operate multiple realms with different compliance postures (e.g., a HIPAA tenant alongside a standard SaaS tenant), set independent retention windows on each realm.

---

## 2. Session retention

### How it works

A session record is written when a user authenticates. It carries two deadlines:

- **`absolute_deadline`** — the session expires at this timestamp regardless of activity, controlled by `auth.session_ttl`.
- **`idle_deadline`** — the session expires after a period of inactivity (set at creation; renewing the session resets it).

Sessions are not soft-expired. When either deadline elapses, the session record is deleted from storage.

### Default

`24h` (`auth.session_ttl`).

### Configuring

In `hearth.yaml`:

```yaml
auth:
  session_ttl: "8h"       # shorten for high-security environments
```

Per-realm override:

```yaml
realms:
  acme-corp:
    auth:
      session_ttl: "4h"
```

### Compliance implications

HIPAA §164.312(a)(2)(iii) requires automatic logoff after inactivity. Hearth's `idle_deadline` satisfies this. Set `session_ttl` and the idle window to values that meet your organization's Minimum Necessary Access policy. 30-minute idle timeout is a common HIPAA-aligned default.

---

## 3. Token retention

### Access tokens

Access tokens are short-lived JWTs. They are **not stored** in Hearth — they are verified by signature alone. The server accepts them until they pass their `exp` claim. No background cleanup is needed.

| Config key | Default | Per-realm override |
|---|---|---|
| `token.access_token_ttl` | `"15m"` | `realms.<name>.auth.token.access_token_ttl` |

### Refresh tokens

Refresh tokens are stored as a SHA-256 hash of the current token in a grant family record (`oauth:family:{family_id}`). The plaintext refresh token is never persisted. On rotation, the old hash is replaced; on revocation, the family record is deleted. A background sweep removes grant families whose `expires_at` has elapsed.

| Config key | Default | Per-realm override |
|---|---|---|
| `token.refresh_token_ttl` | `"7d"` | `realms.<name>.auth.token.refresh_token_ttl` |

### Authorization codes

Authorization codes are stored as SHA-256 hashes and expire after a short window. The plaintext code is never persisted.

| Config key | Default |
|---|---|
| `oidc.authorization_code_ttl` | `"10m"` |

### Revoked JTI blocklist

When a client-credentials access token is explicitly revoked (via `POST /oauth/revoke`), its JTI claim is added to the revocation blocklist under `oauth:revjti:{jti}`. This record carries a TTL equal to the originating token's remaining lifetime. Once the token would have expired naturally, the blocklist entry is automatically removed by the storage engine's TTL sweep. No operator action is required.

### One-time tokens (password reset, magic link)

Only the SHA-256 hash of each token is stored; the plaintext is delivered to the user by email once and never written to storage.

| Token type | Default TTL | Hard cap |
|---|---|---|
| Password reset | `1h` | 1 hour (A-14, cannot exceed) |
| Magic link | `30m` | 30 minutes (A-14, cannot exceed) |
| Email verification | Follows magic link TTL | — |

The `allow_unsafe_ttl: true` per-realm flag removes the hard caps for development environments. Do not set this in production.

---

## 4. User data retention

### Retention policy

User records have **no automatic expiry**. A user account persists indefinitely until an operator explicitly deletes it via the Admin UI or API:

```bash
# Permanent deletion — irreversible
curl -X DELETE https://auth.example.com/admin/api/realms/{realm}/users/{user_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

This cascades to all associated data: the credential record, credential history, MFA secrets, WebAuthn credentials, sessions, device fingerprints, and organization memberships.

### GDPR right to erasure (Art. 17)

Hearth's user deletion API satisfies a GDPR erasure request for the core identity record. Operators are responsible for:

1. Triggering deletion in response to a verified erasure request.
2. Purging any copies of user data held in external systems (CRMs, analytics, data warehouses) that were populated from Hearth-issued JWTs or API responses.
3. Documenting the email tombstone reservation (see §5 below) in their privacy notice.

---

## 5. Email tombstone (A-20)

### What it is

When a user account is deleted, Hearth reserves the email address for **90 days** under the key `email:reserved:{normalized_email}`. During this window, the same email address cannot be used to register a new account.

### Why it exists

This prevents account-cycling attacks where a bad actor registers, abuses an account, deletes it, and immediately re-registers under the same email to obtain a fresh identity. The 90-day window is hardcoded and is not operator-configurable.

After the 90-day TTL elapses, the tombstone record is physically removed during SST compaction. There is no PII in the tombstone value — only the normalized email in the key.

### Privacy notice guidance

Operators subject to GDPR or CCPA must document this behavior in their privacy notice. Example disclosure language:

> "When you delete your account, your email address is temporarily reserved for 90 days to prevent account abuse. During this period your email address cannot be used to create a new account. After 90 days the reservation is removed and no further record of your email address is retained by [Product Name]."

---

## 6. Audit log on realm deletion

:::danger
Realm deletion permanently destroys the audit log for that realm. There is no recovery path.
:::

When `DELETE /admin/api/realms/{realm_id}` is called, Hearth performs a cascading delete that includes all audit log events for the realm. This is by design — the audit chain is realm-scoped and has no meaning independent of its realm.

**If you must retain audit records after deleting a realm** (e.g., for a compliance hold), export the audit log before issuing the deletion:

```bash
# Export all events as NDJSON before deletion
curl -s "https://auth.example.com/admin/realms/{realm}/audit/export?format=ndjson" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o "audit-{realm}-$(date +%F).ndjson"

# Verify export is non-empty
wc -l "audit-{realm}-$(date +%F).ndjson"

# Then delete the realm
curl -X DELETE https://auth.example.com/admin/api/realms/{realm_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

For frameworks with multi-year retention requirements (HIPAA, PCI DSS), maintain archived NDJSON exports in durable cold storage even after realm deletion.

---

## 7. Credential history

### What is retained

When a user changes their password, the previous Argon2id or PBKDF2 hash is appended to the credential history record (`cred:history:{user_uuid}`). Only hashes are stored; plaintext passwords are never retained.

### Retention duration

Credential history has **no automatic expiry**. It is retained for the lifetime of the user account and is deleted as part of cascading user deletion. There is no per-realm configuration for credential history depth.

### Purpose

The history is used exclusively to enforce password-reuse policies. It is not exposed via any API or audit log.

---

## 8. Device fingerprint retention

### What is retained

When adaptive MFA is enabled, Hearth stores a device fingerprint key `dfp:user:{user_uuid}:{hmac_sha256_hex}`. The key is an HMAC-SHA256 of the raw signals (IP address + user-agent string). **The raw IP address and user-agent string are never written to storage.**

### Default retention window

`30` days (rolling). A fingerprint seen within the recognition window is refreshed; one that has not been seen within the window expires.

### Configuring

```yaml
realms:
  acme-corp:
    auth:
      adaptive_mfa:
        recognition_window_days: 14   # shorten for higher-security environments
```

### Cleanup

A background sweeper scans all `dfp:user:*` keys approximately hourly and deletes expired entries. No operator action is required.

**Manual deletion** (e.g., for a GDPR Art. 17 erasure request on a specific user's devices):

```bash
DELETE /admin/api/realms/{realm}/users/{user_id}/device-fingerprints
```

This endpoint is also called automatically as part of the full user deletion cascade.

---

## 9. Compliance checklist

Use this checklist when preparing for an audit or completing a Data Protection Impact Assessment (DPIA).

### SOC 2 Type II

- [ ] Audit log `retention_days` ≥ 90 for all in-scope realms (default satisfies this).
- [ ] Audit log integrity verification scheduled periodically (`POST /admin/api/realms/{realm}/audit/verify`).
- [ ] Session TTL documented in access control policy.
- [ ] Admin API access restricted to named admin accounts; access logged.

### ISO 27001 (A.12.4 — Logging and monitoring)

- [ ] Audit log `retention_days` set to `365` or higher for all in-scope realms.
- [ ] Audit logs exported and archived externally (in case of realm deletion).
- [ ] Alerting configured on `login_failed` events exceeding threshold.

### HIPAA (§164.312)

- [ ] Audit log `retention_days` set to `0` (unlimited) with external archival to cold storage for 6-year compliance.
- [ ] Session `idle_deadline` set to ≤30 minutes (`auth.session_ttl`).
- [ ] Automatic session logoff documented in your HIPAA policies.
- [ ] Email tombstone disclosure added to Business Associate Agreement (BAA) and privacy notice.
- [ ] User deletion procedure documented for responding to account-termination requests.

### GDPR / CCPA

- [ ] Privacy notice documents: email tombstone (90 days), device fingerprint (30 days), session TTL.
- [ ] Data erasure procedure in place: `DELETE /admin/api/realms/{realm}/users/{user_id}` for right-to-erasure requests.
- [ ] Audit log retention justified under Article 6 lawful basis (legitimate interest for security monitoring).
- [ ] Downstream systems that receive Hearth JWT claims have independent deletion procedures.
- [ ] Data Processing Agreement (DPA) references Hearth's sub-processor role if applicable.

---

## 10. Export and archival recommendations

For frameworks requiring retention beyond what is practical to keep in the Hearth engine, establish a scheduled export pipeline:

```bash
#!/usr/bin/env bash
# Example: nightly audit export for long-term archival
REALM="production"
DATE=$(date +%F)
ARCHIVE_DIR="/mnt/audit-archive/${REALM}"

mkdir -p "$ARCHIVE_DIR"

curl -sf "https://auth.example.com/admin/realms/${REALM}/audit/export" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  --data-urlencode "start_date=${DATE}" \
  --data-urlencode "end_date=${DATE}" \
  -o "${ARCHIVE_DIR}/audit-${DATE}.ndjson"

# Optionally ship to S3 / Azure Blob / GCS for long-term cold storage
# aws s3 cp "${ARCHIVE_DIR}/audit-${DATE}.ndjson" s3://your-audit-bucket/hearth/${REALM}/
```

:::tip
Set `retention_days` to `0` (unlimited) while standing up an external archive pipeline, then reduce it once you have confirmed the pipeline is healthy and data is flowing correctly.
:::
