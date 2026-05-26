# Security Hardening Guide

This guide documents security configuration recommendations for Hearth deployments. It is
aimed at production operators and complements the default configuration documented in
[CONFIGURATION.md](../specs/CONFIGURATION.md).

## Session TTL

### Default and recommended values

The `session_ttl` option controls how long a session remains valid after issuance or last
refresh. The built-in default is `24h`.

| Deployment context | Recommended `session_ttl` |
|---|---|
| High-security / admin consoles | `1h`–`4h` |
| Standard enterprise SaaS | `8h`–`24h` |
| Consumer applications | `7d`–`30d` |
| **Maximum recommended** | **`30d`** |

**Do not set `session_ttl` above 30 days.** Long-lived sessions increase the window of
exposure for stolen session tokens and make revocation less effective as a security control.
There is no hard upper limit enforced by Hearth — operators are responsible for choosing a
value appropriate for their threat model.

```yaml
auth:
  session_ttl: "8h"       # reasonable default for enterprise SaaS

realms:
  - name: internal-tools
    session_ttl: "4h"     # tighter for admin interfaces
  - name: customer-portal
    session_ttl: "30d"    # maximum recommended for consumer contexts
```

### Access and refresh token TTLs

Refresh tokens can extend session validity beyond the access token TTL. Ensure
`refresh_token_ttl` is set intentionally and is not longer than your `session_ttl`.

```yaml
auth:
  access_token_ttl: "15m"    # short-lived, minimises exposure window
  refresh_token_ttl: "8h"    # drives actual session length
  session_ttl: "8h"
```

---

## SAML 2.0

### Algorithm suite

Hearth's SAML implementation locks the algorithm suite to **Exclusive C14N 1.0 +
SHA-256 digests + RSA-SHA256 signatures**. SHA-1 digests and RSA-SHA1 signatures are
rejected unconditionally — algorithm downgrade is a common SAML attack vector.

### Attestation limitations

Hearth's WebAuthn implementation does not validate TPM or FIDO MDS attestation chains.
Only `none` and `packed` self-attestation are supported. This is a deliberate design choice:
- TPM/x5c attestation requires a live X.509 chain validation against the FIDO Metadata Service
  (MDS), which adds significant complexity and an external runtime dependency.
- `packed` self-attestation is the correct choice for most deployments; it verifies the
  authenticator's signature without requiring knowledge of the authenticator's make and model.

**Impact:** Hearth cannot enforce "only hardware authenticators from certified vendors"
policies. If your threat model requires attestation-level authenticator verification
(e.g., FIPS 140-3 Level 2 hardware requirement), Hearth's current WebAuthn implementation
is not a fit.

### SAML ACS URL validation

Hearth validates that the `AssertionConsumerServiceURL` in incoming `AuthnRequest` messages
matches a pre-registered ACS URL. Do not configure wildcard ACS URLs; always register the
exact endpoint URL.

---

## Secrets Management

### Host key

The host key (`HEARTH_MASTER_KEY`) encrypts all realm Key Encryption Keys (KEKs) at rest. It
is the most sensitive secret in a Hearth deployment.

- **Never commit the host key to version control.**
- Store it in a secrets manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager).
- Inject it at runtime via the `HEARTH_MASTER_KEY` environment variable.
- Rotate it by re-wrapping all realm KEKs (Hearth supports O(n files) rotation — only DEK
  headers are re-wrapped, not bulk data).

### OAuth client secrets

OAuth client secrets are stored as Argon2id hashes, not plaintext. Treat them like passwords:
- Generate at least 32 bytes of cryptographically random material.
- Rotate them immediately if compromised (Hearth supports multiple active secrets per client
  for zero-downtime rotation).

### Device fingerprint HMAC secret

Adaptive MFA (`adaptive_mfa.enabled = true` on a realm) derives a per-device fingerprint by
computing `HMAC-SHA256(secret, "{user_id}:{ip_/24}:{user_agent_normalized}")` and storing the
hex digest in the Redis device-recognition cache. The `fingerprint_hmac_secret` is the HMAC
key for that derivation. **A weak or compromised secret allows an attacker who knows a
victim's `{user_id, ip_/24, user_agent}` tuple to forge the fingerprint and bypass step-up
MFA on an unrecognised device.** Treat it accordingly.

**Scope:** the secret is **per-realm** — each realm has its own value. Rotating one realm's
secret does not affect any other realm. There is no global Hearth-level fingerprint secret.

**Generation.** Hearth enforces a **hard 32-byte minimum** on this field (NIST SP 800-107:
HMAC keys ≥ hash output length, i.e. ≥ 32 bytes for SHA-256). A secret shorter than 32
bytes with `adaptive_mfa.enabled = true` is a configuration error — Hearth fails closed at
load time with a message naming the actual length, *not* fail-open. See HEA-861. Use a
CSPRNG to produce ≥ 32 bytes of randomness, encoded as Base64 or hex for transport
through env vars / Helm `secret.env`:

```sh
# 32 random bytes, Base64 (44 chars including padding) — recommended
openssl rand -base64 32

# 32 random bytes, hex (64 chars) — equivalent entropy, longer encoding
openssl rand -hex 32
```

Note: both encodings shown above produce strings longer than 32 bytes (Base64 → 44 chars,
hex → 64 chars), so they clear the minimum-length check trivially. The encoded length —
not the underlying entropy — is what `len() < 32` measures.

**Storage and injection.** The secret MUST come from an external secret store at deploy
time, never from a committed file. The supported chain is:

1. **External secret store** (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager,
   1Password Connect) — the authoritative copy.
2. **Kubernetes Secret**, populated by External Secrets Operator / sealed-secrets / SOPS, or
   for non-K8s deployments a systemd `EnvironmentFile` with mode `0400` root-owned.
3. **Pod env var**, by convention named
   `HEARTH_REALM_<SCREAMING_SNAKE_REALM_NAME>_FINGERPRINT_HMAC_SECRET`. The Helm chart's
   `secret.env` map (see `deploy/helm/hearth/values.yaml`) wires this through.
4. **YAML substitution.** Reference the env var from your realm config — Hearth's config
   loader (`src/config/env.rs`) supports `${VAR}` substitution at load time:

   ```yaml
   realms:
     customer-portal:
       adaptive_mfa:
         enabled: true
         recognition_window_days: 30
         fingerprint_hmac_secret: "${HEARTH_REALM_CUSTOMER_PORTAL_FINGERPRINT_HMAC_SECRET}"
   ```

   The substituted value lives only in memory inside the Hearth process and is never
   written back to disk. To prevent accidental disclosure through structured logs, the
   field is held as a `secrecy::SecretString` and `AdaptiveMfaConfig` provides a custom
   `Debug` impl that prints the field as `[REDACTED]` (see [HEA-869](/HEA/issues/HEA-869)).
   Note that this protects only Hearth's own `tracing` output — the underlying value is
   still present in the pod's environment block, so log aggregators that capture
   `/proc/<pid>/environ` or systemd's `EnvironmentFile` content via diagnostics tooling
   can still see it. Restrict that access at the platform layer.

**Fail-secure behaviour.** When `adaptive_mfa.enabled = true` but the substituted secret
fails the length check (env var unset → empty substitution + load warning, or value
shorter than 32 bytes → length error), Hearth returns a hard configuration error on any
code path that would derive a fingerprint. There is no silent fail-open. See
`src/identity/engine.rs` (HEA-836 BLK-2 fix + HEA-861 LOW-1 hardening).

#### Rotation runbook

Use this procedure for scheduled rotation (recommended every 12 months) or in response to
suspected compromise. Plan the rotation per-realm — there is no atomic multi-realm rotation.

**Blast radius.** Rotating the secret invalidates every cached device fingerprint for that
realm (the previous-secret HMAC no longer matches the new-secret HMAC). For the
`recognition_window_days` window after rotation, every active user appears as an
"unrecognised device" exactly once and is challenged with step-up MFA on their next login.
This is the intended behaviour but causes a short-lived support-ticket spike — schedule
rotations outside peak hours and pre-notify support.

**Pre-flight checklist**

- Confirm the user is `realm-admin` for the target realm (or company-level admin).
- Verify all Hearth replicas in the target deployment are healthy (`/health` 200) and on the
  same release. A rotation against a mixed-version fleet can produce inconsistent fingerprint
  behaviour until the slowest replica observes the new secret.
- Locate the current secret in the source of truth (Vault path, AWS Secrets Manager ARN, …)
  and the env-var name it maps to (e.g. `HEARTH_REALM_CUSTOMER_PORTAL_FINGERPRINT_HMAC_SECRET`).
- Snapshot or version the secret store entry so you can roll back.
- Pre-notify support of the expected step-up-MFA spike window.

**Procedure**

1. **Generate the replacement secret.**

   ```sh
   NEW_SECRET="$(openssl rand -base64 32)"
   ```

   Do not echo `$NEW_SECRET` to a shell with command logging enabled and do not pipe it
   anywhere except the secret store CLI.

2. **Write the new secret to the secret store.** Use the store's versioning so the old
   value is retained as an automatic rollback point. Examples:

   ```sh
   # HashiCorp Vault (KV v2 — automatic versioning)
   vault kv put secret/hearth/customer-portal fingerprint_hmac_secret="$NEW_SECRET"

   # AWS Secrets Manager — VersionStage: AWSCURRENT becomes the new value
   aws secretsmanager put-secret-value \
     --secret-id hearth/customer-portal/fingerprint-hmac-secret \
     --secret-string "$NEW_SECRET"

   # GCP Secret Manager
   gcloud secrets versions add hearth-customer-portal-fingerprint-hmac-secret \
     --data-file=<(printf '%s' "$NEW_SECRET")
   ```

3. **Trigger a refresh of the in-cluster Kubernetes Secret.** External Secrets Operator
   picks the new value up on its next refresh interval — force a sync if you do not want to
   wait:

   ```sh
   kubectl annotate externalsecret hearth-customer-portal-fingerprint-hmac-secret \
     force-sync="$(date +%s)" --overwrite
   ```

4. **Roll the Hearth pods so they pick up the new env var.** A standard Helm-managed
   `kubectl rollout restart deploy/hearth` is sufficient; the deployment's pod template
   already has `checksum/secret` and `checksum/config` annotations, so any change to the
   underlying Secret triggers a rolling restart on the next `helm upgrade` as well.

   ```sh
   kubectl rollout restart deployment/hearth -n <namespace>
   kubectl rollout status  deployment/hearth -n <namespace> --timeout=5m
   ```

5. **Verify the new secret is in effect.** From a workstation with a configured Hearth
   admin token, log in as a test user that already has a recognised device. You should be
   challenged with step-up MFA — confirming the previous-secret HMAC no longer matches.
   After successful MFA, repeat the login: it should now be silent (the new-secret HMAC has
   been cached).

6. **Confirm there is no plaintext leak.** Check the rolling logs for the substituted
   value:

   ```sh
   kubectl logs -n <namespace> deploy/hearth --since=10m | grep -F "$NEW_SECRET" && \
     echo "FAIL: secret material found in logs" || \
     echo "OK: no plaintext secret in recent logs"
   ```

   (`grep` exits 0 on match, so the `&&` branch fires only on the failure case.)

7. **Secondary verification — audit-event surface.** As a durable check that survives
   `unset NEW_SECRET`, query the `StepUpMfaTriggered` audit event count for the rotated
   realm and confirm a fresh spike correlated with the pod restart. The spike confirms the
   new-secret HMAC is in effect (every previously-recognised device is briefly treated as
   unrecognised). This gate is more reliable than log scraping once the shell variable is
   gone and works equally well from monitoring dashboards.

   ```sh
   # Replace the example with your audit-query mechanism (Hearth admin API,
   # SIEM, or the durable audit log) — the shape of the check is what matters.
   hearth-admin audit-events --realm customer-portal --type StepUpMfaTriggered \
     --since "$ROTATION_START_TS"
   ```

8. **Delete the temporary shell variable.**

   ```sh
   unset NEW_SECRET
   history -d $((HISTCMD-1)) 2>/dev/null || true
   ```

9. **Mark the rotation in your audit log.** Hearth emits a `StepUpMfaTriggered` audit event
   whenever a user is challenged — the rotation window will show a spike in those events.
   Tag the operational change in your change-management system with the realm name, the new
   secret store version id, and the operator who performed the rotation.

**Rollback.** If the new secret causes unexpected behaviour, restore the previous version
in the secret store and repeat steps 3–4. The previous-version fingerprints rejoin the
recognition cache automatically as users log in.

**Compromise response.** If you suspect the secret has leaked, run the rotation immediately
and **additionally** invalidate the Redis device-recognition cache. The flush is **only
required in the compromise path** — for scheduled rotation it is unnecessary, because
old-HMAC fingerprints simply fail to match on next lookup and users are re-challenged
naturally as they log in. The flush is also intentionally **realm-agnostic**: the Redis
key schema is `dev:fp:{uid}:{hmac_hex}` (no realm prefix), so realm-scoped invalidation
would require enumerating every UID belonging to the affected realm — complex, fragile,
and unnecessarily conservative when a compromise has already happened. The full flush
is the right default for incident response.

The flush below invalidates the recognition cache across **all realms** in the Redis
instance — make sure that is what you want before running it. The intent is to prevent
an attacker from riding out the rotation on a stale, attacker-controlled fingerprint:

```sh
redis-cli --scan --pattern "dev:fp:*:*" | xargs -r redis-cli del
```

Combine with credential-stuffing rate-limit review (`security.rate_limiting`) and a forced
session revoke for affected users.

### SCIM bearer tokens

SCIM bearer tokens are SHA-256 hashed before storage and compared in constant time. Generate
them with at least 32 bytes of cryptographic randomness.

### Webhook signing secrets

Webhook signing secrets are HMAC-SHA256 keys. Generate at least 32 bytes of randomness.
Verify the `X-Hearth-Signature-256` header on all incoming webhook deliveries.

---

## TLS Configuration

Hearth uses `rustls` 0.23 and supports TLS 1.2 and TLS 1.3. TLS 1.0 and 1.1 are not
supported.

- **Terminate TLS at Hearth, not a reverse proxy**, unless you have a specific reason to use
  a proxy. Terminating at the proxy creates a plaintext hop between proxy and Hearth.
- Use the `tls` configuration block to point Hearth at your certificate and key files.
- Hearth supports hot-reload of TLS certificates without dropping existing connections.

---

## Dependency Vulnerability Scanning

Hearth ships with `deny.toml` which enforces `cargo deny` checks in CI. All CVE exceptions are
documented with justification. Known exceptions:

| Advisory | Crate | Justification |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa` | Marvin Attack affects decrypt path only; Hearth uses `rsa` only for key generation and PKCS#8 serialization — no decryption. |

Additionally, Dependabot is configured to automatically detect and open PRs for
newly disclosed vulnerabilities in dependencies.

---

## Rate Limiting

The admin API enforces 100 requests per minute per authenticated admin. Adjust this at the
infrastructure level (API gateway, load balancer) if you need tighter limits for your
deployment.

---

## Audit Log Integrity

Hearth's audit log uses a SHA-256 hash chain for tamper evidence. Treat the audit log as
security-critical data:
- Back it up independently of the main data store.
- Monitor for gaps or out-of-order entries.
- Do not delete audit log entries to cover tracks — the hash chain will reveal the deletion.
