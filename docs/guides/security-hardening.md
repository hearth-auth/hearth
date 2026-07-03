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

### Immediate session revocation when disabling a user

When an admin disables a user account (`update_user()` with `enabled: false`), Hearth
**immediately revokes all active sessions** for that user. Existing access tokens derived
from those sessions will fail validation at the next refresh cycle (within the
`access_token_ttl` window, default 15 minutes).

This means disabling a user in the admin UI or via `PATCH /admin/users/{id}` is an
effective and fast off-boarding control — you do not need to wait for token expiry or
manually revoke sessions separately.

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

> **Production requirement (HEA-1368):** In production mode (any startup without `--dev`),
> Hearth **refuses to start** if `HEARTH_MASTER_KEY` is unset and no `hearth.host_key` file
> exists. Auto-generation is only permitted under `--dev`. The startup error message is
> actionable and explains the remediation. This is intentional fail-closed security behavior.

- **Never commit the host key to version control.**
- Store it in a secrets manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager).
- Inject it at runtime via the `HEARTH_MASTER_KEY` environment variable.
- If you previously ran Hearth without `HEARTH_MASTER_KEY` set, Hearth auto-generated and
  persisted the key to `<data-dir>/hearth.host_key` (mode 0600). You can export it:
  `export HEARTH_MASTER_KEY=$(xxd -p -c 32 /path/to/hearth.host_key | tr -d '\n')`
- Rotate it by re-wrapping all realm KEKs (Hearth supports O(n files) rotation — only DEK
  headers are re-wrapped, not bulk data).

### OAuth client secrets

OAuth client secrets are stored as Argon2id hashes, not plaintext. Treat them like passwords:
- Generate at least 32 bytes of cryptographically random material.
- Rotate them immediately if compromised (Hearth supports multiple active secrets per client
  for zero-downtime rotation).

### Device fingerprint HMAC secret

Adaptive MFA (`adaptive_mfa.enabled = true` on a realm) derives a per-device fingerprint by
computing `HMAC-SHA256(secret, "{user_id}:{ip_/24}:{user_agent_normalized}")` and storing
the hex digest in Hearth's embedded key-value store under the key schema
`dfp:user:{user_uuid}:{hmac_hex}` (see `src/identity/keys.rs`). The `fingerprint_hmac_secret`
is the HMAC key for that derivation. **A weak or compromised secret allows an attacker who
knows a victim's `{user_id, ip_/24, user_agent}` tuple to forge the fingerprint and bypass
step-up MFA on an unrecognised device.** Treat it accordingly.

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

**Blast radius.** Rotating the secret renders every stored device fingerprint for that
realm unreachable via normal lookup: the previous-secret HMAC and the new-secret HMAC
produce different `hmac_hex` values, so the stored key (`dfp:user:{uuid}:{old_hmac}`) no
longer matches what `derive_hmac(new_secret, …)` computes. For the `recognition_window_days`
window after rotation, every active user appears as an "unrecognised device" exactly once
and is challenged with step-up MFA on their next login. The stale `dfp:user:*` entries
created under the old secret remain in the embedded KV but are unreachable and are removed
by the background sweeper (`identity.cleanup.dfp_sweeper_interval_secs`, default 6 hours;
see HEA-862). This is the intended behaviour but causes a short-lived support-ticket spike
— schedule rotations outside peak hours and pre-notify support.

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
in the secret store and repeat steps 3–4. Devices last recognised under the old secret
become reachable again immediately (the stored `dfp:user:*` entries were never deleted —
only orphaned by the HMAC key change), so users on previously-known devices stop being
challenged for step-up MFA again.

**Compromise response.** If you suspect the secret has leaked, run the rotation
immediately. **Cache invalidation is self-contained** — there is no separate flush step.
Rotating the secret changes the HMAC derivation key, so every subsequent fingerprint
lookup resolves to a different storage key (`dfp:user:{uuid}:{new_hmac}`) than what was
stored with the old secret. Old entries become unreachable on first use of the new secret
and are removed by the background sweeper (`identity.cleanup.dfp_sweeper_interval_secs`,
default 6 hours; HEA-862). Device fingerprints live in Hearth's embedded key-value store,
not Redis or another external cache — there is no `redis-cli` or equivalent flush command
to run, and Hearth currently exposes no admin endpoint to force an immediate sweep.
Attempting to use a Redis CLI in this position would silently succeed against an
unrelated Redis instance, leaving you with false confidence during an active incident.
Do not do that.

For forced immediate re-authentication of all users in the affected realm, revoke active
sessions through the admin sessions endpoint and review credential-stuffing rate-limit
metrics (`security.rate_limiting`). Tighten the rate-limit thresholds for the duration of
the incident if attacker traffic is observed.

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

### HSTS (HTTP Strict Transport Security)

When TLS is enabled, Hearth automatically sets:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

This enforces HTTPS for one year on the domain and all subdomains, and includes the
`preload` directive. **The `preload` directive opts your domain into browser HSTS preload
lists** (maintained by Chrome, Firefox, Safari, etc.). Once submitted and accepted,
browsers will refuse plain HTTP connections to your domain even on first visit — this
cannot be undone quickly (removal from preload lists takes months to propagate).

**Operator actions required before enabling TLS:**

1. Confirm that _all_ subdomains of your Hearth domain can serve HTTPS. The `includeSubDomains`
   directive means `*.auth.example.com` is also covered.
2. If you are not ready to submit to HSTS preload lists, do not publicly advertise the domain
   yet, or use a subdomain isolated from your main domain.
3. If you later need to remove the preload protection, submit a removal request at
   [hstspreload.org](https://hstspreload.org) — expect several months for full propagation.

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

---

## Auth-Boundary PR Review Checklist

Any PR that touches `src/protocol/http/admin.rs`, `src/protocol/grpc/*.rs`, or the
auth helpers (`src/protocol/http/auth.rs`, `src/protocol/grpc/auth.rs`) is an
**auth-boundary PR** and must pass the following checks before merge.

### Automated backstops (enforced in CI)

| Check | Mechanism | Catches |
|---|---|---|
| `#[must_use]` on `extract_admin_auth` / `authenticate_admin` | Rust compiler + `clippy -D warnings` | Unbound calls (result dropped as statement) |
| `scripts/check-auth-discard.sh` | `filter` job, runs on every PR | `let _auth`, `let _ = auth-call(...)`, unbound calls |
| `make auth-discard-check` | `ci-local-fast` | Same as above, runs pre-push |

CI gate: the auth-discard lint runs inside the `filter` job, which feeds into
`required-summary`. A lint failure blocks merge.

### Manual review checklist

Reviewers MUST verify the following for every handler in scope:

- [ ] **Auth result is bound to a named variable**, e.g. `let auth = match extract_admin_auth(...)`.
      A `let _` or `let _auth` binding compiles but bypasses authorization — CI will catch
      these, but human review is the second line of defense.

- [ ] **`?` or explicit error-return is used** immediately after the auth call.
      The `Result` must be propagated so an auth failure returns an HTTP/gRPC error
      rather than falling through to handler logic.

- [ ] **`scoped_realm(auth, path_realm_id)` is called** for any handler that accepts a
      `{realm_id}` path parameter. Plain `auth.realm_id` bypasses the cross-realm guard.
      See `src/protocol/http/admin.rs::scoped_realm` for the canonical pattern.

- [ ] **No new handler omits the auth call entirely.** Grep for `async fn` in scope
      and confirm every handler body contains at least one of:
      `extract_admin_auth`, `authenticate_admin`, or an explicit `scoped_realm` call.

- [ ] **gRPC service methods return `?` on the auth result**, not just log/ignore it.
      Tonic methods that return `Result<Response<_>, Status>` must propagate `Status::unauthenticated`.

### Why this matters

The HEA-1629 audit found 11 REST handlers and 30+ gRPC handlers where the auth extractor
was called but its `Result` was either silently dropped or the handler continued even on
auth failure. This is Broken Object-Level Authorization (BOLA): an attacker in one realm
could read or mutate resources in another realm by supplying a different `{realm_id}` path
parameter. The `scoped_realm` accessor and the `#[must_use]` annotation were introduced to
make this class of mistake a compile error rather than a code review catch.

### Suppression escape hatch

If a line is legitimately exempt (e.g. a test fixture that intentionally exercises the
failure path of `extract_admin_auth`), add an inline comment to suppress the grep lint:

```rust
let _result = extract_admin_auth(&headers, &state); // auth-discard-lint-allow
```

The `// auth-discard-lint-allow` token must appear on the **same line** as the violation.
Use suppressions sparingly — each one is a documented exception that reviewers should
scrutinize.
