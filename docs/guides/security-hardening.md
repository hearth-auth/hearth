# Security Hardening Guide

This guide documents security configuration recommendations for Hearth deployments. It is
aimed at production operators and complements the default configuration documented in
[docs/guides/configuration-reference.md](configuration-reference.md).

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

### Security enforcement behaviors

The following behaviors are enforced unconditionally and cannot be disabled via configuration:

- **Hearth is a SAML service provider only.** It does not act as a SAML IdP (removed in
  3.0.0), so it signs no assertions and serves no SSO endpoint that could become a signing
  oracle. The Assertion Consumer Service accepts the HTTP-POST binding only; Hearth receives
  no DEFLATE-compressed HTTP-Redirect payloads.

- **Audience/destination validated against `onboarding.base_url`.** When `onboarding.base_url`
  is set in `hearth.yaml`, SAML assertion audience and destination are validated against that
  trusted origin, not the request `Host` header. This prevents a request-spoofing bypass where
  an attacker supplies a crafted `Host` header matching an audience they control.

- **`Conditions/NotOnOrAfter` is required.** SAML assertions without a `NotOnOrAfter` upper
  bound are rejected. An assertion with no expiry is replayable indefinitely.

- **`want_assertions_signed` is enforced per connector.** When a SAML provider is configured
  with `want_assertions_signed: true` in `hearth.yaml`, the ACS rejects inbound assertions that
  are not individually signed. This setting was previously parsed but had no effect.

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

The host key (`HEARTH_MASTER_KEY`) encrypts the Key Encryption Keys (KEKs) held in
`hearth.keys` at rest. It is the most sensitive secret in a Hearth deployment. Note that the
registry currently holds a **single** KEK — the system realm's — and that one KEK wraps the
data key of every WAL segment and SST for every realm.

> **Production requirement:** In production mode (any startup without `--dev`), the host key
> comes from `HEARTH_MASTER_KEY` **only**. Hearth **refuses to start** when the variable is
> unset, and it never reads a `hearth.host_key` file from the data directory — a plaintext key
> stored beside the ciphertext it protects would defeat encryption at rest, so such a file is
> ignored (the startup error says so). Generating and reading `hearth.host_key` happens only
> under `--dev`. This is intentional fail-closed security behavior.

- **Never commit the host key to version control.**
- Store it in a secrets manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager).
- Inject it at runtime via the `HEARTH_MASTER_KEY` environment variable.
- Do not leave a `hearth.host_key` file in a production data directory. Production ignores it,
  and it is a plaintext key on the same disk as the data.
- Rotate it by re-wrapping the KEKs in `hearth.keys` (Hearth supports O(n files) rotation —
  only DEK headers are re-wrapped, not bulk data).

### OAuth client secrets

OAuth client secrets are never stored in plaintext. How they are hashed depends on who chose them:

- **Hearth-generated** secrets (`POST /register`, the console's new-application form, *Regenerate
  secret*) are 32 bytes from the OS CSPRNG and are stored as an unsalted SHA-256 digest
  (`$hearth-sha256$v=1$…`). Against a 256-bit random preimage a single SHA-256 is already
  infeasible to invert, so a slow KDF adds nothing — and it would make every authenticated
  introspection cost a full Argon2id run. Verification is one SHA-256 plus a constant-time compare.
- **Caller-chosen** secrets (`hearth.yaml` `applications[].client_secret`, migration import) may be low-entropy, so they are stored as
  Argon2id hashes, like passwords. Secrets stored before the SHA-256 format existed are Argon2id
  too and keep verifying. They are never re-hashed automatically — Hearth cannot tell from the hash
  whether the secret was random. Regenerate the secret to move a client onto the fast format.
  Authenticating such a client is slower than authenticating any other, which reveals that the
  client exists to anyone timing the endpoint; prefer Hearth-generated secrets.

**The remaining Argon2id cost is an amplification vector, bounded by the KDF gate.** Anyone who
knows an Argon2id-hashed client's `client_id` can make the server run one Argon2id verification
per request by presenting any secret at `/token`, `/as/par`, `/introspect`, `/revoke` or
`/device_authorization` (or their `/realms/{realm}/…` twins). Client ids are not secret: they
travel in browser authorization requests, and a `hearth.yaml` application's id is a UUID v5 that
anyone can compute from the realm and the application key. Every such verification therefore runs
behind the same process-wide admission gate as password hashing
(`security.password.kdf.max_in_flight`), on the blocking pool; when the gate is saturated the
request is shed with `503` and `Retry-After`, exactly like a login. The gate
caps the CPU and memory this can consume, but under such a flood legitimate Argon2id clients and
password logins share the shed. Rotate config-managed and legacy clients to Hearth-generated
secrets (*Regenerate secret* on the client's page in the admin console), after which their
verification is one SHA-256, never touches the gate, and cannot be used this way. An unknown or
public `client_id` presenting a secret costs one SHA-256.

Treat client secrets like passwords:
- If you must supply your own, generate at least 32 bytes of cryptographically random material.
- Rotate them immediately if compromised (Hearth supports multiple active secrets per client
  for zero-downtime rotation).

### Device fingerprint HMAC secret (removed)

Adaptive MFA and device fingerprinting were removed in Hearth 3.0.0, so there is no
fingerprint secret to manage. MFA is a plain per-realm policy (`mfa_required`).

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

Hearth emits, on every `/ui/*` response:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

in exactly two situations:

| Deployment | HSTS emitted? |
|---|---|
| TLS terminated **at Hearth** (`server.tls_cert_path` set) | Yes, on every response. |
| TLS terminated **at a proxy**, with `server.trust_forwarded_proto: true` and a non-empty `server.trusted_proxies` | Yes, on requests the proxy marks `X-Forwarded-Proto: https`. |
| TLS terminated **at a proxy**, `trust_forwarded_proto` unset | **No.** Hearth sees only plaintext and cannot tell that the browser used HTTPS. Set the header at the proxy. |

The third row is the trap. Hearth behind a TLS-terminating reverse proxy sees a plaintext
hop and has no way to know the browser's scheme unless the proxy tells it. If you do not
set `trust_forwarded_proto`, **HSTS is your proxy's job** — add it there:

```nginx
# nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

```yaml
# Envoy
route_config:
  response_headers_to_add:
    - header:
        key: Strict-Transport-Security
        value: "max-age=31536000; includeSubDomains; preload"
```

Read the `preload` warning below before you add either one.

This enforces HTTPS for one year on the domain and all subdomains, and includes the
`preload` directive. **The `preload` directive opts your domain into browser HSTS preload
lists** (maintained by Chrome, Firefox, Safari, etc.). Once submitted and accepted,
browsers will refuse plain HTTP connections to your domain even on first visit — this
cannot be undone quickly (removal from preload lists takes months to propagate).

**Operator actions required before enabling TLS (or before adding the header at your proxy):**

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

Hearth enforces multiple rate-limit tiers out of the box. All thresholds are tunable under
[`security.rate_limiting`](configuration-reference.md#securityrate_limiting) in `hearth.yaml`
and per-realm under `realms.<name>.auth.rate_limit`.

### Per-IP login rate limit

Blocks credential-stuffing and distributed brute-force attacks by IP address.

| Config key | Default | Effect |
|---|---|---|
| `login_per_ip.max_attempts` | `10` | Failed login attempts before IP is blocked |
| `login_per_ip.window_seconds` | `60` | Sliding window length in seconds |

After the window closes, the IP is released automatically. This limiter is **in-memory** — it
does not survive a server restart. Deploy a reverse-proxy (nginx, Caddy, Cloudflare) with its
own IP-based limiting if your threat model requires persistence across restarts.

> **TLS connections:** when Hearth terminates TLS directly (no reverse proxy), the real client
> IP is correctly extracted from the TCP connection and attributed to the rate limiter (HEA-2164).
> Releases before this fix collapsed all TLS-sourced requests into a single global bucket,
> making per-IP limits ineffective on the TLS listener.

### Per-account lockout

Blocks sustained per-account password attacks.

| Config key | Default | Effect |
|---|---|---|
| `login_per_account.max_failures` | `5` | Consecutive failures before account is locked |
| `login_per_account.lockout_seconds` | `300` | Lockout duration (5 min default) |

This limiter **persists across restarts** — the lockout state is WAL-persisted and restored at
startup.

### Admin API rate limit

| Config key | Default | Effect |
|---|---|---|
| `admin_per_minute` | `100` | Requests/minute per admin user |

Requests beyond the cap receive `429 Too Many Requests`. Set to `0` to disable (logs a `WARN`
at startup and emits `hearth_rate_limiters_disabled{reason="config_zero"} 1`; never set `0`
on a production bind).

### Token endpoint rate limit

| Config key | Default | Effect |
|---|---|---|
| `token_per_minute` | `200` | Requests/minute per `(realm, client)` pair at `/token`, `/as/par`, `/introspect`, `/revoke` and `/device_authorization` (and their realm twins), counted before the client is authenticated; `/as/par` counts against a separate bucket of the same size |

Applies to token issuance, introspection, and device-authorization requests. Same zero-warning
behaviour as `admin_per_minute`.

### Rate-limit durability across restarts

| Limiter | Restart-safe? |
|---|---|
| Per-account lockout (`login_per_account`) | **Yes** — WAL-persisted |
| Per-IP login flood (`login_per_ip`) | **No** — in-memory only |
| Magic-link / password-reset request rate | **No** — in-memory only |
| Self-registration rate | **No** — in-memory only |

An attacker who triggers or waits for a server restart can transiently bypass the in-memory
limiters immediately after startup. Mitigations: keep restart windows short, deploy a
proxy-level rate limiter, and enable CAPTCHA or MFA for magic-link and password-reset flows
in high-threat environments.

---

## Webhook Egress Security

Hearth enforces several protections on all outbound webhook HTTP calls (event dispatcher,
approval notifier, pre-token webhook, and the admin webhook test-ping):

- **SSRF guard with connect-time DNS validation.** Before connecting, Hearth validates the
  destination URL against a blocklist of private, link-local, and loopback address ranges
  (RFC 1918, `169.254.0.0/16`, `::1`, etc.). Critically, the DNS lookup that feeds
  `connect()` is the same lookup that is validated — there is no second lookup between the
  check and the connect. This closes the DNS-rebinding TOCTOU window where a hostname could
  resolve to a public address during the guard and then re-bind to a private address before
  the actual TCP connect.

- **HTTP redirects refused.** All four egress paths pin `max_redirects` to `0`. A `3xx`
  response cannot bounce the request to an internal target that was never validated.

- **HTTPS required.** Only `https://` destinations are accepted.

> **Operator note:** these protections are enforced in code and cannot be disabled via
> configuration. If your webhook destination requires a private network route (internal
> SIEM, intranet receiver), deploy a dedicated HTTPS relay at a public-resolvable address
> that Hearth can reach, then forward from the relay.

---

## Audit Log Integrity

Hearth's audit log uses a per-realm HMAC-SHA256 hash chain for tamper evidence. A signed chain head (last hash + event count) is persisted atomically with every append and prune, so tail truncation — removing the newest events — is detected by `verify_integrity` in addition to internal reordering or deletion. Treat the audit log as security-critical data:
- Back it up independently of the main data store.
- Monitor for gaps or out-of-order entries.
- Do not delete audit log entries to cover tracks — the hash chain and signed chain head will reveal the deletion or truncation.
- Run `POST /admin/realms/{realm}/audit/verify` periodically as an integrity check; a clean run returns 200 with a summary of verified event count and chain head status.

---

## Auth-Boundary PR Review Checklist

Any PR that touches `src/protocol/http/admin.rs`, `src/protocol/http/admin/*.rs`, or the
auth helpers (`src/protocol/http/auth.rs`) is an
**auth-boundary PR** and must pass the following checks before merge.

### Automated backstops (enforced in CI)

| Check | Mechanism | Catches |
|---|---|---|
| `#[must_use]` on `extract_admin_auth` | Rust compiler + `clippy -D warnings` | Unbound calls (result dropped as statement) |
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
      The `Result` must be propagated so an auth failure returns an HTTP error
      rather than falling through to handler logic.

- [ ] **`scoped_realm(auth, path_realm_id)` is called** for any handler that accepts a
      `{realm_id}` path parameter. Plain `auth.realm_id` bypasses the cross-realm guard.
      See `src/protocol/http/admin.rs::scoped_realm` for the canonical pattern.

- [ ] **No new handler omits the auth call entirely.** Grep for `async fn` in scope
      and confirm every handler body contains at least one of:
      `extract_admin_auth` or an explicit `scoped_realm` call.

### Why this matters

The HEA-1629 audit found 11 REST handlers and 30+ gRPC handlers (the gRPC API was removed in 3.0.0) where the auth extractor
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
