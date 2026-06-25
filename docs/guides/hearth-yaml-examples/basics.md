# Basics — Examples 1–6

Core `hearth.yaml` patterns for first-time setup through production-hardened password auth.
Return to the [example index](./index.md) for a full list of all examples.

---

## Example 1 — Zero-config / dev quickstart

**Audience:** developers running Hearth locally for the first time.

```yaml
{}
```

Start with:

```bash
hearth serve --dev
```

`--dev` enables in-memory storage (nothing is persisted), disables `fsync`, and binds to
`127.0.0.1:8420`. The bootstrap endpoint is available immediately:

```bash
curl -X POST http://127.0.0.1:8420/admin/bootstrap
```

- An empty YAML file and a missing file are treated identically — every field defaults.
- Never use `--dev` in production: data is lost on restart and fsync is off.

---

## Example 2 — Minimal production

**Audience:** operators deploying Hearth for the first time behind a TLS-terminating load balancer
or directly with TLS enabled.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 8420
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"
  trusted_proxies:
    - "10.0.0.0/8"          # CIDR ranges are not yet supported; list individual IPs
  trust_forwarded_proto: true

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true               # must be true — WAL durability guarantee

oidc:
  issuer: "https://auth.example.com"

token:
  audience: "my-app"
```

- `oidc.issuer` populates the `iss` claim in all JWTs and the OIDC Discovery document
  at `/.well-known/openid-configuration`. Must be reachable by clients.
- `token.audience` is the `aud` claim. Set it to match your application's expected audience.
- When TLS is enabled, Hearth spawns an HTTP→HTTPS redirect listener on `port - 1`
  (or port 80 when `port: 443`). Send `SIGHUP` to hot-reload the certificate.

---

## Example 3 — Traditional password login (basic)

**Audience:** operators wanting open registration with standard password auth and explicit Argon2id
tuning.

```yaml
auth:
  session_ttl: "24h"
  password_memory_cost: 65536  # Argon2id memory in KiB (OWASP minimum: 64 MiB = 65536)
  password_time_cost: 3        # Argon2id iterations

oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: open             # anyone may self-register
```

- `auth.*` at the top level sets global defaults inherited by all realms. Per-realm overrides
  go under `realms.<name>.auth.*`.
- `registration.mode: open` allows anyone to create an account. The default when `registration`
  is omitted is `disabled` — only admins can create users.
- Duration strings accept suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days).

---

## Example 4 — Traditional password login (strict policy)

**Audience:** operators in regulated or enterprise environments that need password complexity rules
and expiry enforcement.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: open
      password_policy:
        min_length: 12
        require_uppercase: true
        require_number: true
        require_special: true
        not_username: true     # password must not equal or contain the display name
        not_email: true        # password must not equal or contain the email address
        history_depth: 12      # reject the last 12 passwords on change
        max_age_days: 90       # require reset after 90 days
```

- All `password_policy` fields are optional; omit any you don't need.
- `not_username` and `not_email` perform case-insensitive substring checks.
- `history_depth` stores Argon2id hashes of previous passwords — it does not store plaintext.
- `max_age_days` forces a password-reset flow; it does not lock the account.

---

## Example 5 — Rate limiting + lockout

**Audience:** operators hardening a public-facing login endpoint against credential-stuffing.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      rate_limit:
        max_failed_logins: 5      # failed attempts before lockout
        lockout_duration: "15m"   # locked for 15 minutes
```

- Rate limit fields live under `realms.<name>.auth.rate_limit`, not at the top level.
- Lockout is per-account (not per-IP). Combine with a WAF or reverse proxy for IP-level rate
  limiting.
- A locked account can be manually unlocked via the Admin UI or `PATCH /admin/users/{id}`.

---

## Example 6 — Closed / invite-only registration

**Audience:** operators running an internal or B2B product where user accounts must be
pre-approved.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: invite_only    # only users with a valid organization invitation may register
```

Valid `registration.mode` values:

| Value | Behavior |
|-------|----------|
| `disabled` | No self-registration; admins create users (default) |
| `open` | Anyone may register |
| `invite_only` | Must present a valid organization invitation |
| `domain_restricted` | Email must match `allowed_domains` |

For `domain_restricted`, add:

```yaml
      registration:
        mode: domain_restricted
        allowed_domains:
          - "example.com"
          - "subsidiary.example.com"
```

---
