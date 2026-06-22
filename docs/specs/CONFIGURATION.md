# Configuration Reference

Hearth is configured via a single YAML file. Every field is optional — an empty file (`{}`) is a valid, production-safe configuration with sensible defaults.

## File Location & Loading

Hearth looks for configuration in this order:

1. `--config` / `-c` CLI flag: `hearth serve -c /etc/hearth/config.yaml`
2. `HEARTH_CONFIG` environment variable: `HEARTH_CONFIG=/etc/hearth/config.yaml hearth serve`
3. `hearth.yaml` in the current working directory (auto-detected)

If no config file is found, all defaults apply.

## Environment Variable Expansion

Any string value in the YAML supports `${VAR_NAME}` substitution:

```yaml
email:
  smtp:
    password: "${SMTP_PASSWORD}"

realms:
  prod:
    applications:
      api:
        client_secret: "${API_CLIENT_SECRET}"
```

A referenced variable that is **not set** is a **startup error** — there is no silent fallback. This prevents accidental deployment with missing secrets.

## Duration Format

Duration fields accept human-readable strings with a single suffix:

| Suffix | Unit    | Example  | Equivalent         |
|--------|---------|----------|--------------------|
| `s`    | seconds | `"30s"`  | 30 seconds         |
| `m`    | minutes | `"15m"`  | 15 minutes         |
| `h`    | hours   | `"24h"`  | 24 hours           |
| `d`    | days    | `"7d"`   | 7 days             |

No spaces between the number and suffix. Fractional values are not supported — use a smaller unit instead (e.g. `"90s"` not `"1.5m"`).

---

## Top-Level Sections

### `server`

Network binding and TLS configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_address` | string | `"127.0.0.1"` | IP address to bind the HTTP(S) listener to. Use `"0.0.0.0"` for all interfaces. |
| `port` | integer | `8420` | TCP port for the main listener. |
| `tls_cert_path` | string | — | Path to a PEM-encoded TLS certificate. If set, `tls_key_path` MUST also be set. |
| `tls_key_path` | string | — | Path to the PEM-encoded private key for the TLS certificate. |
| `tls_client_ca_path` | string | — | Path to a CA certificate for client certificate verification (mTLS). |
| `tls_require_client_cert` | bool | `false` | When `true`, all connections must present a valid client certificate signed by `tls_client_ca_path`. |
| `trusted_proxies` | list of strings | `[]` | IP addresses of trusted reverse proxies. When non-empty, the real client IP is extracted from `X-Forwarded-For` using the rightmost-non-trusted algorithm. When empty (the default), the peer socket address is used and `X-Forwarded-For` is ignored — the safe default for direct-to-internet deployments. CIDR notation is not yet supported; supply individual IPs. |
| `trust_forwarded_proto` | bool | `false` | Trust the `X-Forwarded-Proto: https` header from proxies listed in `trusted_proxies`. When `true`, session cookies gain the `Secure` attribute when the forwarded proto header indicates HTTPS. Only enable when `trusted_proxies` is correctly configured. |

When TLS is enabled, Hearth also spawns an HTTP → HTTPS redirect listener on `port - 1` (or port 80 when `port: 443`). Send `SIGHUP` to hot-reload the certificate and key without downtime.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path: "/etc/hearth/tls/server.key"
```

### `storage`

Embedded storage engine tuning. These control WAL, memtable, and hot tier behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `data_dir` | string | `"./data"` | Directory for WAL files, SSTs, and metadata. Created if it does not exist. |
| `wal_max_size_bytes` | integer | `268435456` (256 MiB) | WAL file rotation threshold. |
| `memtable_flush_bytes` | integer | `67108864` (64 MiB) | Memtable size threshold before flushing to an SST file. |
| `hot_tier_capacity` | integer | auto | When set, uses this exact number of hot tier entries. When omitted, auto-sizes from system memory (or `hot_tier_max_memory` if set). |
| `hot_tier_max_memory` | integer | none | Maximum bytes to allocate for the hot tier. Overrides system memory detection during auto-sizing. Ignored when `hot_tier_capacity` is explicitly set. |
| `fsync` | bool | `true` | Whether to `fsync` WAL writes. **MUST be `true` in production.** Dev mode disables this for faster iteration. |

```yaml
storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true
  # Option A: explicit entry count
  hot_tier_capacity: 500000
  # Option B: memory budget (triggers auto-sizing, ignored when capacity is set)
  hot_tier_max_memory: 4294967296  # 4 GiB
```

### `cluster`

Multi-node Raft consensus configuration. **Omit this section entirely for single-node deployments** — when absent, Hearth runs in single-node mode with no clustering overhead, no extra port, and no Raft log.

When present, Hearth starts a Raft engine and participates in peer-to-peer log replication over mTLS-secured gRPC. All three TLS certificate fields are required — plaintext peer connections are unconditionally rejected.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `node_id` | integer | — | **Required.** This node's numeric ID. Must be unique across the cluster. Typically `1`, `2`, `3`, … |
| `peer_address` | string | `"127.0.0.1:8421"` | `host:port` this node listens on for inbound Raft RPCs from peers. Use a routable address in production (not loopback). |
| `peers` | list | `[]` | Known cluster peers. Each entry has `id` (integer) and `address` (string `host:port`). List all nodes except this one. |
| `tls_cert_path` | path | — | **Required.** Path to this node's PEM certificate (presented to peers during mTLS). |
| `tls_key_path` | path | — | **Required.** Path to this node's PEM private key. |
| `tls_ca_cert_path` | path | — | **Required.** Path to the CA certificate used to verify peer certificates. All nodes must share the same CA. |
| `read_lag_threshold_ms` | integer | `500` | Maximum follower replication lag in milliseconds before reads are refused. When exceeded, the caller receives a redirect to the leader's address. |

```yaml
cluster:
  node_id: 1
  peer_address: "10.0.0.1:8421"
  peers:
    - id: 2
      address: "10.0.0.2:8421"
    - id: 3
      address: "10.0.0.3:8421"
  tls_cert_path: "/etc/hearth/certs/node1.crt"
  tls_key_path:  "/etc/hearth/certs/node1.key"
  tls_ca_cert_path: "/etc/hearth/certs/ca.crt"
  read_lag_threshold_ms: 500   # optional — omit to use the default
```

**Write routing:** Writes that arrive on a follower return an error with the leader's address. Your load balancer or client should retry the write against that address. Writes go through Raft and are only acknowledged after quorum commit.

**Read routing:** Follower reads are served locally when replication lag is below `read_lag_threshold_ms`. When lag is exceeded, reads also return the leader's address for redirect.

**Bootstrap:** On first cluster startup, call the bootstrap API on the designated bootstrap node once all peers are reachable. See the [Clustering guide](../guides/clustering.md) for the step-by-step sequence.

**NTP requirement:** Hearth embeds `leader_timestamp` (wall-clock microseconds) in every Raft log entry to produce stable, monotonic timestamps across nodes. **NTP-synchronized clocks are a hard operational requirement for cluster mode.** Clock skew above 1 second will cause a startup warning; skew above several seconds will produce incorrect ordering of concurrent writes.

> **See also:** [Clustering guide](../guides/clustering.md) for bootstrap, quorum, cert generation, graceful shutdown, and backup strategy.

### `metrics`

Prometheus metrics endpoint configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Expose the `GET /metrics` Prometheus scrape endpoint. Set to `false` when metrics are collected via a sidecar agent instead of a direct scrape. |

```yaml
metrics:
  enabled: true
```

The `/metrics` endpoint returns metrics in Prometheus text exposition format (`text/plain; version=0.0.4`). It includes the following metric families:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `hearth_http_request_duration_seconds` | histogram | `method`, `route`, `status` | HTTP request latency |
| `hearth_auth_attempts_total` | counter | `realm`, `outcome` | Authentication attempts by outcome (`success`/`failure`) |
| `hearth_tokens_issued_total` | counter | `realm`, `grant_type` | Tokens issued by OAuth 2.0 grant type |
| `hearth_active_sessions` | gauge | — | Current active session count across all realms |
| `hearth_storage_operation_duration_seconds` | histogram | `operation` | Storage write/scan latency |

### `observability`

Logging and tracing configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_level` | string | `"info"` | Tracing log level filter. One of: `trace`, `debug`, `info`, `warn`, `error`. |
| `log_format` | string | `"text"` | Output format. `"text"` for human-readable, `"json"` for structured logging. |

```yaml
observability:
  log_level: "info"
  log_format: "json"
```

### `operational`

Operational limits and timeouts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `request_timeout_secs` | integer | `30` | Maximum time in seconds for a single HTTP request. |
| `shutdown_timeout_secs` | integer | `10` | Graceful shutdown timeout in seconds. |
| `max_connections` | integer | `1024` | Maximum concurrent TCP connections. |
| `queue_depth` | integer | `4096` | Internal work queue depth. |

```yaml
operational:
  request_timeout_secs: 60
  max_connections: 2048
```

### `branding`

Global UI and email branding. Controls the product name, logo, and visual theme across the admin UI and all outbound emails.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `product_name` | string | `"Hearth"` | Shown in logo alt text, page titles, and email subjects. |
| `logo_url` | string | built-in Hearth SVG | Logo image URL. Can be a remote URL (used directly in `<img>`) or a local file path (read at startup, served at `/ui/static/custom-logo`). Supported formats: SVG, PNG, JPEG. |
| `theme` | string | `"ember"` | Named UI theme. See [Themes](#themes) below. |
| `custom_css` | string | — | Path to a CSS file appended after the named theme. Use this to override `--ht-*` CSS variables without forking a theme. Read once at startup. |

#### Themes

| Name | Type | Description |
|------|------|-------------|
| `ember` | dark | Warm charcoal with orange accents (default) |
| `ocean` | dark | Deep blue with teal accents |
| `midnight` | dark | Purple/violet dark theme |
| `forest` | dark | Green-accented dark theme |
| `cloud` | light | Clean light theme |
| `parchment` | light | Warm light theme |

```yaml
branding:
  product_name: "Acme Auth"
  logo_url: "/opt/hearth/logo.svg"
  theme: ocean
  custom_css: "/etc/hearth/brand.css"
```

### `email`

Outbound email delivery for verification emails, password resets, magic links, and invitation notifications.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `transport` | string | `"log"` | Delivery transport. One of: `log`, `smtp`, `sendgrid`, `postmark`, `mailgun`, `mailtrap`. |
| `from` | string | — | Sender address for the `From:` header. **Required** when transport is not `log`. |
| `smtp` | object | — | SMTP-specific settings. Required when `transport: smtp`. |
| `sendgrid` | object | — | SendGrid API settings. Required when `transport: sendgrid`. |
| `postmark` | object | — | Postmark API settings. Required when `transport: postmark`. |
| `mailgun` | object | — | Mailgun API settings. Required when `transport: mailgun`. |
| `mailtrap` | object | — | Mailtrap API settings. Required when `transport: mailtrap`. |
| `branding` | object | — | Global email branding defaults (accent color, support email, footer text). |
| `templates_dir` | string | — | Directory containing custom Tera email templates that override compiled defaults. |

#### `email.smtp`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | *required* | SMTP server hostname. |
| `port` | integer | *required* | SMTP port (25, 465, 587, or 1025 for a local relay). |
| `encryption` | string | `"starttls"` | Transport encryption: `none`, `starttls`, `tls`. |
| `username` | string | — | SMTP AUTH username. Must be paired with `password`. |
| `password` | string | — | SMTP AUTH password. Must be paired with `username`. |

#### `email.sendgrid`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | string | *required* | SendGrid API key. |

#### `email.postmark`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server_token` | string | *required* | Postmark server token. |

#### `email.mailgun`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | string | *required* | Mailgun API key. |
| `domain` | string | *required* | Sending domain (e.g. `mg.example.com`). |
| `region` | string | `"us"` | API region: `us` or `eu`. |

#### `email.mailtrap`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_key` | string | *required* | Mailtrap API key. |
| `inbox_id` | integer | — | Inbox ID for sandbox/testing mode. When set, emails go to the sandbox API. |

#### `email.branding`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `accent_color` | string | `"#E85D04"` | Brand color used in email templates. |
| `support_email` | string | — | Support email shown in email footers. |
| `custom_footer_text` | string | — | Custom text appended to email footers. |

```yaml
email:
  transport: smtp
  from: "Hearth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
  branding:
    accent_color: "#4F46E5"
    support_email: "support@example.com"
```

### `oidc`

OIDC Discovery metadata and authorization code behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | string | — | The `iss` claim in ID tokens and the `issuer` in the discovery document. Must be a valid HTTPS URL. **Required in production — no safe default exists.** |
| `authorization_code_ttl` | duration | `"10m"` | How long an authorization code is valid after issuance. |
| `enforce_nonces` | bool | `true` | When `true`, authorization requests must include a unique `nonce` parameter. Disable only for legacy clients that cannot supply a nonce. |
| `require_pkce_for_confidential_clients` | bool | `true` | Require PKCE for confidential OAuth clients (RFC 9700 §2.1.1). Disable only for legacy clients that cannot supply `code_challenge`. |

```yaml
oidc:
  issuer: "https://auth.example.com"
  authorization_code_ttl: "5m"
  enforce_nonces: true
```

### `token`

JWT issuance parameters.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | string | `oidc.issuer` | The `iss` claim value. Defaults to `oidc.issuer` when omitted. Set this only if your token issuer differs from the OIDC issuer. |
| `audience` | string | `oidc.issuer` | The `aud` claim value. Defaults to `oidc.issuer` when omitted. Override only if your resource server expects a different audience (e.g. a separate API gateway URL). |
| `access_token_ttl` | duration | `"15m"` | Access token lifetime. |
| `refresh_token_ttl` | duration | `"7d"` | Refresh token lifetime. |

```yaml
token:
  audience: "my-app"
  access_token_ttl: "30m"
  refresh_token_ttl: "14d"
```

### `auth`

Global authentication defaults. These apply to all realms unless overridden per-realm.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_ttl` | duration | `"24h"` | Default session lifetime. |
| `password_memory_cost` | integer | `65536` | Argon2id memory parameter in KiB (OWASP minimum). |
| `password_time_cost` | integer | `3` | Argon2id time parameter (iterations). |
| `mfa_required` | bool | `false` | Whether MFA is required for all users. Per-realm `auth.mfa_required` overrides. |
| `passkey_requires_mfa` | bool | `false` | Whether passkey login requires an additional TOTP challenge. Per-realm `auth.passkey_requires_mfa` overrides. |

```yaml
auth:
  session_ttl: "12h"
  password_memory_cost: 131072
  password_time_cost: 4
```

### `onboarding`

First-run setup flow configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | When `true`, the `/ui/setup` flow is available until the first admin is created. Set to `false` to permanently disable. |
| `base_url` | string | — | Public base URL for verification-email links (e.g. `https://auth.example.com`). Falls back to the request `Host` header when unset. |
| `notification_email` | string | — | Email address that receives the setup URL on first boot (requires a working email transport). |

```yaml
onboarding:
  base_url: "https://auth.example.com"
  notification_email: "ops@example.com"
```

---

### `security`

Global security hardening options.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dpop_nonce_secret` | string | `"auto"` | 32-byte HMAC secret for stateless DPoP nonce generation (RFC 9449). Absent or `"auto"`: a fresh random key is generated at each startup — safe for single-node deployments but invalidates all outstanding DPoP proofs on restart. A 64-character lowercase hex string is decoded to 32 bytes and used verbatim; use a stable hex key to keep nonces valid across rolling restarts or in multi-node deployments where all nodes must share the same secret. **Never use the all-zero key (`0000…`) in production** — the server rejects it at startup. Set via `HEARTH_DPOP_NONCE_SECRET` env var to avoid storing secrets in the YAML file. |
| `bearer_token` | string | — | Bearer token required to access the `/metrics` scrape endpoint (A-26). Requests without a matching `Authorization: Bearer <token>` header receive HTTP 401. Comparison is constant-time. When absent, the endpoint is unauthenticated — firewall it at the network layer instead. |
| `allowed_hosts` | list of strings | `[]` (any) | Allowlist of `Host` header values the server will accept (A-40). Requests with a `Host` not in this list are rejected with `400 Bad Request`. Include the port for non-standard ports (e.g. `"localhost:8420"`). Empty list = accept any host (backward-compatible default). |
| `allowed_return_to_origins` | list of strings | `[]` | Absolute origins permitted as `return_to` redirect targets (A-52). Relative paths (`/ui/…`) are always accepted. Absolute URLs are only accepted when their `scheme://host[:port]` matches an entry here. |
| `jwks_rps_limit` | integer | `60` | Maximum JWKS / discovery requests per source IP per second (A-10). Applies to all unauthenticated key-discovery endpoints. Requests beyond this limit receive `429 Too Many Requests`. |
| `reserved_slugs` | list of strings | 26-item built-in list | Slug names that may never be used as a realm or organization slug (case-insensitive). Setting this key **replaces** the built-in list entirely — include all names you still want reserved. The built-in default includes: `admin`, `api`, `support`, `www`, `mail`, `help`, `status`, `blog`, `app`, `auth`, `login`, `logout`, `signup`, `register`, `account`, `profile`, `settings`, `dashboard`, `billing`, `security`, `webhook`, `callback`, `oauth`, `oidc`, `saml`, `scim`. |
| `slug_cooldown_days` | integer | `30` | Days a slug is held in reserve after its realm or organization is deleted, before it may be reused. |

```yaml
security:
  dpop_nonce_secret: "${HEARTH_DPOP_NONCE_SECRET}"  # 64-char hex, or omit for auto
  reserved_slugs:
    - admin
    - api
    - auth
    - login
    - logout
    - signup
  slug_cooldown_days: 30
```

#### `security.backup`

Backup and restore hardening (A-30). When `verify_key` is set, the restore endpoint verifies that every uploaded archive's `manifest.json` carries a valid Ed25519 detached signature. Archives without a valid signature are rejected unconditionally (fail-closed). When absent, signature verification is skipped.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `verify_key` | string | — | Base64url-encoded Ed25519 public key (32 bytes, URL-safe no-padding). When set, all restore uploads must carry a matching `detached_signature_b64` in their manifest or they are rejected. |
| `export_rate_limit` | integer | `10` | Maximum backup/export calls per admin user per hour. Set to `0` to disable per-export rate limiting. |

```yaml
security:
  backup:
    verify_key: "${HEARTH_BACKUP_VERIFY_KEY}"  # base64url Ed25519 public key
    export_rate_limit: 10
```

#### `security.captcha`

CAPTCHA provider integration (P-1). When configured, Hearth renders a CAPTCHA challenge on the login, registration, and password-reset pages and verifies the token server-side before proceeding.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | — | **Required.** CAPTCHA provider to activate. Currently supported: `turnstile` (Cloudflare Turnstile). |
| `turnstile` | object | — | Turnstile-specific settings. **Required** when `provider: turnstile`. |

##### `security.captcha.turnstile`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `site_key` | string | *required* | Cloudflare Turnstile site key (public — safe to embed in HTML). Obtain from the Cloudflare Zero Trust dashboard. |
| `secret_key` | string | — | Cloudflare Turnstile secret key (private). Set via the `HEARTH_TURNSTILE_SECRET_KEY` environment variable rather than embedding in the config file. |
| `verify_url` | string | Cloudflare default | Override for the Turnstile siteverify URL. Omit in production; useful only for testing with a mock server. |

```yaml
security:
  captcha:
    provider: turnstile
    turnstile:
      site_key: "0x4AAAAAAA..."
      secret_key: "${HEARTH_TURNSTILE_SECRET_KEY}"
```

#### `security.rate_limiting`

Global per-IP and per-account rate-limit thresholds. These are the server-wide defaults; per-realm overrides live under `realms.<name>.auth.rate_limit`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `login_per_ip.max_attempts` | integer | `10` | Maximum failed login attempts from a single IP within the window before the IP is blocked. |
| `login_per_ip.window_seconds` | integer | `60` | Sliding window length in seconds for per-IP failed-login counting. |
| `login_per_account.max_failures` | integer | `5` | Maximum consecutive failures for a single account before it is locked out. |
| `login_per_account.lockout_seconds` | integer | `300` | Duration (seconds) of the account lockout after `max_failures` is reached. |

```yaml
security:
  rate_limiting:
    login_per_ip:
      max_attempts: 10
      window_seconds: 60
    login_per_account:
      max_failures: 5
      lockout_seconds: 300
```

##### Rate-Limit Durability After Restart

Not all rate limiters survive a server restart:

| Limiter | Scope | Restart-safe? |
|---------|-------|---------------|
| `login_per_account` (password brute-force) | per user | **Yes** — WAL-persisted and restored at startup |
| `login_per_ip` (IP flood) | per source IP | **No** — in-memory only, cleared on restart |
| Magic-link request rate | per email | **No** — in-memory only, cleared on restart |
| Password-reset request rate | per email | **No** — in-memory only, cleared on restart |
| Self-registration rate | per email / per IP | **No** — in-memory only, cleared on restart |

**Security implication:** an attacker who triggers or waits for a server restart can temporarily bypass the in-memory rate limits for magic-link, password-reset, and IP-based login flows. The window is narrow — the attacker must act immediately after restart — but operators should be aware of this behaviour in rolling-restart or high-availability deployments.

**Recommended mitigations:**

- Deploy a reverse-proxy (nginx, Caddy, Cloudflare) with its own IP-based rate limiting in front of Hearth. Proxy-level limits are not affected by application restarts.
- Keep restart windows short and infrequent in production.
- Enable CAPTCHA or MFA for magic-link and password-reset flows when operating in high-threat environments.

> **Future work:** WAL-persisted magic-link, password-reset, and IP rate trackers are tracked in
> [HEA-1139](/HEA/issues/HEA-1139). Contributions welcome.

#### `security.http2`

HTTP/2 rapid-reset defense parameters (A-39). These cap the number of concurrent streams and RST_STREAM frames per connection, mitigating CVE-2023-44487 (HTTP/2 Rapid Reset Attack).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_concurrent_streams` | integer | `100` | Maximum concurrent HTTP/2 streams per connection. |
| `max_pending_reset_streams` | integer | `10` | Maximum number of pending RST_STREAM frames (rapid-reset budget). Connections exceeding this are closed. |

```yaml
security:
  http2:
    max_concurrent_streams: 100
    max_pending_reset_streams: 10
```

---

#### `security.request_shaper`

Global per-IP and per-realm token-bucket request limiter (A-2). When absent, no global shaping is applied; operator is responsible for upstream rate limiting.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ip_rps` | integer | `100` | Maximum requests per second from a single source IP across all endpoints. |
| `realm_rps` | integer | `1000` | Maximum requests per second across all clients within a single realm. |

```yaml
security:
  request_shaper:
    ip_rps: 100
    realm_rps: 1000
```

---

#### `security.ip_reputation`

IP reputation integration (P-2). Checks incoming IPs against blocklists and optionally a MaxMind ASN database before processing requests.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Whether IP reputation checks are active. |
| `action` | string | `"log"` | Action taken when an IP is flagged: `"block"` (HTTP 403), `"challenge"` (CAPTCHA), or `"log"` (metric + log only). |
| `maxmind_db_path` | string | — | Path to a MaxMind GeoLite2-ASN or GeoIP2-ASN `.mmdb` file. When absent, MaxMind ASN lookup is disabled. |

```yaml
security:
  ip_reputation:
    enabled: true
    action: block
    maxmind_db_path: "/var/lib/hearth/GeoLite2-ASN.mmdb"
```

##### `security.ip_reputation.spamhaus`

Spamhaus DROP / EDROP IPv4/IPv6 blocklist settings. Lists are fetched at startup and refreshed on the configured interval.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `drop_url` | string | Spamhaus DROP URL | URL for the Spamhaus DROP (IPv4) list. |
| `dropv6_url` | string | Spamhaus EDROP URL | URL for the Spamhaus EDROP (IPv6) list. |
| `refresh_interval_secs` | integer | `86400` (24 h) | How often (seconds) the blocklists are re-fetched. |

```yaml
security:
  ip_reputation:
    enabled: true
    spamhaus:
      refresh_interval_secs: 86400  # 24 hours
```

---

#### `security.grpc`

gRPC-specific security settings (A-43).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `reflection_enabled` | bool | `false` (prod), `true` (dev) | Whether the gRPC server reflection service is exposed. Reflection reveals the full API schema to unauthenticated callers — keep disabled in production. Enabling in production also requires the `--allow-reflection-in-prod` CLI flag; the server refuses to start without it. |

```yaml
security:
  grpc:
    reflection_enabled: false
```

---

#### `security.tls`

TLS-specific security settings (A-44).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `crl_paths` | list of strings | `[]` | Paths to PEM-encoded Certificate Revocation List (CRL) files for mTLS. When non-empty, client certificates are checked against every CRL on each TLS handshake. Revoked certificates are rejected. Paths are reloaded on `SIGHUP` alongside the server certificate. Empty list = no revocation check (existing mTLS behaviour preserved). |

```yaml
security:
  tls:
    crl_paths:
      - "/etc/hearth/crl/ca.crl"
```

---

### `agent_auth`

Staged capability gate for agent authentication. Features are enabled per-capability rather than as a single binary switch — set only the capabilities whose implementation phase has shipped.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `capabilities.identity` | bool | `false` | Enables the M1 agent identity surface: `POST/GET/PATCH/DELETE /v1/agents`, `POST /v1/agents/{id}/credentials/keys`, `GET /v1/agents/{id}/credentials`, `DELETE /v1/agents/{id}/credentials/{cred_id}`, `GET /.well-known/agent.json`, `GET /realms/{name}/.well-known/agent.json`, and gRPC agent methods on `IdentityAdminService`. Set to `true` once M1 is deployed. |
| `capabilities.delegation` | bool | `false` | **Not yet implemented (M3).** Setting to `true` is a startup error. Enables act-as delegation chains and Agent Authorization Tokens (AATs). |
| `capabilities.mcp` | bool | `false` | **Not yet implemented (M2).** Setting to `true` is a startup error. Enables MCP authorization server and protected-resource surfaces. |

```yaml
agent_auth:
  capabilities:
    identity: true   # enables /v1/agents, /.well-known/agent.json, gRPC stubs

# Future phases (not yet implemented — setting these is a startup error):
#   delegation: false  # Phase C: act-as delegation + AATs
#   mcp: false         # Phase B: MCP authorization server + protected resources
```

> **Note:** Capabilities not listed here (delegation, mcp, approval, aat) are refused at startup with a descriptive error. See `docs/specs/AGENT_AUTH.md` for the full milestone map.

---

## `realms` Section

The `realms` key is a map of **slug → configuration**. When present, Hearth manages realms declaratively via YAML reconciliation at startup.

### Reconciliation Behavior

| Scenario | Action |
|----------|--------|
| YAML entry not in storage | **Created** as an Active realm |
| YAML entry exists in storage | Config **updated** if changed |
| Storage realm not in YAML | **Archived** (soft-deleted) |
| `realms` key omitted entirely | No realms → auto-create `"default"`; existing realms left untouched |

Archived realms appear in the Admin UI with an "Archived" badge and can be permanently deleted from there.

### Per-Realm Fields

Each realm entry supports:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_ttl` | duration | inherits `auth.session_ttl` | Per-realm session lifetime override. |
| `password_memory_cost` | integer | inherits `auth.password_memory_cost` | Per-realm Argon2id memory cost. |
| `password_time_cost` | integer | inherits `auth.password_time_cost` | Per-realm Argon2id time cost. |
| `email` | object | — | Per-realm email branding overrides. |
| `web` | object | — | Per-realm UI theme overrides. |
| `auth` | object | — | Per-realm auth policy (MFA, password policy, rate limits, token TTLs). |
| `applications` | map | — | Declarative OAuth 2.0 client definitions. |
| `organizations` | map | — | Declarative organization definitions. |
| `fapi_profile` | string | — | FAPI 2.0 Security Profile for the realm: `"baseline"` or `"advanced"`. When set, all clients in the realm must comply. `"baseline"` requires PAR + PKCE (S256). `"advanced"` adds JAR + JARM. Absent means standard OAuth 2.0 / OIDC rules apply. Can also be set at runtime via `PATCH /admin/realms/{id}/config`. |

### `realms.<name>.email`

| Field | Type | Description |
|-------|------|-------------|
| `branding.accent_color` | string | Override the email accent color for this realm. |
| `branding.support_email` | string | Override the support email shown in footers. |
| `branding.custom_footer_text` | string | Override the email footer text. |

### `realms.<name>.web`

| Field | Type | Description |
|-------|------|-------------|
| `theme` | string | Named theme override for this realm's UI sessions. |
| `custom_css` | string | Path to a CSS file for this realm's UI sessions. |

### `realms.<name>.auth`

Per-realm authentication policy. These are policy declarations stored in `RealmConfig` — enforcement happens in the identity engine.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mfa_required` | bool | `false` | Whether MFA is required for all users in this realm. |
| `passkey_requires_mfa` | bool | `false` | Whether passkey (WebAuthn) login still requires a TOTP challenge. Passkeys are inherently multi-factor, but regulated environments (healthcare, finance) may require an additional TOTP step. When `true` and the user has TOTP enrolled, passkey login redirects to the MFA challenge page. When `true` but the user has no TOTP enrolled, login proceeds normally. |
| `mfa_methods` | list | — | Allowed MFA methods: `"totp"`, `"webauthn"`, `"email_otp"`. When set, only the listed methods are offered for enrollment and challenge; methods not in the list are rejected. Absent = all methods allowed. |
| `allowed_auth_methods` | list | — | Allowed login methods: `"password"`, `"magic_link"`, `"passkey"`. |
| `password_policy` | object | — | Password complexity requirements (see below). |
| `token` | object | — | Per-realm token TTL overrides. |
| `rate_limit` | object | — | Per-realm rate limit overrides. |
| `adaptive_mfa` | object | — | Risk-based step-up MFA using device fingerprinting. See below. |

#### `realms.<name>.auth.password_policy`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_length` | integer | — | Minimum password length. Must be >= 1. |
| `require_uppercase` | bool | — | Require at least one uppercase letter. |
| `require_number` | bool | — | Require at least one digit. |
| `require_special` | bool | — | Require at least one special character. |

#### `realms.<name>.auth.token`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `access_token_ttl` | duration | inherits `token.access_token_ttl` | Per-realm access token lifetime. |
| `refresh_token_ttl` | duration | inherits `token.refresh_token_ttl` | Per-realm refresh token lifetime. |
| `password_reset_token_ttl` | duration | `"30m"` | Per-realm password reset token lifetime. Hard-capped at `1h` unless `allow_unsafe_ttl: true`. |
| `magic_link_ttl` | duration | `"15m"` | Per-realm magic link token lifetime. Hard-capped at `30m` unless `allow_unsafe_ttl: true`. |
| `allow_unsafe_ttl` | bool | `false` | Lift the A-14 TTL hard caps for this realm. When `true`, `password_reset_token_ttl` may exceed 1 hour and `magic_link_ttl` may exceed 30 minutes. Operators accept the additional token-theft window by enabling this flag. Never enable without a documented operational justification. |

#### `realms.<name>.auth.rate_limit`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_failed_logins` | integer | — | Maximum failed login attempts before lockout. |
| `lockout_duration` | duration | — | How long to lock out after exceeding max failed logins. |

#### `realms.<name>.auth.adaptive_mfa`

When enabled, Hearth computes a per-device fingerprint from `{user_id, ip_/24, user_agent_normalized}` using HMAC-SHA256. Devices that have not been seen within `recognition_window_days` trigger an additional MFA challenge — a step-up — regardless of the realm's base `mfa_required` setting.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable risk-based step-up MFA for this realm. When `true`, `fingerprint_hmac_secret` is required. |
| `recognition_window_days` | integer | `30` | Days a recognised device fingerprint remains valid. After this window expires the device is treated as unrecognised again and triggers a fresh MFA challenge. |
| `fingerprint_hmac_secret` | string | — | **Required when `enabled: true`.** HMAC-SHA256 key for deriving device fingerprints. Must be at least 32 bytes. Supply via an environment variable — never commit a plaintext value. |

```yaml
realms:
  customer-portal:
    auth:
      adaptive_mfa:
        enabled: true
        recognition_window_days: 30   # default: 30
        fingerprint_hmac_secret: "${HEARTH_REALM_CUSTOMER_PORTAL_FINGERPRINT_HMAC_SECRET}"
```

> **Key management:** See [Device fingerprint HMAC secret](../guides/security-hardening.md#device-fingerprint-hmac-secret) for key generation, minimum-length enforcement, Kubernetes injection, and the 9-step rotation runbook.

#### `realms.<name>.auth.webauthn_attestation`

WebAuthn attestation policy for the realm (A-13). When absent, any authenticator is accepted (fail-open default). Use this block to restrict which authenticators may register in the realm.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_none` | bool | `true` | Whether attestation format `"none"` is accepted. When `false`, platform and cross-platform authenticators that omit attestation are rejected at registration. Most consumer authenticators (Touch ID, Face ID, Android) send `"none"` — only set `false` in environments where authenticator provenance is a hard requirement. |
| `aaguid_allowlist` | list of strings | `[]` | Allowlist of authenticator AAGUID values in lowercase UUID format (e.g. `"aaguid-value-here"`). When non-empty, only authenticators whose AAGUID matches an entry in this list may register. An empty list (the default) accepts any AAGUID. |
| `require_prf` | bool | `false` | Require the `prf` WebAuthn extension. Reject authenticators that do not support PRF. |
| `require_large_blob` | bool | `false` | Require the `largeBlob` WebAuthn extension. Reject authenticators that do not support large blob storage. |

```yaml
realms:
  enterprise:
    auth:
      webauthn_attestation:
        allow_none: false          # require attestation
        aaguid_allowlist:
          - "08987058-cadc-4b81-b6e1-30de50dcbe96"  # YubiKey 5 series
```

### `realms.<name>.applications`

Declarative OAuth 2.0 client definitions. Keyed by a **slug** (used to derive a deterministic `client_id` via UUID v5).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | *required* | Human-readable application name. |
| `redirect_uris` | list | `[]` | Allowed OAuth 2.0 redirect URIs. |
| `grant_types` | list | `["authorization_code"]` | Allowed grant types: `authorization_code`, `client_credentials`, `refresh_token`, `device_code`. |
| `confidential` | bool | `false` | Whether this is a confidential client (has a client secret). |
| `client_secret` | string | — | Client secret. Supports `${ENV_VAR}` substitution. **Required** when `confidential: true`. Hashed with Argon2id before storage. |
| `access_token_authorization` | string | `embedded` | Controls how resource servers resolve RBAC permissions for tokens issued to this client. One of: `embedded`, `introspection`, `decision`. See [Token Authorization Modes](../guides/rbac.md#token-authorization-modes). |
| `require_consent` | bool | `true` | Whether users must approve the OAuth consent screen before tokens are issued. Set `false` only for first-party clients you control. |
| `profile` | string | `"standard"` | Security profile for this client: `"fapi2"` or `"standard"`. Setting `"fapi2"` subjects this client to FAPI 2.0 constraints (DPoP sender-constrained tokens, PAR, PKCE S256) regardless of the realm-level `fapi_profile`. |

Reconciliation:
- New slug → client **created** with deterministic UUID
- Existing slug → `name`, `redirect_uris`, `grant_types` **updated** if changed
- Removed slug → client **archived**

```yaml
realms:
  prod:
    applications:
      dashboard:
        name: "Dashboard"
        redirect_uris:
          - "https://app.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
      api-service:
        name: "API Service"
        confidential: true
        client_secret: "${API_CLIENT_SECRET}"
        grant_types:
          - client_credentials
        access_token_authorization: embedded    # embedded (default) | introspection | decision
```

### `realms.<name>.organizations`

Declarative organization definitions. Keyed by **slug**. Members and invitations are managed at runtime — not via YAML.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | *required* | Human-readable organization name. |
| `description` | string | — | Optional description. |
| `config.max_members` | integer | — | Maximum number of members allowed. `null`/omitted means unlimited. |

Reconciliation:
- New slug → organization **created**
- Existing slug → `name`, `description`, `config` **updated** if changed
- Removed slug → organization left in place (not archived, since it may have runtime members)

```yaml
realms:
  prod:
    organizations:
      acme-corp:
        name: "Acme Corporation"
        description: "Enterprise customer"
        config:
          max_members: 500
      beta-testers:
        name: "Beta Testers"
```

### `realms.<name>.federation`

Declarative external IdP connector configuration. Reconciled with storage at startup; connectors not represented in YAML are removed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `link_existing_accounts` | string | `"confirm"` | How to handle an external identity that matches an existing local user by email. One of: `disabled` (always JIT-provision a new account), `confirm` (require local-credential re-auth before linking — Keycloak-equivalent default), `auto` (auto-link on verified email match). |
| `providers` | map | `{}` | Connector definitions keyed by a slug used as the `?idp=<slug>` query parameter on the login page. |

#### `realms.<name>.federation.providers.<idp>`

Each entry under `providers` declares one external identity provider. The `type` field selects the underlying protocol.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | *required* | Protocol selector: `oidc` (generic), `google`, `microsoft`, `apple`, `github`, or `saml`. Presets (`google`, `microsoft`, etc.) have discovery URLs and scopes pre-filled. |
| `display_name` | string | preset default | Human-readable label shown on the login button. Overrides the preset default. |
| `client_id` | string | — | OAuth client ID registered at the upstream IdP. |
| `client_secret` | string | — | OAuth client secret. Use `${ENV_VAR}` substitution — never commit plaintext. |
| `issuer` | string | — | OIDC issuer URL. **Required** for `type: oidc`; optional for presets (use to pin to a specific Azure AD tenant). |
| `scopes` | list | preset default | OAuth scopes to request. Defaults to `["openid", "email", "profile"]` for OIDC types. |
| `claim_mappings` | map | — | Per-claim renames for IdPs that use non-standard claim names. Maps a Hearth field name (e.g. `"email"`) to the upstream claim name the IdP sends (e.g. `"upn"`). Useful for Azure AD (`"email": "upn"`) and custom Okta apps. |
| `leeway_seconds` | integer | `60` | Clock-skew allowance in seconds applied to OIDC ID-token `exp` and `nbf` checks. The default (60 s) follows standard OIDC RP tolerance. Raise only for enterprise IdPs with known clock drift; **maximum 300 s**. |

```yaml
realms:
  prod:
    federation:
      link_existing_accounts: confirm
      providers:
        google:
          type: google
          client_id: "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
        corp-sso:
          type: oidc
          display_name: "Corp SSO"
          issuer: "https://idp.corp.example.com"
          client_id: "${CORP_SSO_CLIENT_ID}"
          client_secret: "${CORP_SSO_CLIENT_SECRET}"
          leeway_seconds: 120   # corp IdP has known 2-minute clock drift
```

---

### `realms.<name>.saml_service_providers`

Declarative SAML 2.0 Service Provider (SP) registrations where **Hearth acts as the IdP**. Keyed by an operator-assigned slug that identifies the SP. Reconciled at startup — runtime SPs not present in YAML are removed.

Each entry configures one SP:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `entity_id` | string | *required* | SP entity ID (a URI, e.g. `https://app.example.com/saml/metadata`). Must match the `Issuer` in AuthnRequests from this SP. |
| `acs_url` | string | *required* | Assertion Consumer Service URL — where Hearth posts the SAML response. |
| `slo_url` | string | — | Single Logout Service URL. When present, Hearth sends a `<LogoutRequest>` here on user logout. |
| `sp_certificate_pem` | string | — | PEM-encoded SP certificate for verifying signed AuthnRequests. Required when `want_authn_requests_signed: true`. |
| `sign_assertions` | bool | `true` | Whether Hearth signs individual `<Assertion>` elements. |
| `sign_responses` | bool | `false` | Whether Hearth signs the outer `<Response>` envelope in addition to assertions. |
| `want_authn_requests_signed` | bool | `false` | Require incoming AuthnRequests to carry a valid XML signature. Needs `sp_certificate_pem` to verify. |
| `nameid_format` | string | `emailAddress` | NameID format to use in assertions: `emailAddress`, `persistent`, `transient`, or `unspecified`. |
| `attribute_map` | map | `{}` | Custom SAML attribute statements. Keys are attribute names; values are Hearth claim paths (e.g. `user.email`, `user.display_name`, `roles`). |

```yaml
realms:
  - name: corp
    saml_service_providers:
      salesforce:
        entity_id: "https://myorg.my.salesforce.com"
        acs_url: "https://myorg.my.salesforce.com/sso/saml"
        slo_url: "https://myorg.my.salesforce.com/slo/saml"
        sign_assertions: true
        sign_responses: false
        nameid_format: emailAddress
        attribute_map:
          email: user.email
          displayName: user.display_name
          groups: roles
```

The SAML IdP metadata (public signing key, SSO endpoint) for a realm is available at:
```
GET /realms/{realm-name}/saml/idp-metadata.xml
```

---

### `realms.<name>.rbac`

Declarative role, permission, group, and scope setup for the realm's RBAC model. See [`AUTHORIZATION.md`](./AUTHORIZATION.md) for the semantic model and [`AUTHZ_EXPANSION.md`](./AUTHZ_EXPANSION.md) for the full registry, scope-bundle, and claim-profile surfaces.

**Authoring model:** permissions, roles, and scope bundles are YAML-only. The admin UI displays them read-only. Runtime data (group memberships, user role assignments, user extras, OAuth consents) is admin-UI-managed. A YAML reload hot-swaps the registry via `ArcSwap`; dangling references are handled lazily (fail-closed at resolution).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `permissions` | array of permission | `[]` | Permission definitions. See rules below. |
| `permissions[].name` | string | *required* | Permission identifier. Must contain `.`, must not contain `:`. Pattern: `^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$`. ≤128 chars. Reserved namespace `hearth.*` rejected. Single-word names (e.g. `admin`) rejected — use `system.admin`. |
| `permissions[].display_name` | string | *required* | Human-readable label for admin UI and consent screens. |
| `permissions[].description` | string | — | Optional longer explanation. |
| `permissions[].category` | string | — | Optional tag for admin UI grouping. |
| `roles` | array of role | `[]` | Role definitions. |
| `roles[].name` | string | *required* | Role identifier, unique per realm. |
| `roles[].scope_kind` | `realm` \| `organization` \| `any` | `realm` | Controls where this role may be assigned. Realm-kind roles cannot be assigned at org scope and vice versa; `any` accepts either. |
| `roles[].permissions` | array of strings | `[]` | Permission names granted by this role. All must be declared in the realm's `permissions` list. |
| `roles[].parents` | array of strings | `[]` | Parent role names. Resolution unions parent permissions (composition depth capped at 10, cycle-detected). |
| `roles[].description` | string | — | Optional description for admin UI display. |
| `groups` | map of group | `{}` | Groups keyed by slug. Group memberships are runtime data (admin-UI-managed). |
| `groups.<slug>.name` | string | *required* | Human-readable name. |
| `groups.<slug>.description` | string | — | Optional description. |
| `scopes` | array of scope bundle | `[]` | OPTIONAL coarse-grained consent bundles. When a token request specifies `scope=<name>`, the user's effective permissions are intersected with the bundle's permissions (per AUTHZ_EXPANSION). A client may also request individual permission names directly as scopes without needing a bundle. |
| `scopes[].name` | string | *required* | Bundle identifier. Must contain `:`, must not contain `.`. Pattern: `^[A-Za-z0-9_\-]+(:[A-Za-z0-9_\-]+)+$`. ≤128 chars. Single-word names rejected. |
| `scopes[].display_name` | string | *required* | Shown on consent screens. |
| `scopes[].description` | string | — | Shown on consent screens. |
| `scopes[].permissions` | array of strings | *required* | Permission names this bundle expands to. All must be declared in the realm's `permissions` list. |
| `claims` | object | *(defaults)* | OPTIONAL override of the realm's token claim profile. Absent → default profile emits `roles`, `groups`, `permissions`, `oid` with their standard shapes. Note: under the layered profile model in [`AUTHZ_EXPANSION.md`](./AUTHZ_EXPANSION.md), `roles`, `groups`, AND `permissions` are gated `first_party_only: true` by default — third-party clients receive none of these by default. |
| `claims.mappings` | array of mapping | `[]` | Ordered list of claim mappings appended after the built-in defaults and evaluated under the **layered gate-aware fallback model** per (claim-name, token-target) tuple. NOT last-wins replacement — when a YAML override's release gates fail for a given context, evaluation falls back to the default mapping for the same (claim, target) rather than suppressing the claim entirely. See `AUTHZ_EXPANSION.md` §"Evaluation and merge model" for the authoritative rule. |
| `claims.mappings[].claim` | string | *required* | Target JWT claim name. Tier 1 claims (JWT-registered, identity, authorization, tenant-routing, OIDC flow, token-binding, client-identity, proof-of-possession, delegation-attestation, and verification-attestation claims) rejected at config load. See `AUTHZ_EXPANSION.md` §"Claim name tiers" for the full Tier 1 list. |
| `claims.mappings[].source` | enum | *required* | One of: `roles_from_assignments`, `groups_from_memberships`, `effective_permissions`, `org_context`, `canonical_user_field` (with `field` — closed enum of OIDC standard fields), `user_attribute` (with `attribute` — `User.attributes` map lookup, **disjoint from canonical**), `role_subset` (with `prefix`), `constant` (with `value`), `omit`. |
| `claims.mappings[].include_in_access_token` | bool | `true` | Whether this claim appears in access tokens. |
| `claims.mappings[].include_in_id_token` | bool | `true` | Whether this claim appears in ID tokens. |
| `claims.mappings[].include_in_userinfo` | bool | `false` | Whether this claim is emitted by the `/userinfo` endpoint. The merge model evaluates per (claim, token-target) — a YAML override gated for ID tokens does NOT suppress the default's UserInfo emission. |
| `claims.mappings[].first_party_only` | bool | `true` for Tier 3 (custom) claims; default of the overridden mapping otherwise | Release gate: emit only when `client.trust_level == FirstParty`. Tier 3 custom claims default to `true` (over-disclosure is opt-in). |
| `claims.mappings[].required_scopes` | array of strings | — | Release gate: if set, the **granted** scope set (post-resolution, not raw request) must include ≥1 of these for the claim to emit. |
| `claims.mappings[].allowed_clients` | array of strings | — | Release gate: if set, the requesting client's slug must be in this list. **Managed-client slugs only** — DCR-registered slugs are rejected at config load. |
| `protected_resources` | array of resource | `[]` | OPTIONAL RFC 8707 protected-resource registrations (e.g., MCP tool servers). Each resource owns its own scope namespace; scopes declared here are NOT realm-global and apply only when a token is issued with `aud` set to this resource's URI. See `AUTHZ_EXPANSION.md` §"Architectural Model" and `AGENT_AUTH.md` §2.5. |
| `protected_resources[].resource_uri` | string | *required* | Canonical URI of the protected resource (becomes the token `aud` claim). |
| `protected_resources[].display_name` | string | *required* | Shown on consent screens. |
| `protected_resources[].scopes` | array of scope bundle | `[]` | Resource-local scope bundles. Same shape as the realm-level `scopes` entries. Looked up only when a token request includes `resource = <this URI>`; the realm-level `scopes` block is NOT consulted under a resource. |
| `oauth_clients[].slug` | string | *required* | Realm-unique human-readable handle. Managed clients (declared in YAML) have admin-authored slugs; runtime-registered (DCR) clients have auto-generated slugs and cannot be referenced from `allowed_clients` mapper gates. |

**Example:**

```yaml
realms:
  prod:
    rbac:
      permissions:
        - { name: docs.view,       display_name: "View documents",   category: Documents }
        - { name: docs.edit,       display_name: "Edit documents",   category: Documents }
        - { name: docs.delete,     display_name: "Delete documents", category: Documents }
        - { name: billing.view,    display_name: "View billing",     category: Billing }
        - { name: billing.write,   display_name: "Manage billing",   category: Billing }
        - { name: system.admin,    display_name: "System administrator", category: System }

      roles:
        - name: docs.viewer
          scope_kind: realm
          permissions: [docs.view]
          description: "Read-only access to docs"
        - name: docs.editor
          scope_kind: realm
          permissions: [docs.view, docs.edit]
          parents: [docs.viewer]
        - name: docs.admin
          scope_kind: realm
          permissions: [docs.delete]
          parents: [docs.editor]
          description: "Full docs administration"
        - name: billing.admin
          scope_kind: organization
          permissions: [billing.view, billing.write]

      groups:
        engineering:
          name: "Engineering"
          description: "All engineers"
        leads:
          name: "Engineering Leads"

      scopes:
        # OPTIONAL — only define when you want coarse-grained consent bundling
        - name: read:docs
          display_name: "Read your documents"
          description: "View documents you own or have been shared with you."
          permissions: [docs.view]
        - name: manage:billing
          display_name: "Manage your billing"
          description: "View and update billing settings."
          permissions: [billing.view, billing.write]

    claims:
      # OPTIONAL — omit for default shape
      mappings:
        - { claim: groups,     source: omit }
        - { claim: department, source: user_attribute, attribute: dept }
```

The first user created in a realm is automatically assigned the seed `realm.admin` role (not configurable). All other role assignments happen at runtime via the admin API.

### `realms.<name>.quotas`

> **Admin API only.** Per-realm resource quotas are not currently configurable via `hearth.yaml`. They are set and read via `PATCH /admin/realms/{id}/config` and `GET /admin/realms/{id}`. This section documents the available quota fields for operators using the admin API.

Resource quotas cap the number of entities that can exist in a realm at once. All limits are enforced synchronously on the create path (except `max_disk_bytes`, which is sampled by a background task).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_users` | integer | unlimited | Maximum number of user records allowed in the realm. Attempts to create a user when this limit is reached return HTTP 422. |
| `max_orgs` | integer | unlimited | Maximum number of organizations allowed in the realm. |
| `max_clients` | integer | unlimited | Maximum number of OAuth/OIDC clients registered in the realm. |
| `max_sessions` | integer | unlimited | Maximum total active sessions across all users in the realm. Checked synchronously on `create_session`. Because this requires a full-prefix scan, only set this for realms with a known bounded user population. |
| `max_audit_rows` | integer | unlimited | Maximum number of audit log rows retained for the realm. Enforced by the background pruner — oldest rows are deleted when the limit is exceeded. |
| `max_disk_bytes` | integer | unlimited | Disk-usage warning threshold in bytes for the realm's storage prefix. Checked by the background pruner (sampled, once per day). Exceeding this limit emits a warning log but does **not** block writes. |

**Example (admin API):**

```bash
curl -s -X PATCH \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:8420/admin/realms/<realm-id>/config \
  -d '{
    "quotas": {
      "max_users": 10000,
      "max_clients": 50,
      "max_audit_rows": 1000000
    }
  }'
```

---

### `realms.<name>.seed_users`

Declarative user accounts created at startup if they do not already exist. Reconciliation is **additive-only** — existing accounts are never modified or deleted by the reconciler. Useful for local development, demo environments, and automated test setups.

Each entry in the list is a `SeedUserYamlConfig`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `email` | string | — | Email address, unique within the realm. **Required.** |
| `display_name` | string | — | Human-readable display name. **Required.** |
| `password` | string | — | Initial plaintext password. Hashed with Argon2id at startup before storage. **Required.** Use `${ENV_VAR}` substitution to avoid committing passwords. |
| `roles` | string[] | `[]` | Role names to assign at creation time. Must match roles declared under `realms.<name>.rbac.roles` or the built-in RBAC seed roles for this realm. |
| `email_verified` | bool | `true` | When `true`, the account is activated immediately with no email verification step. Set to `false` to leave the account in `PendingVerification`. |

```yaml
realms:
  - name: my-app
    seed_users:
      - email: "admin@example.com"
        display_name: "Admin User"
        password: "${SEED_ADMIN_PASSWORD}"
        roles: ["realm.admin"]
        email_verified: true
      - email: "viewer@example.com"
        display_name: "Viewer"
        password: "${SEED_VIEWER_PASSWORD}"
        roles: ["viewer"]
```

> **Security note:** Seed user passwords appear in `hearth.yaml`. Always use `${ENV_VAR}` substitution in production so plaintext passwords are never committed to version control.

---

### `realms.<name>` — Migration Controls

Three fields trigger one-shot realm data migrations during startup reconciliation. **Remove them from YAML after the migration completes** — the reconciler marks the flag consumed, and leaving them in has no effect on subsequent restarts, but keeping them prevents accidental re-migration after future config reloads.

| Field | Type | Description |
|-------|------|-------------|
| `migrate_from` | string | Slug of the source realm to migrate from. After migration, the source is **archived** (orphan-detection treats the slug as resolved). Use when decommissioning the source realm. |
| `copy_from` | string | Like `migrate_from` but with copy semantics — the source realm is **left intact** after users are copied to the destination. Use when duplicating a realm for staging or A/B purposes. |
| `migrate` | object | Fine-grained migration options. Only meaningful when `migrate_from` or `copy_from` is set. All fields have defaults and the block may be omitted entirely. |

#### `realms.<name>.migrate`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `users` | bool | `true` | Whether to copy user records and credentials. |
| `orgs` | bool | `true` | Whether to copy organization memberships for migrated users. |
| `applications` | bool | `false` | Whether to copy OAuth 2.0 application (client) registrations. |
| `on_conflict` | string | `"error"` | Action when a user with the same email already exists in the destination realm: `"error"` (collect all conflicts and abort startup with a full list) or `"skip"` (leave conflicting users in the source realm and continue). |

```yaml
realms:
  - name: production
    migrate_from: staging      # "staging" will be archived after migration
    migrate:
      users: true
      orgs: true
      applications: false
      on_conflict: skip        # skip conflicts rather than aborting
```

---

### `realms.<name>.attribute_definitions`

Declares a strict attribute schema for users and organizations in a realm. When this block is present, only the declared attribute keys are accepted at create/update time — unknown keys are rejected with a validation error. **When absent (the default), attributes are free-form**: any key-value pair is accepted.

Use `attribute_definitions` when you need to enforce a canonical set of user/org properties for compliance, reporting, or UI consistency.

#### `realms.<name>.attribute_definitions.users` / `.organizations`

Each list entry declares one attribute:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `key` | string | *required* | Machine-readable attribute key. Used as the storage key; must be URL-safe. |
| `label` | string | same as `key` | Human-readable label shown in the admin UI. |
| `type` | string | `"string"` | Data type hint for validation and UI rendering: `"string"`, `"number"`, `"boolean"`, or `"enum"`. |
| `required` | bool | `false` | When `true`, the attribute must be present when creating a record. |
| `description` | string | — | Short description shown as a placeholder or tooltip in the admin UI. |
| `enum_values` | list of strings | `[]` | Allowed values when `type: enum`. Ignored for other types. |

```yaml
realms:
  - name: corp
    attribute_definitions:
      users:
        - key: employee_id
          label: "Employee ID"
          type: string
          required: true
          description: "HR system identifier"
        - key: department
          type: enum
          enum_values: [engineering, sales, support, product]
        - key: is_contractor
          type: boolean
      organizations:
        - key: tier
          type: enum
          enum_values: [free, pro, enterprise]
          required: true
```

---

## Complete Example

```yaml
server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path: "/etc/hearth/tls/server.key"

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

observability:
  log_level: "info"
  log_format: "json"

branding:
  product_name: "Acme Auth"
  theme: ocean

email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    username: "${SMTP_USER}"
    password: "${SMTP_PASS}"

oidc:
  issuer: "https://auth.example.com"

token:
  access_token_ttl: "15m"
  refresh_token_ttl: "7d"

auth:
  session_ttl: "24h"

onboarding:
  base_url: "https://auth.example.com"

security:
  bearer_token: "${HEARTH_METRICS_TOKEN}"
  allowed_hosts:
    - "auth.example.com"
  dpop_nonce_secret: "${HEARTH_DPOP_NONCE_SECRET}"
  jwks_rps_limit: 60
  http2:
    max_concurrent_streams: 100
    max_pending_reset_streams: 10
  request_shaper:
    ip_rps: 100
    realm_rps: 1000
  ip_reputation:
    enabled: true
    action: block
  rate_limiting:
    login_per_ip:
      max_attempts: 10
      window_seconds: 60
    login_per_account:
      max_failures: 5
      lockout_seconds: 300
  backup:
    verify_key: "${HEARTH_BACKUP_VERIFY_KEY}"
    export_rate_limit: 10

realms:
  customer-portal:
    session_ttl: "12h"
    web:
      theme: cloud
    auth:
      mfa_required: true
      passkey_requires_mfa: true
      mfa_methods: [totp, webauthn]
      password_policy:
        min_length: 12
        require_uppercase: true
        require_number: true
      rate_limit:
        max_failed_logins: 5
        lockout_duration: "15m"
    applications:
      portal-app:
        name: "Customer Portal"
        redirect_uris:
          - "https://portal.example.com/callback"
        grant_types: [authorization_code, refresh_token]
    organizations:
      acme:
        name: "Acme Corp"
        config:
          max_members: 100

  internal:
    session_ttl: "8h"
    applications:
      api:
        name: "Internal API"
        confidential: true
        client_secret: "${INTERNAL_API_SECRET}"
        grant_types: [client_credentials]
```

---

## Defaults Table

Every field's default value at a glance.

| Section | Field | Default |
|---------|-------|---------|
| `server` | `bind_address` | `"127.0.0.1"` |
| `server` | `port` | `8420` |
| `server` | `tls_require_client_cert` | `false` |
| `server` | `trusted_proxies` | `[]` (disabled) |
| `server` | `trust_forwarded_proto` | `false` |
| `cluster` | `peer_address` | `"127.0.0.1:8421"` |
| `cluster` | `read_lag_threshold_ms` | `500` |
| `storage` | `data_dir` | `"./data"` |
| `storage` | `wal_max_size_bytes` | `268435456` (256 MiB) |
| `storage` | `memtable_flush_bytes` | `67108864` (64 MiB) |
| `storage` | `hot_tier_capacity` | `10000` |
| `storage` | `fsync` | `true` |
| `observability` | `log_level` | `"info"` |
| `observability` | `log_format` | `"text"` |
| `operational` | `request_timeout_secs` | `30` |
| `operational` | `shutdown_timeout_secs` | `10` |
| `operational` | `max_connections` | `1024` |
| `operational` | `queue_depth` | `4096` |
| `branding` | `product_name` | `"Hearth"` |
| `branding` | `theme` | `"ember"` |
| `email` | `transport` | `"log"` |
| `email.smtp` | `encryption` | `"starttls"` |
| `email.mailgun` | `region` | `"us"` |
| `oidc` | `issuer` | required (no default) |
| `oidc` | `authorization_code_ttl` | `"10m"` |
| `oidc` | `enforce_nonces` | `true` |
| `oidc` | `require_pkce_for_confidential_clients` | `true` |
| `token` | `issuer` | same as `oidc.issuer` |
| `token` | `audience` | same as `oidc.issuer` |
| `token` | `access_token_ttl` | `"15m"` |
| `token` | `refresh_token_ttl` | `"7d"` |
| `auth` | `session_ttl` | `"24h"` |
| `auth` | `mfa_required` | `false` |
| `auth` | `passkey_requires_mfa` | `false` |
| `realms.<name>.auth.adaptive_mfa` | `enabled` | `false` |
| `realms.<name>.auth.adaptive_mfa` | `recognition_window_days` | `30` |
| `realms.<name>.auth.webauthn_attestation` | `allow_none` | `true` |
| `realms.<name>.auth.webauthn_attestation` | `require_prf` | `false` |
| `realms.<name>.auth.webauthn_attestation` | `require_large_blob` | `false` |
| `realms.<name>.auth.token` | `password_reset_token_ttl` | `"30m"` |
| `realms.<name>.auth.token` | `magic_link_ttl` | `"15m"` |
| `realms.<name>.auth.token` | `allow_unsafe_ttl` | `false` |
| `realms.<name>.federation.providers.<idp>` | `leeway_seconds` | `60` |
| `agent_auth.capabilities` | `identity` | `false` |
| `agent_auth.capabilities` | `delegation` | `false` |
| `agent_auth.capabilities` | `mcp` | `false` |
| `realms.<name>.seed_users[*]` | `email_verified` | `true` |
| `realms.<name>.seed_users[*]` | `roles` | `[]` |
| `realms.<name>.migrate` | `users` | `true` |
| `realms.<name>.migrate` | `orgs` | `true` |
| `realms.<name>.migrate` | `applications` | `false` |
| `realms.<name>.migrate` | `on_conflict` | `"error"` |
| `security` | `dpop_nonce_secret` | `"auto"` (random per startup) |
| `security` | `jwks_rps_limit` | `60` |
| `security` | `allowed_hosts` | `[]` (any) |
| `security` | `allowed_return_to_origins` | `[]` |
| `security` | `reserved_slugs` | 26-item built-in list |
| `security` | `slug_cooldown_days` | `30` |
| `security.backup` | `export_rate_limit` | `10` |
| `security.captcha.turnstile` | `verify_url` | Cloudflare default |
| `security.http2` | `max_concurrent_streams` | `100` |
| `security.http2` | `max_pending_reset_streams` | `10` |
| `security.ip_reputation` | `enabled` | `false` |
| `security.ip_reputation` | `action` | `"log"` |
| `security.ip_reputation.spamhaus` | `refresh_interval_secs` | `86400` (24 h) |
| `security.grpc` | `reflection_enabled` | `false` (prod), `true` (--dev) |
| `security.rate_limiting.login_per_ip` | `max_attempts` | `10` |
| `security.rate_limiting.login_per_ip` | `window_seconds` | `60` |
| `security.rate_limiting.login_per_account` | `max_failures` | `5` |
| `security.rate_limiting.login_per_account` | `lockout_seconds` | `300` |
| `onboarding` | `enabled` | `true` |
