## ADDED Requirements

### Requirement: A-1 One abuse policy consulted by every public handler
Every publicly reachable handler SHALL consult one per-realm abuse policy through a single `AbuseGuard` check that returns `Allow`, `Challenge` or `Deny(reason)`. The policy SHALL be swapped atomically on reload and looked up without allocation. The check SHALL take at most 5 µs at p99 on an `Allow` outcome, and a CI benchmark SHALL gate that budget. Every deny-list and rate-limit change SHALL be reversible from the admin UI without a restart. The guard SHALL never deny the realm owner's own admin session.

#### Scenario: A public handler is called
- **WHEN** a request reaches any publicly reachable handler
- **THEN** the handler asks the realm's `AbuseGuard` and acts on `Allow`, `Challenge` or `Deny`

#### Scenario: A deny entry matches the realm owner
- **WHEN** a deny-list entry matches the address of the realm owner's own admin session
- **THEN** that admin session is not denied

#### Scenario: An operator lifts a block
- **WHEN** an operator removes a deny-list entry in the admin UI
- **THEN** the next request from that address is allowed, with no restart

### Requirement: A-51 Signed audit-head attestations shipped off-host
The server SHALL periodically (for example hourly) sign each realm's audit-chain head hash with the realm's dedicated audit key and ship the attestation to an operator-supplied destination (an S3 bucket, a transparency log or a webhook). On restart the server SHALL verify the last shipped attestation against the current chain.

#### Scenario: Storage rewrites the chain
- **WHEN** a compromised storage layer rewrites both audit payloads and the hash chain after an attestation was shipped
- **THEN** the restart check finds that the chain no longer matches the shipped head hash

### Requirement: P-6 WAF egress through the security webhook channel
Hearth SHALL ship a `WafEgress` integration, with a no-op reference adapter, that forwards security events to an external WAF (for example AWS WAF, Cloudflare WAF or Fastly) through the A-7 security webhook channel.

#### Scenario: A WAF adapter is configured
- **WHEN** an operator configures a WAF egress adapter and the A-3 detector fires
- **THEN** the abuse event reaches the WAF through the security webhook channel

### Requirement: A-8 Block and unblock an IP from the abuse dashboard
The admin abuse dashboard SHALL offer a one-click block and unblock of an IP, which writes the realm's A-9 deny list.

#### Scenario: An operator blocks a failing IP
- **WHEN** an operator clicks "block" next to an IP in the top failing IPs table
- **THEN** the next login from that IP is refused by the A-9 policy

### Requirement: A-14 Lifting a TTL cap is logged
When `auth.token.allow_unsafe_ttl: true` lets a realm exceed the password-reset or magic-link TTL cap, the server SHALL log a warning at startup that names the realm and the field.

#### Scenario: Unsafe TTL accepted with a warning
- **WHEN** a realm sets `password_reset_token_ttl: 2h` and `allow_unsafe_ttl: true`
- **THEN** the configuration loads and a warning naming the realm and `password_reset_token_ttl` is logged

### Requirement: A-19 Self-service email change is reachable and notifies the old address
A user SHALL be able to start and confirm an email change through an HTTP or UI route that drives the token-verified email-change flow. After confirmation the server MUST send a `security.email_changed` notification with a revoke link to the old address.

#### Scenario: A user changes their email
- **WHEN** a signed-in user requests an email change and confirms it with the token sent to the new address
- **THEN** the change takes effect and the old address receives a `security.email_changed` notification with a revoke link

### Requirement: A-27 Per-deployment PII logging override
An operator SHALL be able to opt a deployment into logging redacted fields with `HEARTH_LOG_INCLUDE_PII=1`, and SHALL be able to set the same override per realm. Without the override, redaction SHALL stay on.

#### Scenario: The override is set
- **WHEN** `HEARTH_LOG_INCLUDE_PII=1` is set and the server logs a password-reset URL
- **THEN** the log record shows the URL

### Requirement: A-40 Cookie name prefixes and partitioned session cookies
Cookies SHALL carry the `__Host-` or `__Secure-` name prefix where applicable. Session cookies MAY carry the `Partitioned` attribute (CHIPS).

#### Scenario: The session cookie is issued over TLS
- **WHEN** a user signs in over HTTPS
- **THEN** the session cookie name starts with `__Host-`

### Requirement: P-7 Session lookups go through a pluggable store
Session listing and lookup SHALL go through a pluggable `SessionStore` interface, so the A-18 concurrent-session policy is enforceable cluster-wide in multi-node deployments. The WAL-backed embedded store SHALL be the reference adapter. Hot-path callers SHALL treat a store error as "session not found", so a transient outage does not lock users out.

#### Scenario: The store errors on lookup
- **WHEN** the session store returns an error during a hot-path lookup
- **THEN** the caller treats the session as not found

### Requirement: P-8 Secrets are read through a pluggable backend
Signing keys, encryption-at-rest keys and the Argon2 pepper SHALL be read and written through a pluggable `SecretsBackend`. The storage-under-system-realm backend SHALL be the default and SHALL need no migration. A file backend SHALL store keys as files and write them atomically. KMS and HSM adapters MAY ship as stubs that answer "not configured". The backend SHALL fail closed: any error SHALL propagate to the caller with no fallback to another backend, and the server SHALL NOT start when the system realm signing key cannot be loaded.

#### Scenario: The backend is unavailable at startup
- **WHEN** the secrets backend cannot return the system realm signing key at startup
- **THEN** the server refuses to start

### Requirement: Abuse data retention and IP truncation
Retention of IP and ASN data collected by the abuse controls SHALL be configurable, with a default of 30 days. When `privacy.truncate_ip = true`, IP addresses SHALL be truncated to `/24` in the audit log. Tokens and passwords SHALL be redacted from request metadata before it is handed to a pluggable provider.

#### Scenario: IP truncation is on
- **WHEN** `privacy.truncate_ip` is `true` and a login fails from `198.51.100.23`
- **THEN** the audit event records `198.51.100.0/24`
