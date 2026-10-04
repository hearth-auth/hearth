## ADDED Requirements

### Requirement: Abuse guards are opt-in and run before password hashing
The guards listed below, except A-12, SHALL be off by default. A-12 SHALL always be on for `POST /ui/device`. A disabled guard SHALL be constructed in its no-op form and SHALL allow every request, so upgrading changes no behaviour until an operator enables a guard. The login-form guards SHALL run before a permit is taken from the Argon2 admission gate, so rejected traffic consumes no hashing capacity. Every refusal by a login-form guard SHALL render the one generic sign-in failure page, so no guard is an account-enumeration oracle.

| Guard | Where it is consulted |
|-------|-----------------------|
| A-3 distributed-attack detector | login form, before the admission gate |
| A-9 tenant CIDR policy | login form, before the admission gate |
| A-16 CAPTCHA challenge state | login form, before the admission gate |
| A-4 outbound volume shield | self-service verification and password-reset sends |
| A-50 cross-realm aggregation cap | self-service verification and password-reset sends |
| A-12 adaptive backoff | `POST /ui/device` approval guard |

#### Scenario: No guard is configured
- **WHEN** `hearth.yaml` enables none of the guards above
- **THEN** login, registration and outbound mail behave exactly as they do without the guards

#### Scenario: A guard refuses a login
- **WHEN** a login-form guard refuses a sign-in attempt
- **THEN** the response is the same generic sign-in failure page that a wrong password gets
- **AND** no Argon2 work is done for the attempt

### Requirement: A-2 Global request shaper
The server SHALL apply a per-client and a per-realm request-rate limit to all public routes, counted in a sliding one-second window. The shaper SHALL be on when `security.request_shaper` is absent. The defaults SHALL be 100 requests per second per IP and 1000 requests per second per realm. Both limits SHALL be configurable under `security.request_shaper` (`ip_rps`, `realm_rps`), where `0` disables that dimension. A shed request SHALL receive `429 Too Many Requests` with `Retry-After: 1` and a JSON body whose `limiter` field is `shaper`.

#### Scenario: One address floods the server
- **WHEN** one client address sends more than `ip_rps` requests in one second
- **THEN** the excess requests receive `429` with `Retry-After: 1`

#### Scenario: One realm is flooded from many addresses
- **WHEN** requests naming one realm exceed `realm_rps` in one second
- **THEN** the excess requests receive `429`, and requests to other realms are unaffected

### Requirement: A-3 Distributed-attack detector
The server SHALL count, in a rolling window, the distinct usernames tried from each source IP and the distinct source IPs that target each username, and SHALL challenge a login attempt when either count exceeds its threshold. Each counting bucket SHALL hold at most `2 × threshold` entries, so memory per key is bounded whatever the attack rate.

| Key (`security.distributed_attack_detector.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Whether the detector runs |
| `window` | `300s` | Rolling window length |
| `username_per_ip_threshold` | `20` | Distinct usernames per IP |
| `ip_per_username_threshold` | `20` | Distinct IPs per username |

A caller that receives a challenge MUST emit an `AbuseDetected` audit event with the IP and the username in its metadata, MUST apply the A-16 challenge, and MUST return an error to the client (HTTP `429` or a challenge token). The caller MUST NOT surface the challenge reason to the client. Setting a threshold to `usize::MAX` SHALL disable that dimension. When its lock is poisoned, the detector SHALL recover the lock and keep counting.

#### Scenario: Password spray from one address
- **WHEN** one source IP tries more than `username_per_ip_threshold` distinct usernames inside the window
- **THEN** the next attempt from that IP is challenged
- **AND** an `AbuseDetected` audit event records the IP and the username

#### Scenario: Distributed credential stuffing
- **WHEN** more than `ip_per_username_threshold` distinct IPs try one username inside the window
- **THEN** the next attempt against that username is challenged

#### Scenario: The reason stays private
- **WHEN** an attempt is challenged
- **THEN** the response does not reveal which dimension fired

### Requirement: A-4 Outbound email volume shield
The server SHALL track the distinct outbound email recipients of each realm in a rolling window, and SHALL abandon a send that exceeds the realm's hard cap. Recipient addresses SHALL be held only as `SipHash-1-3` hashes; plaintext recipient addresses SHALL NOT be retained in memory. The check SHALL run before the send, and before the A-50 cross-realm check. The check SHALL run in the off-request-path send job, so a refused send costs the caller exactly what an allowed one does and the caller's response does not reveal it.

| Key (`security.outbound_volume_shield.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Whether the shield runs |
| `window` | `3600s` | Rolling window length |
| `email_soft_cap` | `1000` | Distinct recipients before `SoftCap` |
| `email_hard_cap` | `5000` | Distinct recipients before `HardCap` |

| Outcome | Required caller action |
|---------|------------------------|
| `Allow` | Proceed with the send |
| `SoftCap` | Emit an `AbuseDetected` audit event and an A-7 security webhook; the send MAY proceed |
| `HardCap` | MUST abandon the send silently, with the caller's response unchanged; emit an `AbuseDetected` audit event |

When its lock is poisoned, the shield SHALL recover the lock and keep counting.

#### Scenario: A realm pumps email to many recipients
- **WHEN** a realm sends to more than `email_hard_cap` distinct recipients inside the window
- **THEN** the next message to a new recipient is not sent, and the response to the request that triggered it is the same as for a sent message
- **AND** an `AbuseDetected` audit event is written

#### Scenario: A realm crosses the soft cap
- **WHEN** a realm exceeds `email_soft_cap` but not `email_hard_cap`
- **THEN** the send proceeds, and an audit event and a security webhook are emitted

### Requirement: A-5 Reserved slugs and post-delete cooldown
The server SHALL reject a realm name or an organization slug that matches an entry of `security.reserved_slugs`, and SHALL reject a realm name or organization slug that was deleted within the cooldown window with `HEARTH_SLUG_IN_COOLDOWN`. The cooldown SHALL be 30 days (`security.slug_cooldown_days`, default `30`). Built-in URL-routing keywords SHALL always be reserved, whatever the list says. Expired cooldown entries SHALL be cleaned up automatically, with no operator action. The check SHALL fail closed: a match is always rejected.

#### Scenario: A reserved slug is requested
- **WHEN** an operator creates an organization with a slug listed in `security.reserved_slugs`
- **THEN** the create is rejected with `HEARTH_RESERVED_SLUG`

#### Scenario: A just-deleted slug is re-registered
- **WHEN** an organization is deleted and an organization with the same slug is created immediately after
- **THEN** the create is rejected with `HEARTH_SLUG_IN_COOLDOWN`

### Requirement: A-6 Bootstrap endpoint production guard
`POST /admin/bootstrap` and the `/dev/seed-*` routes SHALL be compiled only into a binary built with the `dev-endpoints` cargo feature. They SHALL be registered only when the server runs in dev mode (`--dev`), and SHALL answer only a loopback peer. Everywhere else the path SHALL answer `404`, so it cannot be fingerprinted. A `--dev` server built without the feature SHALL log that bootstrap is unavailable. There SHALL be no `hearth.yaml` key and no production override for this guard.

#### Scenario: Production server
- **WHEN** a server started without `--dev` receives `POST /admin/bootstrap`
- **THEN** it answers `404`

#### Scenario: Development server, loopback caller
- **WHEN** a `dev-endpoints` build started with `--dev` receives `POST /admin/bootstrap` from a loopback peer
- **THEN** the bootstrap runs and answers `200`

#### Scenario: Development server, remote caller
- **WHEN** the same server receives `POST /admin/bootstrap` from a non-loopback peer
- **THEN** it answers `404`

### Requirement: A-7 Security webhook channel
Operators SHALL be able to subscribe a webhook to the `security.*` event family, so security events fan out to a SIEM, a chat channel or a WAF without polling the audit log. Each matching audit event SHALL be signed with HMAC-SHA256 and POSTed to the endpoint with exponential-backoff retry. The `X-Hearth-Event` header SHALL carry the audit action's wire key (for example `login_failed`), not the dot-notation name; consumers SHOULD match on the wire key. The five event types SHALL appear in the admin UI webhook create and edit form under a **Security events** group.

| Event type | Audit action | Meaning |
|------------|--------------|---------|
| `security.login_failed` | `LoginFailed` | Credential verification failed |
| `security.account_locked` | `LoginLocked` | Account temporarily locked |
| `security.abuse_detected` | `AbuseDetected` | Abuse pattern detected by the A-3 detector |
| `security.password_compromised` | `PasswordCompromisedRejected` | Password rejected as known-compromised (HIBP) |
| `security.rate_limit_exceeded` | `IpLoginLimitExceeded` | Per-IP login rate limit hit |

#### Scenario: A failed login reaches a subscribed endpoint
- **WHEN** a webhook is subscribed to `security.login_failed` and a login fails
- **THEN** the endpoint receives a signed POST with `X-Hearth-Event: login_failed`

#### Scenario: The endpoint is down
- **WHEN** the endpoint fails a delivery
- **THEN** the delivery is retried with exponential backoff

### Requirement: A-8 Admin abuse dashboard
`GET /ui/admin/realms/{realm}/abuse` SHALL render a server-side security monitor with counters over a rolling 24-hour window and a table of the top 10 failing IPs. Events whose metadata carries an `"ip"` key SHALL be aggregated into the top-IP table. A query failure SHALL degrade to empty counters with status `200`, so an audit-engine outage never blocks operator access to the admin UI.

| Counter | Audit action |
|---------|--------------|
| Login failures | `LoginFailed` |
| Accounts locked | `LoginLocked` |
| Rate-limit hits | `IpLoginLimitExceeded` |
| Compromised-password rejections | `PasswordCompromisedRejected` |
| Abuse detections | `AbuseDetected` |

#### Scenario: An operator opens the page
- **WHEN** an operator opens the abuse page after a burst of failed logins
- **THEN** the login-failure counter and the top failing IPs reflect the last 24 hours

#### Scenario: The audit query fails
- **WHEN** the audit query behind the page fails
- **THEN** the page answers `200` with zero counters

### Requirement: A-9 Tenant CIDR allow and deny lists
Each realm SHALL be able to declare IPv4 and IPv6 CIDR `allow` and `deny` lists under `realms.<name>.security.cidr_policy`, and every public authentication request SHALL be checked against them. Evaluation SHALL be deny first, then allow: a source IP that matches any `deny` entry SHALL be refused, even when it is also inside the `allow` list; otherwise a non-empty `allow` list SHALL refuse every IP it does not contain; otherwise the request SHALL be allowed. When both lists are empty the realm SHALL have no network restriction (fail-open), so a missing policy never locks operators out.

#### Scenario: A deny exception inside an allowed range
- **WHEN** a realm allows `10.0.0.0/8` and denies `10.1.2.3/32`, and a login arrives from `10.1.2.3`
- **THEN** the login is refused

#### Scenario: Strict allowlist
- **WHEN** a realm allows only `10.0.0.0/8` and a login arrives from `203.0.113.5`
- **THEN** the login is refused

#### Scenario: No policy
- **WHEN** a realm declares no `cidr_policy`
- **THEN** logins from every address proceed to authentication

### Requirement: A-10 JWKS and discovery rate cap
The server SHALL cap requests per source IP to the key-discovery endpoints `GET /jwks`, `GET /certs`, `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration`, `GET /realms/{realm_name}/.well-known/jwks.json` and `GET /realms/{realm_name}/.well-known/openid-configuration`, and SHALL answer requests over the cap with `429 Too Many Requests` and `Retry-After: 1`. The cap SHALL be `security.jwks_rps_limit` requests per IP in a fixed one-second window, default `60`; `0` SHALL mean unlimited. A `--dev` server SHALL NOT apply the cap. The JWKS response SHALL carry `Cache-Control: max-age=3600, must-revalidate`.

#### Scenario: A client hammers JWKS
- **WHEN** one IP sends more than `security.jwks_rps_limit` JWKS requests in one second
- **THEN** the excess requests receive `429`

#### Scenario: Normal relying-party traffic
- **WHEN** an IP stays under the cap
- **THEN** every request receives the current key set

### Requirement: A-12 Adaptive lockout backoff
The server SHALL track consecutive lockouts per key and SHALL lengthen the lockout on each repeat offence. The offence counter SHALL reset to zero only after `offense_cooldown` (default 7 days) has passed since the end of the most recent lockout, so waiting out one lockout does not restore a clean slate. The schedule SHALL be configurable under `security.adaptive_backoff` (`durations`, `offense_cooldown`). `durations: []` SHALL disable adaptive backoff, leaving the flat per-account lockout active. The `POST /ui/device` guard SHALL key the backoff by realm and user, and SHALL lock a key after 5 wrong user codes.

| Offence | Lockout |
|:---:|---:|
| 1st | 1 minute |
| 2nd | 5 minutes |
| 3rd | 30 minutes |
| 4th and later | 24 hours |

#### Scenario: A repeat offender
- **WHEN** a key is locked out a second time inside the cooldown
- **THEN** the second lockout lasts 5 minutes

#### Scenario: A patient attacker
- **WHEN** a key waits exactly until its lockout ends and offends again
- **THEN** the next lockout is longer than the previous one

### Requirement: A-13 WebAuthn attestation policy
Each realm SHALL be able to restrict WebAuthn registration with `realms.<name>.auth.webauthn_attestation.{allow_none,aaguid_allowlist,require_prf,require_large_blob}`, and the policy SHALL be enforced at registration time. `allow_none` SHALL default to `true`. A non-empty `aaguid_allowlist` SHALL accept only authenticators whose AAGUID it lists. `require_prf` and `require_large_blob` SHALL require the matching extension. An authenticator that fails an active control SHALL receive `403 Forbidden` with `attestation_policy_violation`, and no credential SHALL be stored. An absent policy SHALL accept every authenticator.

#### Scenario: AAGUID not in the allowlist
- **WHEN** a realm sets an `aaguid_allowlist` and an authenticator with an unlisted AAGUID registers
- **THEN** the registration is refused and no credential is stored

#### Scenario: `none` attestation refused
- **WHEN** a realm sets `allow_none: false` and an authenticator presents the `"none"` attestation format
- **THEN** the registration is refused

### Requirement: A-14 Per-realm TTL hard caps
Configuration load SHALL refuse a realm whose `auth.token.password_reset_token_ttl` exceeds 1 hour or whose `auth.token.magic_link_ttl` exceeds 30 minutes, unless `auth.token.allow_unsafe_ttl: true` is also set. The keys SHALL apply per realm under `realms.<name>` and globally under `auth.token`.

#### Scenario: Unsafe reset TTL
- **WHEN** a realm sets `password_reset_token_ttl: 2h` without `allow_unsafe_ttl`
- **THEN** startup fails with a validation error naming the field

#### Scenario: Unsafe TTL accepted on opt-in
- **WHEN** the same realm also sets `allow_unsafe_ttl: true`
- **THEN** the configuration loads

### Requirement: A-16 CAPTCHA-of-last-resort challenge
The server SHALL count failed authentications per IP and SHALL put an IP into a challenge state for `challenge_ttl_secs` once `challenge_threshold` failures occur inside `window_secs`. An API caller in the challenge state SHALL receive HTTP `403` with `error_code: "HEARTH_ABUSE_CHALLENGE_REQUIRED"`, and that SHALL be the only error code and the only detail returned. A UI caller in the challenge state SHALL receive a login or registration page that carries the configured CAPTCHA widget at the `<!-- captcha-widget-slot -->` marker. A solved CAPTCHA, or expiry of the window, SHALL return the IP to `Allow`.

| Key (`security.captcha.*`) | Default | Meaning |
|-----|---------|---------|
| `provider` | none; required | CAPTCHA provider (`turnstile`); a `security.captcha` block without it does not parse |
| `challenge_threshold` | absent | Failures per window before a challenge; required to enable the store |
| `window_secs` | `60` | Window for counting failures |
| `challenge_ttl_secs` | `1800` | How long the challenge state lasts |

When `challenge_threshold` is absent the store SHALL be disabled and every check SHALL return `Allow` (fail-open).

#### Scenario: A hot IP keeps guessing
- **WHEN** an IP reaches `challenge_threshold` failed logins inside `window_secs`
- **THEN** its next API attempt receives `403` with `HEARTH_ABUSE_CHALLENGE_REQUIRED`
- **AND** its next UI attempt is shown the CAPTCHA widget

#### Scenario: The challenge is solved
- **WHEN** the IP solves the CAPTCHA
- **THEN** its state returns to `Allow`

### Requirement: A-18 Session lifecycle policy
A realm SHALL be able to set an idle timeout and an absolute timeout for sessions, and a session past either deadline SHALL be rejected on the read path. The keys SHALL be `auth.session_idle_timeout_secs` and `auth.session_absolute_timeout_secs` globally, with per-realm overrides `realms.<name>.session_idle_timeout_secs` and `realms.<name>.session_absolute_timeout_secs`; `null` (the default) SHALL disable each timeout. Concurrent sessions per user SHALL be capped by `auth.session_max_concurrent`, overridden per realm by `realms.<name>.session_max_concurrent`; absent at both levels means unlimited. `session_over_limit_policy` (global, per-realm override) SHALL decide what happens at the cap: `reject_new` (the default) refuses the new session, and `evict_oldest` evicts the user's oldest session. Any other value SHALL fail configuration parsing.

- Idle timeout: a session SHALL be rejected when `now ≥ last_refreshed_at + idle_timeout_secs`. Each `refresh_session()` SHALL reset it.
- Absolute timeout: a session SHALL be rejected when `now ≥ created_at + absolute_timeout_secs`. Refreshes SHALL NOT reset it.
- Both deadlines SHALL be embedded in the session record at creation, so the read path needs no realm-config lookup.

| Mechanism | Effect | Audit |
|-----------|--------|-------|
| Read-path rejection | The lookup returns no session (fail-closed) and drops it from the in-process cache; the caller answers `401` | None on the read path |
| Background eviction sweep | Marks the session revoked in storage and bumps the session version | `session_evicted` |
| `refresh_session()` on an expired session | Returns an error and writes nothing | None |

The `session_evicted` audit event SHALL be emitted only by the background sweep, with `reason` (`"idle_timeout"` or `"absolute_timeout"`), `session_id`, `user_id` and failure policy `LogOnly`. When neither timeout is configured, the existing TTL SHALL govern (fail-open). Removing a timeout from config SHALL NOT retroactively release existing sessions: a session keeps the deadlines embedded at its creation.

#### Scenario: An idle session
- **WHEN** a session is not refreshed for longer than `idle_timeout_secs`
- **THEN** token validation for it answers `401`
- **AND** the next background sweep writes a `session_evicted` event with `reason` `idle_timeout`

#### Scenario: An active session reaches the absolute cap
- **WHEN** a session is refreshed regularly but is older than `absolute_timeout_secs`
- **THEN** it is rejected

### Requirement: A-19 Email-change re-verification
The user email-change flow SHALL take effect only after the new address is verified with a separate token. An email change made by an operator or over SCIM SHALL take effect at once and SHALL set `email_verified = false`. Initiating a change SHALL validate and normalise the new address, check uniqueness and the A-20 reservation, generate a 32-byte cryptographically random token, store only `SHA-256(token)`, and emit an `EmailChangeInitiated` audit event; the caller delivers the token to the new address. Confirming SHALL enforce a 24-hour expiry and single use, swap the email indexes atomically, set `email_verified = true`, revoke all of the user's sessions, and emit an `EmailChangeConfirmed` audit event. `EmailChangeConfirmed` SHALL use failure policy `FailOperation`; the other audit writes SHALL use `LogOnly`.

| Error | Condition |
|-------|-----------|
| `EmailChangeTokenInvalid` (`HEARTH_EMAIL_CHANGE_TOKEN_INVALID`) | Token not found, expired, or already consumed |
| `DuplicateEmail` | New address already registered |
| `EmailReserved` | New address is under the A-20 cooldown |

#### Scenario: The change is confirmed
- **WHEN** a user confirms an email change with a valid token inside 24 hours
- **THEN** the new address is active and verified, and all of the user's sessions are revoked

#### Scenario: The token is replayed
- **WHEN** the same confirmation token is used a second time
- **THEN** the request fails with `HEARTH_EMAIL_CHANGE_TOKEN_INVALID`

### Requirement: A-20 Deleted-account email reservation
Deleting a user SHALL reserve the user's normalised email address in that realm for 90 days. Creating a user and initiating an email change SHALL refuse a reserved address with `EmailReserved`, whose wire code SHALL be `HEARTH_DUPLICATE_EMAIL`, the same as `DuplicateEmail`, so a caller cannot tell "address in use" from "address reserved". An expired reservation SHALL be removed and the operation SHALL proceed. Re-registration after the cooldown SHALL create a wholly new identity with a new `UserId`; no membership, invitation, session or credential SHALL be inherited from the deleted account.

#### Scenario: Re-registration inside the cooldown
- **WHEN** an account is deleted and the same address registers 10 days later
- **THEN** the registration fails with `HEARTH_DUPLICATE_EMAIL`

#### Scenario: Re-registration after the cooldown
- **WHEN** the same address registers 91 days later
- **THEN** a new user with a new `UserId` and no inherited memberships is created

### Requirement: A-21 JSON parse-bomb guard
Every `POST`, `PUT` and `PATCH` request with a `Content-Type` starting with `application/json` SHALL have its body scanned before any handler logic runs, and SHALL be rejected with HTTP `400 Bad Request` when its nesting depth exceeds `MAX_JSON_DEPTH` (128) or any array holds `MAX_JSON_ARRAY_LEN` (65 536) or more items. JSON bodies SHALL already be capped at 1 MiB (`DefaultBodyLimit`) before the scan. The scan SHALL be linear in the body size and SHALL NOT deserialize the body. Other content types and the `GET`, `HEAD`, `DELETE` and `OPTIONS` methods SHALL bypass the guard. The guard SHALL fail closed.

#### Scenario: Deeply nested JSON
- **WHEN** a JSON body nests deeper than 128 levels
- **THEN** the response is `400` and the error body names `depth`

#### Scenario: Nesting at the limit
- **WHEN** a JSON body nests exactly 128 levels
- **THEN** the guard passes it to the handler

#### Scenario: A huge flat array
- **WHEN** a JSON array holds 65 536 elements
- **THEN** the response is `400` and the error body names `array`

#### Scenario: Requests the guard ignores
- **WHEN** a `GET` request or a non-JSON body arrives
- **THEN** the guard does not inspect it

### Requirement: A-22 No inbound decompression
The server SHALL NOT decompress inbound request bodies: a body with `Content-Encoding: gzip` SHALL reach the handler as opaque bytes, so a decompression bomb cannot expand in-process. If inbound decompression is ever introduced, the decoded size SHALL be capped at 4 × the body limit and the stream SHALL be aborted on overrun.

#### Scenario: A gzip bomb is posted
- **WHEN** a client posts a gzip-encoded body that would expand to gigabytes
- **THEN** the server does not expand it

### Requirement: A-23 Pagination hard cap
Every offset-paginated list request SHALL have its page size clamped to [1, 200] (`MAX_PAGE_LIMIT`). The agent list SHALL refuse a page size above `MAX_PAGE_SIZE` (1 000) with an invalid-input error, before any storage scan. A SCIM list request SHALL materialise at most `SCIM_MAX_SCAN_LIMIT` (1 000) users or groups, whatever `count` it asks for.

#### Scenario: An oversized page is requested
- **WHEN** a caller asks a paginated list for 10 000 items in one page
- **THEN** at most 200 items are returned

#### Scenario: An oversized agent page
- **WHEN** a caller asks the agent list for 1 001 items in one page
- **THEN** the request is refused with an invalid-input error and no storage scan runs

### Requirement: A-24 Per-realm resource quotas
Each realm SHALL be able to cap its resources under `realms.<name>.quotas`; every limit SHALL default to unlimited. A create that would exceed a count-based limit SHALL be rejected with `HEARTH_QUOTA_EXCEEDED` (HTTP `429`) once `current >= limit`.

| Key | Resource | Enforcement |
|-----|----------|-------------|
| `max_users` | User records in the realm | On create, fail-closed |
| `max_orgs` | Organizations in the realm | On create, fail-closed |
| `max_clients` | Registered OAuth/OIDC clients | On create, fail-closed |
| `max_sessions` | Active sessions across all users | On create, fail-closed |
| `max_audit_rows` | Audit rows | Daily background pruner |
| `max_disk_bytes` | Disk usage | Sampled daily; warning only |

Count-based quotas SHALL be checked on every create by scanning the relevant storage prefix, and a scan error SHALL count as `current = limit`, so the create is rejected rather than bypassing the quota. `max_disk_bytes` SHALL be checked once per day by the background pruner and SHALL emit a warning but SHALL NOT block writes (fail-open); operators SHOULD pair it with OS-level disk quotas or alerting. `max_audit_rows` SHALL be enforced by the daily pruner after the `retention_days` sweep.

#### Scenario: The user quota is full
- **WHEN** a realm with `max_users: 10000` holds 10 000 users and another user is created
- **THEN** the create fails with `429` and `HEARTH_QUOTA_EXCEEDED`

#### Scenario: The storage scan fails
- **WHEN** the quota count cannot be read
- **THEN** the create is rejected

### Requirement: A-25 Audit auto-retention and row backstop
The daily audit pruner SHALL delete events older than the realm's `retention_days`, and SHALL then, when `count > max_rows`, delete the oldest `count - max_rows` events. The pruner SHALL log at `info` the realm, the number deleted and `max_rows` when it trims rows. Both settings SHALL be set through `PUT /ui/admin/api/realms/{realm}/audit/config` with the body fields `retention_days` and `max_rows`. `retention_days = 0` SHALL disable time-based pruning and `max_rows = null` SHALL disable the row backstop; both MAY be active together. Pruning breaks the hash chain for the removed window, so integrity verification SHOULD be run only against the retained window after a prune.

#### Scenario: An event storm overruns the backstop
- **WHEN** a realm with `max_rows: 500000` holds 600 000 audit events at the daily prune
- **THEN** the oldest 100 000 events are deleted

#### Scenario: The backstop is off
- **WHEN** `max_rows` is `null`
- **THEN** no row-count pruning happens

### Requirement: A-26 Metrics authentication and Server header suppression
When `metrics.bearer_token` is set, the `/metrics` endpoint SHALL require `Authorization: Bearer <token>`, compared in constant time, and SHALL answer a missing or wrong token with `401` and `WWW-Authenticate: Bearer`. When `metrics.bearer_token` is absent (the default) the endpoint SHALL be unauthenticated; operators who need authentication MUST set the field, and SHOULD otherwise firewall the endpoint or bind it to loopback. `metrics.enabled` SHALL default to `false`; while it is `false` the endpoint SHALL answer `404`, and `true` SHALL enable it. A middleware SHALL remove the `Server:` response header from every response, with no opt-out.

| Request (endpoint enabled) | `metrics.bearer_token` | Result |
|---------|------------------------|--------|
| No header | set | `401` + `WWW-Authenticate: Bearer` |
| Wrong token | set | `401` + `WWW-Authenticate: Bearer` |
| Correct token | set | `200` with the metrics body |
| Any | absent | `200` |

#### Scenario: Scrape without the token
- **WHEN** `metrics.bearer_token` is set and a scrape sends no `Authorization` header
- **THEN** the response is `401` with `WWW-Authenticate: Bearer`

#### Scenario: Fingerprinting
- **WHEN** an unauthenticated client requests any route
- **THEN** the response carries no `Server:` header

### Requirement: A-27 Tracing PII and token redaction
Every tracing field that can carry a credential or PII MUST be wrapped in the `Redact` wrapper at the macro call site, and both the `Display` and the `Debug` output of the wrapper SHALL be the literal `[REDACTED]`, so the value never reaches a log record, a span exporter or a SIEM. The fields below SHALL always be redacted.

| Field | Risk |
|-------|------|
| `reset_url` | One-shot password-reset token in the URL |
| `magic_link_url` | One-shot magic-link token in the URL |
| `password` | Plaintext credential |
| `token` | Opaque bearer token |
| `cookie` | Session cookie value |
| Raw email address | PII under GDPR / CCPA |

#### Scenario: A reset URL is logged without a mail transport
- **WHEN** no email transport is configured and the server logs a password-reset URL
- **THEN** the log record shows `[REDACTED]` in place of the URL

### Requirement: A-28 Atomic slug and invitation acquisition
Reserving an organization slug and accepting an invitation SHALL be atomic check-then-write operations, so two concurrent requests cannot both win the same slug and one invitation cannot be accepted twice. The primary record and the slug index SHALL be written in one WAL record. Invitation acceptance SHALL re-check the pending status inside the same critical section. A concurrent role assignment of the same (subject, role, scope) SHALL be idempotent. The loser of a slug race SHALL receive `409` with `HEARTH_ORG_DUPLICATE_SLUG`. A second acceptance of one invitation SHALL receive `400` with `HEARTH_INVITATION_INVALID`.

#### Scenario: Two requests race for one slug
- **WHEN** two requests create organizations with the same slug at the same time
- **THEN** exactly one succeeds and the other receives `409` with `HEARTH_ORG_DUPLICATE_SLUG`

#### Scenario: An invitation is double-spent
- **WHEN** two requests accept the same invitation at the same time
- **THEN** exactly one acceptance succeeds and the other receives `400` with `HEARTH_INVITATION_INVALID`

### Requirement: A-29 Federation hardening
Federated login SHALL defend against IdP mix-up, unverified-email account takeover and SAML signature wrapping.

- **Issuer parameter (RFC 9207 §2).** When the authorization server includes an `iss` query parameter on the callback, the server SHALL compare it with the connector's configured `issuer` before exchanging the code. A mismatch SHALL fail with `HEARTH_FEDERATION_IDP_MIXUP` (HTTP `400`). An absent `iss` SHALL be allowed.
- **Audience pinning.** An upstream ID token SHALL be accepted only when its `aud` contains the connector's client ID.
- **Unverified email.** Email-based account linking, in both `LinkMode::Auto` and `LinkMode::Confirm`, SHALL happen only when the upstream asserts `email_verified = true` and a non-empty email. Otherwise the flow SHALL fall through to just-in-time provisioning of a new account, never to a link with an existing local account.
- **SAML signature wrapping.** The `<ds:Reference URI>` inside `<ds:SignedInfo>` SHALL equal `#<ID>` of the located element, and the SHA-256 digest of the exc-C14N canonicalized element SHALL equal `<ds:DigestValue>`. Any discrepancy SHALL fail with one signature error that does not reveal which check failed.
- **SAML parse cap on the signature path.** Locating the signed element SHALL enforce the same `MAX_SAML_XML_EVENTS` (10 000) cap as response parsing.

| `LinkMode` | `email_verified = true` | `email_verified = false` |
|------------|------------------------|--------------------------|
| `Disabled` | JIT only, no linking | JIT only, no linking |
| `Confirm` | Prompt the user to confirm | JIT only |
| `Auto` | Silent link | JIT only |

#### Scenario: IdP mix-up
- **WHEN** a callback carries an `iss` that differs from the connector's issuer
- **THEN** the login fails with `HEARTH_FEDERATION_IDP_MIXUP` and the code is not exchanged

#### Scenario: Unverified email matches a local account
- **WHEN** an upstream IdP asserts `email_verified: false` with the email of an existing local user, under `LinkMode::Auto`
- **THEN** a new account is provisioned and the existing account is not linked

#### Scenario: Wrong reference URI
- **WHEN** a SAML signature's reference URI names a different element than the one located
- **THEN** the response is rejected with a generic signature error

### Requirement: A-30 Backup and export hardening
Every data-export endpoint (`POST /admin/backup`, `GET /admin/users/export`, `GET /admin/realms/{r}/audit/export`) and `POST /admin/backup/restore` SHALL require the caller's token to carry `hearth.export` in addition to an admin permission (`hearth.admin`, or the sub-admin permission the endpoint accepts). A missing permission SHALL answer `403 Forbidden`.

- **Restore and system-wide backup.** Every backup restore, and every backup export by a system-realm caller, SHALL require `hearth.admin` itself; a sub-admin holding `hearth.export` SHALL receive `403`.
- **Seeding.** `hearth.export` SHALL be seeded in every realm and included in the `realm.admin` role by default.
- **Rate limit.** Exports SHALL be limited to 10 per user per hour (`security.backup.export_rate_limit`), counted per user and not per IP. Over the limit the response SHALL be `429 Too Many Requests`. The permission checks SHALL run first, so a refused caller sees `403`, never `429`, and spends no quota.
- **Restore signature.** A backup manifest SHALL carry `detached_signature_b64`, a base64url Ed25519 signature over the manifest's canonical bytes (the manifest JSON with that field set to `null`). `security.backup.verify_key` SHALL hold the base64url-encoded 32-byte Ed25519 public key. A refused restore over HTTP SHALL answer `400` with `error` = `missing_manifest_signature` or `invalid_manifest_signature`, and the CLI SHALL exit `2`. Nothing SHALL override a configured key, and the CLI SHALL refuse `--skip-verify` alongside one. When no key is configured, restore SHALL be refused outside dev mode with `error` = `backup_verify_key_not_configured` over HTTP; the HTTP route SHALL have no override, the CLI SHALL accept `--allow-unsigned` as an explicit opt-in, and a `--dev` server SHALL restore with a warning. Both restore paths SHALL import from one private, unlinked copy of the archive, so the bytes imported are the bytes verified. `hearth backup create --sign-key <key.pem>` and `hearth backup sign` SHALL sign the canonical bytes, and `hearth backup keygen` SHALL generate a signing key.
- **Watermark.** Every export call, whatever its outcome, SHALL emit a `RealmExportWatermarked` audit event before any export data is produced, with `action` `realm_export_watermarked`, `resource_type` `export`, `resource_id` a unique export UUID, `metadata.export_id` the same UUID, `metadata.export_type` `backup`, `users` or `audit`, and `metadata.realm_slug` when a realm filter was applied.

| Control | Failure mode |
|---------|--------------|
| `hearth.export` permission check | Fail-closed (`403`) |
| Per-export rate limit | Fail-closed (`429`) |
| Restore signature verification | Fail-closed (`400`) |
| Watermark emit failure | Fail-open (logged only) |

#### Scenario: A token without the export permission
- **WHEN** a token with `hearth.admin` but without `hearth.export` calls `POST /admin/backup`
- **THEN** the response is `403` and no export quota is spent

#### Scenario: The eleventh export in an hour
- **WHEN** one user makes an eleventh export inside one hour
- **THEN** the response is `429`

#### Scenario: Unsigned archive with a configured key
- **WHEN** `security.backup.verify_key` is set and an archive without a signature is restored over HTTP
- **THEN** the response is `400` with `error` = `missing_manifest_signature`

### Requirement: A-31 Federation JWT leeway
The clock-skew leeway applied to an upstream OIDC ID token's `exp` and `nbf` SHALL be configurable per identity provider as `federation.<idp>.leeway_seconds`, SHALL default to 60 seconds, and SHALL be capped at 300 seconds: a larger configured value SHALL be clamped to 300.

#### Scenario: Default leeway
- **WHEN** an upstream ID token expired 61 seconds ago and the connector sets no leeway
- **THEN** the token is rejected

#### Scenario: Wider leeway for a drifting IdP
- **WHEN** a connector sets `leeway_seconds: 120` and the token expired 120 seconds ago
- **THEN** the token is accepted

#### Scenario: Leeway above the ceiling
- **WHEN** a connector sets `leeway_seconds: 600` and the token expired 301 seconds ago
- **THEN** the token is rejected, because the effective leeway is 300 seconds

### Requirement: A-32 Trusted proxy validation
Startup SHALL refuse a `server.trusted_proxies` entry that does not parse, that is the unspecified address or a catch-all (`0.0.0.0`, `::`, `0.0.0.0/0`, `::/0`), that has host bits set in a range, or that is an IPv4 range broader than `/8` or an IPv6 range broader than `/16`. Startup SHALL also refuse a loopback entry when the server binds a public listener. A single public address or a narrower public range SHALL be accepted.

#### Scenario: A catch-all proxy entry
- **WHEN** `server.trusted_proxies` contains `0.0.0.0/0`
- **THEN** the server refuses to start and names the entry

#### Scenario: A range that is too broad
- **WHEN** `server.trusted_proxies` contains `64.0.0.0/4`
- **THEN** the server refuses to start and names the entry

#### Scenario: Loopback proxy on a public bind
- **WHEN** the server binds `0.0.0.0` and `server.trusted_proxies` lists `127.0.0.1`
- **THEN** configuration validation reports the entry

### Requirement: A-33 Bounded realm-delete cascade
Deleting a realm SHALL first mark the realm `DeletingInProgress` in storage and in the hot-path status cache, so new authentication operations are blocked at once. The cascade SHALL run in chunks of `cascade_chunk_size` keys (default 200). When the realm holds more than `cascade_background_threshold` items (default 1000), the cascade SHALL run as a background task and the HTTP response SHALL return immediately. The admin dashboard SHALL show the realm in a "Deleting" state while the cascade runs. Both settings SHALL be engine-level defaults, not per-realm keys. A crash SHALL leave the realm `DeletingInProgress`.

#### Scenario: A large realm is deleted
- **WHEN** an operator deletes a realm holding 50 000 items
- **THEN** the delete request returns immediately, the realm shows "Deleting", and authentication against it is refused

### Requirement: A-34 Consent page framing and ticket realm binding
`/oauth/consent` SHALL be served with `frame-ancestors 'none'`. A consent ticket SHALL carry the `realm_id` it was issued in, and SHALL be rejected when presented in a different realm.

#### Scenario: Cross-realm consent ticket
- **WHEN** a consent ticket issued in realm A is submitted from a session in realm B
- **THEN** the consent is refused

#### Scenario: Clickjacking
- **WHEN** a third-party page tries to frame `/oauth/consent`
- **THEN** the browser refuses because of `frame-ancestors 'none'`

### Requirement: A-35 SCIM and SAML payload caps
A SCIM PATCH for a user or a group SHALL be rejected with HTTP `413 Payload Too Large` when `Operations` holds more than `MAX_SCIM_OPERATIONS` (1 000) entries, before any patch logic runs. SAML response parsing SHALL stop with a parse error after `MAX_SAML_XML_EVENTS` (10 000) XML events, and SHALL NOT expand entities. Both caps SHALL fail closed.

#### Scenario: A PATCH with too many operations
- **WHEN** a SCIM client sends a PATCH with 1 001 operations
- **THEN** the response is `413` and nothing is changed

#### Scenario: An element flood
- **WHEN** an Assertion Consumer Service receives a response with 50 000 elements and no DTD
- **THEN** parsing stops and the response is rejected

### Requirement: A-36 Agent-auth partial-implementation guardrail
The server SHALL refuse to start, with an explicit error, when configuration enables an agent-auth feature that the build does not fully implement.

#### Scenario: An unimplemented agent-auth feature is enabled
- **WHEN** `hearth.yaml` enables an agent-auth capability that the build does not implement
- **THEN** startup fails with an error naming the capability

### Requirement: A-37 Silent-authentication probe limit
Every `prompt=none` authorization request for an authenticated subject SHALL increment a per-(realm, subject) counter. The window SHALL be 1 hour and the cap 50 probes; the counter SHALL be WAL-persisted. Probes 1 to 50 SHALL proceed normally. From probe 51 the server SHALL answer `error=login_required` (OIDC Core §3.1.2.6). Every probe, whatever its outcome, SHALL emit an `OidcSilentAuthProbed` audit event with `user_id`, `client_id`, `outcome` and `probe_count`. The window SHALL start at the first probe, and the counter SHALL reset to zero when the window expires. Counters SHALL NOT be shared across realms. The audit write SHALL be `LogOnly`, and a failed counter write SHALL NOT block the flow (fail-open).

#### Scenario: A session-existence oracle
- **WHEN** a client sends a 51st `prompt=none` request for one subject inside one hour
- **THEN** the response is `error=login_required`, whatever the subject's session state

#### Scenario: The window resets
- **WHEN** an hour passes after the first probe
- **THEN** the next probe starts a new window and proceeds normally

### Requirement: A-38 Delegation-chain depth cap
Token validation SHALL reject a token whose RFC 8693 `act` delegation chain is deeper than `MAX_ACT_CHAIN_DEPTH` (3) with an invalid-token error (fail-closed). Depth SHALL count the outer actor as 1 and each nested `act` as one more, and the traversal SHALL be iterative and stop once the cap is passed.

| `act` claim | Depth | Result |
|-------------|-------|--------|
| `{ "sub": "x" }` | 1 | accepted |
| `{ "sub": "x", "act": { "sub": "y" } }` | 2 | accepted |
| Three-level chain | 3 | accepted |
| Four-level chain | 4 | rejected |

#### Scenario: An over-deep chain
- **WHEN** a token carries a four-level `act` chain
- **THEN** validation fails with an invalid-token error

### Requirement: A-39 HTTP/2 rapid-reset defense
The HTTP/2 server SHALL cap concurrent streams per connection and SHALL bound the pending `RST_STREAM` budget per connection, dropping the connection on overrun (CVE-2023-44487). The caps SHALL be configured under `security.http2.*`: `max_concurrent_streams` (default 100) and `max_pending_reset_streams` (default 10).

#### Scenario: Rapid reset
- **WHEN** a client opens and resets streams faster than the reset budget allows
- **THEN** the server closes the connection

### Requirement: A-40 Host allowlist and cross-origin isolation
The server SHALL reject a request whose `Host` header is not in `security.allowed_hosts` with `400 Bad Request`; the default SHALL be the listener's bind hostnames. UI responses SHALL carry `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, and a `Permissions-Policy` that denies sensors and payment by default.

#### Scenario: DNS rebinding
- **WHEN** `security.allowed_hosts` is set and a request arrives with a `Host` outside it
- **THEN** the response is `400`

#### Scenario: UI security headers
- **WHEN** a browser loads a `/ui` page
- **THEN** the response carries COOP `same-origin`, COEP `require-corp` and a `Permissions-Policy` header

### Requirement: A-41 Session-id rotation on authentication
On a successful primary authentication, MFA step-up, federation link, password change or admin impersonation, the server SHALL destroy the current session record, mint a session with a fresh ID, and invalidate the old cookie.

#### Scenario: A pre-planted cookie
- **WHEN** an attacker plants a session cookie in a victim's browser and the victim then signs in
- **THEN** the planted session is revoked and does not survive the login

### Requirement: A-42 Mass revocation on sensitive mutations
`change_password`, `set_password`, an email change and MFA disablement SHALL revoke all of the user's sessions and refresh-token families. The caller MAY keep the active session with a `keep_current = true` opt-in. The revocation SHALL emit a `security.sessions_revoked` audit event and webhook.

#### Scenario: Password rotation after a phish
- **WHEN** a user changes their password while an attacker holds another session
- **THEN** the attacker's session and refresh tokens stop working

#### Scenario: A non-sensitive profile edit
- **WHEN** a user changes only their display name
- **THEN** no session is revoked

### Requirement: A-44 TLS 0-RTT off and mTLS CRL revocation
TLS 1.3 0-RTT early data SHALL be disabled. The server SHALL assert `max_early_data_size = 0` at startup and SHALL panic at boot if a library upgrade changes that default. There SHALL be no configuration knob to enable 0-RTT. `security.tls.crl_paths` SHALL accept a list of PEM-encoded CRL files. When it is set, every client certificate SHALL be checked against the union of the CRLs, a revoked certificate SHALL be rejected with a TLS handshake alert before any application data is exchanged, and the CRLs SHALL be reloaded on `SIGHUP` with the server certificate. A missing, unreadable or malformed CRL file SHALL make startup fail. A certificate absent from every CRL SHALL be treated as not revoked. An empty `crl_paths` (the default) SHALL perform no revocation check.

#### Scenario: A revoked admin client certificate
- **WHEN** `crl_paths` lists a CRL that revokes a client certificate and that client connects
- **THEN** the TLS handshake fails

#### Scenario: A broken CRL file
- **WHEN** a path in `crl_paths` does not exist
- **THEN** the server refuses to start

### Requirement: A-45 Tenant-controlled HTML, CSS and SVG sanitization
All operator- or tenant-supplied content that reaches an unescaped render path SHALL pass through a sanitizer before reaching a template.

- **SVG (`logo_svg_inline`).** The sanitizer SHALL run upstream of every template render. It SHALL strip `<script>` and `<foreignObject>` with their subtrees, `<iframe>`, `<object>` and `<embed>`, every attribute starting with `on`, every `href` or `xlink:href` not starting with `#`, and every `style` attribute containing `expression(`, `javascript:`, `behavior:` or `-moz-binding`. It SHALL keep every other element and attribute, including `viewBox`, `fill`, `stroke`, `d`, `cx`, `cy`, `r`, `class`, `id` and CSS custom properties. Input that cannot be parsed SHALL yield the empty string (fail-closed).
- **CSS (`custom_css`).** Operator- and realm-level `custom_css` SHALL be sanitized before it is concatenated into the served theme CSS. The sanitizer SHALL drop, case-insensitively, every line containing `expression(`, `javascript:`, `behavior:`, `-moz-binding`, `url(data:`, `url(javascript:`, `-ms-filter` or `progid:`, and every `@import` rule. It SHALL keep every other declaration and at-rule, including `@media`, `@keyframes`, `:root {}` blocks and `--ht-*` custom properties, and SHALL return the rest of the file unchanged (fail-open per line).
- **HTML.** A future tenant-supplied HTML body field MUST pass an allowlist sanitizer before rendering. Disk template overrides (`email.templates_dir`) are operator-controlled and are not sanitized.

#### Scenario: A script in an SVG logo
- **WHEN** a logo SVG contains `<script>` and an `onload` attribute
- **THEN** the rendered email contains neither

#### Scenario: An unparseable SVG
- **WHEN** a logo SVG cannot be parsed
- **THEN** the logo renders as nothing

#### Scenario: A dangerous CSS line
- **WHEN** `custom_css` contains `@import url(https://evil.example/x.css);` and a harmless `:root { --ht-accent: red; }`
- **THEN** the served theme CSS keeps the `:root` block and drops the `@import`

### Requirement: A-46 Argon2 pepper rotation
Each peppered credential SHALL record the `pepper_version` it was hashed with. The active pepper SHALL be configured as `security.password.pepper.version` and `security.password.pepper.key_hex`, and a superseded pepper MAY be kept valid during a grace window with `previous_version` and `previous_key_hex`. A credential hashed with the previous pepper SHALL verify during the grace window and SHALL be re-hashed with the active pepper on the next successful login. A credential whose pepper version is neither active nor previous SHALL fail verification. `hearth migrate rotate-pepper` SHALL report the credentials still pending rotation, which are rewritten lazily on the next successful login.

#### Scenario: Login during the grace window
- **WHEN** a user whose credential carries the previous pepper version signs in with the right password
- **THEN** the login succeeds and the credential is re-hashed with the active pepper

#### Scenario: The grace window is closed
- **WHEN** the previous pepper is removed from config and a credential still carries its version
- **THEN** verification fails

### Requirement: A-47 Unknown fields refused on request bodies
Every request-body shape of the admin and authentication APIs SHALL refuse unknown fields, unless a documented forward-compatibility exception is recorded for that shape.

#### Scenario: An extension field slips into an admin body
- **WHEN** an admin request body carries a field its shape does not declare
- **THEN** the request is refused rather than the field being silently dropped

### Requirement: A-48 Federation state bound to the browser
Starting a federated login SHALL bind the opaque `state` to the starting browser, and the callback SHALL refuse a `state` presented without that binding (fail-closed, no fallback). At start the server SHALL draw a random 256-bit `state` token, compute `HMAC-SHA256(cookie_secret, "fed-state-bind|" || state_token)`, and set it in a `hearth_fed_bind` cookie with `HttpOnly; Path=/; Max-Age=600` and a `SameSite` value chosen by how the IdP returns. A connector whose callback arrives as a cross-site `form_post` SHALL get `SameSite=None; Secure`, because a `Lax` cookie is not sent on a cross-site POST. Any other connector SHALL get `SameSite=Lax; Secure` on a secure request and `SameSite=Lax` otherwise, because its callback is a top-level cross-origin navigation. The cookie SHALL carry only the MAC tag, never the `state` value. The HMAC key SHALL be the server-wide 32-byte `cookie_secret`, and the `"fed-state-bind|"` prefix SHALL separate this MAC from every other cookie MAC. The callback SHALL compare the MAC in constant time, and a missing or wrong cookie SHALL redirect with `303` to `/ui/login?error=federation_failed`. The upstream redirect SHALL complete within the 10-minute cookie lifetime.

#### Scenario: The callback arrives without the cookie
- **WHEN** a browser that did not start the flow calls the callback with a valid `state` and code
- **THEN** it is redirected to `/ui/login?error=federation_failed` and no session is created

#### Scenario: A cookie from another flow
- **WHEN** the callback carries a `hearth_fed_bind` cookie computed for a different `state`
- **THEN** the callback is refused

#### Scenario: A forged MAC
- **WHEN** the cookie carries a MAC computed with a different secret
- **THEN** the callback is refused

### Requirement: A-50 Cross-realm email aggregation cap
The server SHALL count, across the whole cluster and in a rolling window, the distinct realms that send to each recipient, so an attacker who splits sends across many realms to stay under the A-4 per-realm budget is caught. The check SHALL run in addition to the A-4 check and after it; both SHALL pass before a send proceeds. Recipient addresses and realm IDs SHALL be held only as `SipHash-1-3` hashes. Callers MUST NOT surface `realm_count` to the sending realm or to any external client.

| Key (`security.cross_realm_aggregation_cap.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Whether the cap runs |
| `window` | `3600s` | Rolling window length |
| `alert_threshold` | `3` | Distinct realms before an operator alert |
| `email_realm_soft_cap` | `5` | Distinct realms before `SoftCap` |
| `email_realm_hard_cap` | `10` | Distinct realms before `HardCap` |

| Outcome | Fires at | Required caller action |
|---------|----------|------------------------|
| `MultiRealmAlert` | more than `alert_threshold` realms | Emit an `AbuseDetected` audit event and an A-7 webhook; the send MAY proceed |
| `SoftCap` | more than `email_realm_soft_cap` realms | The send proceeds; SHOULD emit the audit event and webhook |
| `HardCap` | more than `email_realm_hard_cap` realms | MUST abandon the send silently, with the caller's response unchanged; MUST emit the audit event and webhook |

The check SHALL run in the off-request-path send job, like the A-4 check. Setting every threshold to `usize::MAX` SHALL disable the cap. When its lock is poisoned, the cap SHALL recover the lock and keep counting.

#### Scenario: One victim, many realms
- **WHEN** eleven distinct realms send to `victim@example.com` inside the window, each under its own A-4 budget
- **THEN** the eleventh message is not sent, the response to the request that triggered it is unchanged, and an audit event and webhook are emitted

#### Scenario: The count stays private
- **WHEN** a send is refused by the cap
- **THEN** the response does not reveal how many realms targeted the recipient

### Requirement: A-52 return_to redirect allowlist
In the federation and SAML flows, every `return_to` value, every URL embedded in `RelayState`, and `bag.return_to` MUST pass through the `validate_return_to` helper before it is used as a redirect target. The helper SHALL reject an empty value, a value containing a newline, a carriage return or a NUL, a scheme-relative value (`//evil`), a backslash-relative value (`\evil`), a `data:` or `javascript:` URL, and an absolute URL whose `scheme://host[:port]` is not listed in `security.allowed_return_to_origins`. Absolute paths (`/ui/…`) SHALL be accepted. The UI login flows SHALL use a stricter helper that accepts a `return_to` only when it is `/ui` or starts with `/ui/`, is not scheme-relative, and contains no newline or carriage return.

#### Scenario: Scheme-relative redirect
- **WHEN** a federation login starts with `return_to=//evil.com`
- **THEN** the value is discarded and the user is not redirected off-origin

#### Scenario: An allowed origin
- **WHEN** `security.allowed_return_to_origins` lists `https://app.example.com` and `return_to` is `https://app.example.com/home`
- **THEN** the redirect goes to that URL

#### Scenario: A UI login names a path outside the UI
- **WHEN** a UI login carries `return_to=/admin/users`
- **THEN** the value is discarded and the user lands on the default UI page

### Requirement: P-1 CAPTCHA provider with a Turnstile adapter
Public authentication forms SHALL support a pluggable CAPTCHA provider, with Cloudflare Turnstile as the reference adapter. When a provider is configured, the widget SHALL be injected at the `<!-- captcha-widget-slot -->` marker of the registration form and the forgot-password form, and the server SHALL verify the response token against the provider's siteverify API before it processes the form. The provider SHALL be consulted off the hot path.

| Condition | Outcome |
|-----------|---------|
| Empty token | Fail-closed: the form is refused |
| Transport or provider error | Fail-open: the form proceeds, and a `warn` is logged |
| No provider configured | The no-op provider passes every check |

The provider SHALL be configured under `security.captcha` with `provider: turnstile`, `turnstile.site_key` and `turnstile.secret_key`; operators SHOULD supply the secret through `HEARTH_TURNSTILE_SECRET_KEY` rather than the file.

#### Scenario: A bot skips the widget
- **WHEN** Turnstile is configured and a registration is submitted with an empty CAPTCHA token
- **THEN** the registration is refused

#### Scenario: Cloudflare is unreachable
- **WHEN** the siteverify call fails at the transport level
- **THEN** the form proceeds and a warning is logged

### Requirement: Baseline login, token and admin rate limits
The server SHALL limit failed logins per source IP in a sliding window, SHALL lock an account after consecutive failed logins, SHALL limit token-endpoint requests per `(realm, client)` pair with `429` and `Retry-After`, and SHALL limit admin-API requests per admin user. The limits SHALL be configured under `security.rate_limiting`: `login_per_ip.max_attempts` (default 10) in `login_per_ip.window_seconds` (default 60); `login_per_account.max_failures` (default 5) with `login_per_account.lockout_seconds` (default 300); `token_per_minute` (default 200); `admin_per_minute` (default 100). Magic-link requests SHALL be limited per IP and per account, and SHALL answer `202` whether or not the address exists. TOTP verification SHALL lock after 5 failed attempts in 5 minutes. Every `429` from these limiters SHALL carry a `limiter` field naming its source.

#### Scenario: Sustained credential guessing
- **WHEN** one IP keeps submitting wrong passwords past `login_per_ip.max_attempts`
- **THEN** further attempts from that IP are refused before the password is checked

#### Scenario: Excessive magic-link requests
- **WHEN** a client keeps requesting magic links for the same email
- **THEN** further requests are throttled, and the response does not reveal whether the address exists

#### Scenario: Excessive admin requests
- **WHEN** one admin sends more than `admin_per_minute` admin-API requests in a minute
- **THEN** the excess requests receive `429` with `limiter` `admin`

### Requirement: Every abuse guard identifier has an adversarial test
CI SHALL extract every `A-<number>` identifier from this capability and SHALL fail when an identifier appears in no `tests/abuse_*.rs` file. Each test file SHALL reference the identifier in a test name or a comment. A new identifier SHALL take the next unused number, and its adversarial test SHALL land before or with the requirement. Setting `SKIP_ABUSE_COVERAGE_CHECK=1` SHALL bypass the gate, and the bypass SHALL be logged visibly in CI output.

#### Scenario: A guard without a test
- **WHEN** a requirement for a new guard is added and no `tests/abuse_*.rs` file cites its identifier
- **THEN** the CI gate fails and names the identifier

#### Scenario: The escape hatch
- **WHEN** `SKIP_ABUSE_COVERAGE_CHECK=1` is set
- **THEN** the gate passes and prints a visible warning
