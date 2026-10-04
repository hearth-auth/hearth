## MODIFIED Requirements

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

#### Scenario: The configured backoff schedule is used
- **WHEN** `security.adaptive_backoff.durations` is `["2m"]` and a key is locked out on `POST /ui/device`
- **THEN** the lockout lasts 2 minutes, not the compiled 1-minute default

### Requirement: A-13 WebAuthn attestation policy
Each realm SHALL be able to restrict WebAuthn registration with `realms.<name>.auth.webauthn_attestation.{allow_none,aaguid_allowlist,require_prf,require_large_blob}`, and the policy SHALL be enforced at registration time. `allow_none` SHALL default to `true`. A non-empty `aaguid_allowlist` SHALL accept only authenticators whose AAGUID it lists. `require_prf` and `require_large_blob` SHALL require the matching extension. An authenticator that fails an active control SHALL receive `403 Forbidden` with `attestation_policy_violation`, and no credential SHALL be stored. An absent policy SHALL accept every authenticator.

#### Scenario: AAGUID not in the allowlist
- **WHEN** a realm sets an `aaguid_allowlist` and an authenticator with an unlisted AAGUID registers
- **THEN** the registration is refused and no credential is stored

#### Scenario: `none` attestation refused
- **WHEN** a realm sets `allow_none: false` and an authenticator presents the `"none"` attestation format
- **THEN** the registration is refused

#### Scenario: PRF is required when `require_prf` is set
- **WHEN** a realm sets `require_prf: true` and an authenticator reports the largeBlob extension but not PRF
- **THEN** the registration is refused and no credential is stored

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

#### Scenario: The session timeout keys load
- **WHEN** `hearth.yaml` sets `auth.session_idle_timeout_secs: 3600`
- **THEN** the server starts
- **AND** a session left idle for more than an hour is rejected

### Requirement: A-20 Deleted-account email reservation
Deleting a user SHALL reserve the user's normalised email address in that realm for 90 days. Creating a user and initiating an email change SHALL refuse a reserved address with `EmailReserved`, whose wire code SHALL be `HEARTH_DUPLICATE_EMAIL`, the same as `DuplicateEmail`, so a caller cannot tell "address in use" from "address reserved". An expired reservation SHALL be removed and the operation SHALL proceed. Re-registration after the cooldown SHALL create a wholly new identity with a new `UserId`; no membership, invitation, session or credential SHALL be inherited from the deleted account.

#### Scenario: Re-registration inside the cooldown
- **WHEN** an account is deleted and the same address registers 10 days later
- **THEN** the registration fails with `HEARTH_DUPLICATE_EMAIL`

#### Scenario: Re-registration after the cooldown
- **WHEN** the same address registers 91 days later
- **THEN** a new user with a new `UserId` and no inherited memberships is created

#### Scenario: Reserved and in-use emails answer the same body
- **WHEN** one user create hits a reserved address and another hits an address in use
- **THEN** both responses have the same status and a byte-identical body

### Requirement: A-40 Host allowlist and cross-origin isolation
The server SHALL reject a request whose `Host` header is not in `security.allowed_hosts` with `400 Bad Request`. When `security.allowed_hosts` is not set, the list SHALL default to the host of `oidc.issuer`; under `--dev` a loopback `Host` SHALL also be admitted. The comparison SHALL ignore the port. The liveness and readiness probes (`/healthz`, `/readyz`) SHALL be exempt from the check; every other route, including `/health` and `/metrics`, SHALL NOT be exempt. UI responses SHALL carry `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, and a `Permissions-Policy` that denies sensors and payment by default.

#### Scenario: DNS rebinding
- **WHEN** `security.allowed_hosts` is set and a request arrives with a `Host` outside it
- **THEN** the response is `400`

#### Scenario: UI security headers
- **WHEN** a browser loads a `/ui` page
- **THEN** the response carries COOP `same-origin`, COEP `require-corp` and a `Permissions-Policy` header

#### Scenario: An unset host allowlist accepts only the issuer host
- **WHEN** `security.allowed_hosts` is not set, `oidc.issuer` is `https://hearth.example.com`, and a request arrives with `Host: evil.example`
- **THEN** the response is `400`
- **AND** a request with `Host: hearth.example.com:443` is admitted

#### Scenario: Probes skip the host check
- **WHEN** `security.allowed_hosts` is not set and a request for `/readyz` arrives with `Host: 10.0.0.7:8420`
- **THEN** the request is admitted
- **AND** the same request for `/metrics` is answered `400`

### Requirement: A-41 Session-id rotation on authentication
On a successful primary authentication, MFA step-up, federation link, password change or admin impersonation, the server SHALL destroy the current session record, mint a session with a fresh ID, and invalidate the old cookie.

#### Scenario: A pre-planted cookie
- **WHEN** an attacker plants a session cookie in a victim's browser and the victim then signs in
- **THEN** the planted session is revoked and does not survive the login

#### Scenario: Federation login rotates the session
- **WHEN** a browser holding a session cookie completes a federated login
- **THEN** the earlier session is revoked
- **AND** the browser receives a session with a new ID

### Requirement: A-44 TLS 0-RTT off and mTLS CRL revocation
TLS 1.3 0-RTT early data SHALL be disabled. The server SHALL assert `max_early_data_size = 0` at startup and SHALL panic at boot if a library upgrade changes that default. There SHALL be no configuration knob to enable 0-RTT. `security.tls.crl_paths` SHALL accept a list of PEM-encoded CRL files. When it is set, every client certificate SHALL be checked against the union of the CRLs, a revoked certificate SHALL be rejected with a TLS handshake alert before any application data is exchanged, and the CRLs SHALL be reloaded on `SIGHUP` with the server certificate. A missing, unreadable or malformed CRL file SHALL make startup fail. A certificate absent from every CRL SHALL be treated as not revoked. An empty `crl_paths` (the default) SHALL perform no revocation check.

#### Scenario: A revoked admin client certificate
- **WHEN** `crl_paths` lists a CRL that revokes a client certificate and that client connects
- **THEN** the TLS handshake fails

#### Scenario: A broken CRL file
- **WHEN** a path in `crl_paths` does not exist
- **THEN** the server refuses to start

#### Scenario: SIGHUP reloads the CRLs
- **WHEN** an operator adds a client certificate to a CRL file listed in `crl_paths` and sends `SIGHUP`
- **THEN** the next TLS handshake with that certificate fails

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

#### Scenario: Render paths sanitize SVG and CSS
- **WHEN** a configured logo SVG contains `<script>`, and a configured `custom_css` contains an `@import` rule
- **THEN** the outgoing email contains no `<script>`
- **AND** the served theme CSS contains no `@import`

### Requirement: A-47 Unknown fields refused on request bodies
Every request-body shape of the admin and authentication APIs SHALL refuse unknown fields, unless a documented forward-compatibility exception is recorded for that shape. The OAuth 2.0 and OIDC protocol endpoints (token, pushed authorization, revocation, introspection, authorization and device authorization) are the recorded exceptions: RFC 6749 §3.1 and §3.2 require the server to ignore an unrecognized parameter.

#### Scenario: An extension field slips into an admin body
- **WHEN** an admin request body carries a field its shape does not declare
- **THEN** the request is refused rather than the field being silently dropped

#### Scenario: A client update refuses unknown fields
- **WHEN** a `PATCH /admin/applications/{id}` body carries a field its shape does not declare
- **THEN** the request is refused

#### Scenario: A protocol endpoint ignores an unknown parameter
- **WHEN** a token request carries a parameter the token endpoint does not define
- **THEN** the parameter is ignored and the request is processed
