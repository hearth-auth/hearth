# Abuse Prevention — Sanitization Contract

This document records the security contract for implemented abuse-prevention
features. See `docs/plans/HEA-1114-abuse-prevention.md` for the full
phase-by-phase threat model.

---

## P-1 — `CaptchaProvider`: Cloudflare Turnstile Reference Adapter

**Status:** Shipped (HEA-1202)  
**Module:** `src/abuse/captcha/` → `TurnstileCaptchaProvider`; trait lives in `src/abuse/challenge.rs`

### What it provides

Pluggable CAPTCHA verification for public auth forms. When configured, the
Turnstile widget is injected at the `<!-- captcha-widget-slot -->` marker in
each form template and the server verifies the response token against
Cloudflare's siteverify API before processing the form.

### Trait contract

```rust
pub trait CaptchaProvider: Send + Sync {
    fn widget_html(&self) -> &str;  // HTML snippet to inject; empty = noop
    fn verify(&self, token: &str, ip: IpAddr) -> bool;
}
```

`verify()` is synchronous (blocking `ureq` POST). Call inside `spawn_blocking`.

### Failure mode (§6.1)

| Condition | Outcome |
|-----------|---------|
| Empty token | fail-**closed** (`false`) — bot bypassed widget |
| Transport / Cloudflare error | fail-**open** (`true`) — log at `warn` |
| Provider not configured | `NoopCaptchaProvider` → always `true` |

### Forms wired

| Form | Template | Handler |
|------|----------|---------|
| Registration | `templates/ui/register.html` | `register_submit` |
| Forgot password | `templates/ui/forgot_password.html` | `forgot_password_submit` |

### Configuration (`security.captcha` in `hearth.yaml`)

```yaml
security:
  captcha:
    provider: turnstile
    turnstile:
      site_key: "0x4AAAAAAA..."         # public
      secret_key: "0x4AAAAAAA..."        # private — prefer HEARTH_TURNSTILE_SECRET_KEY
```

When absent, `NoopCaptchaProvider` is active (fail-open per §6.1).

---

## P-2 — IP Reputation: Spamhaus DROP + MaxMind ASN

**Status:** Shipped (HEA-1203)  
**Module:** `src/abuse/ip_reputation/` → `IpReputationProvider` (trait), `SpamhausDropProvider`, `MaxMindAsnProvider`

### What it provides

| Adapter | Signal | Source | Refresh |
|---------|--------|--------|---------|
| `SpamhausDropProvider` | `is_blocklisted: bool` | Spamhaus DROP (IPv4) + EDROP (IPv6) CIDR lists | Daily, background task |
| `MaxMindAsnProvider` | `asn: Option<u32>`, `asn_org: Option<String>` | Local MaxMind GeoLite2-ASN / GeoIP2-ASN MMDB file | On restart / manual |

### Trait contract

```rust
pub trait IpReputationProvider: Send + Sync {
    fn check(&self, ip: IpAddr) -> IpReputationVerdict;
}
```

`check()` MUST be synchronous, allocation-free on the happy path, and
**fail-open** (return `IpReputationVerdict::default()` on any error).

### Data structure

`SpamhausDropProvider` holds a `Arc<ArcSwap<CidrFilter>>`.  The background
refresh task builds a new `CidrFilter` from the downloaded DROP + EDROP text,
then calls `ArcSwap::store(Arc::new(new_filter))` to replace it atomically.
Hot-path reads call `ArcSwap::load()` (zero allocation, no locks), then perform
a linear scan over the deny `Vec<Cidr>`.  For the current DROP list size (~800
IPv4 + ~100 IPv6 CIDRs) this stays well under the 5 µs `AbuseGuard.check()`
budget.

### Outcome and caller contract

Callers inspect `IpReputationVerdict`:
- `is_blocklisted = true` → IP is in Spamhaus DROP/EDROP.  Callers apply the
  per-realm `IpReputationPolicy.action` (Block / Challenge / Log).
- `asn`, `asn_org` → populated by `MaxMindAsnProvider` when available; used
  as an input signal for A-11 risk scoring.  Never used as a direct block
  decision — ASN alone does not block.

Callers MUST NOT expose `is_blocklisted` reason to the client.

### Failure mode: fail-open

Per §6.1 of the abuse-prevention plan: `IpReputation` is **fail-open**.

- `SpamhausDropProvider` starts with an empty filter until the first background
  refresh succeeds.  If a refresh fails, the previous filter is retained.
- `MaxMindAsnProvider` returns `IpReputationVerdict::default()` if the MMDB
  file is missing, unreadable, or the IP has no ASN record.
- Both: any internal error returns the default verdict — no request is ever
  blocked by a provider fault.

### Configuration (`hearth.yaml`)

```yaml
security:
  ip_reputation:
    enabled: true           # false (default) = checks skipped entirely
    action: block           # block | challenge | log (default: log)
    spamhaus:
      drop_url: https://www.spamhaus.org/drop/drop.txt
      dropv6_url: https://www.spamhaus.org/drop/dropv6.txt
      refresh_interval_secs: 86400   # 24 hours
    maxmind_db_path: /etc/hearth/GeoLite2-ASN.mmdb   # absent = disabled
```

Per-realm override: set `security.ip_reputation.enabled: false` in the realm
block to opt a realm out of IP reputation checks.

---

## A-3 — Distributed-Attack Detector

**Status:** Shipped (HEA-1189)  
**Module:** `src/abuse/detector` → `DistributedAttackDetector`

### What it detects

Two cardinality dimensions, independently thresholded:

| Dimension | Pattern caught |
|-----------|---------------|
| Distinct usernames tried per source IP | Password spray: one IP cycling through many accounts |
| Distinct source IPs targeting one username | Distributed credential stuffing: botnet each trying one account once |

### Data structure

A `DistinctWindow` per (IP or username) key uses two rotating `HashSet<u64>`
buckets backed by `SipHash-1-3` (Rust `DefaultHasher`).  Rotation schedule:
- `elapsed ≥ full_window` → full clear (both buckets emptied).
- `elapsed ≥ half_window` → partial rotation (`prev ← current`, fresh `current`).

The distinct count is `current ∪ prev` computed via early-exit iteration once
the threshold is hit, so the check is O(threshold) not O(n).

Each bucket is capped at `2 × threshold` entries, bounding memory per key
regardless of attack rate.

### Outcome and caller contract

```
DetectorOutcome::Challenge { reason: &'static str }
```

Callers receiving `Challenge` MUST:
1. Emit `AuditAction::AbuseDetected` with IP and username in metadata.
2. Apply a challenge response (A-16 CAPTCHA or A-17 tarpit).
3. Return an appropriate error to the client (HTTP 429 or challenge token).

MUST NOT surface the `reason` field to the client.

### Failure mode: fail-open

Lock poisoning returns `DetectorOutcome::Allow`.  The hard rate limiter (A-2)
and per-account lockout (A-12) remain backstops.

### Configuration (`hearth.yaml`)

```yaml
security:
  distributed_attack_detector:
    window: 300s              # rolling window length (default: 5 min)
    username_per_ip_threshold: 20   # distinct usernames per IP
    ip_per_username_threshold: 20   # distinct IPs per username
```

Set `username_per_ip_threshold` or `ip_per_username_threshold` to `usize::MAX`
(or use `DistributedAttackDetector::disabled()`) to disable individual
dimensions without recompiling.

---

## A-4 — Outbound Email/SMS Volume Shield

**Status:** Shipped (HEA-1189)  
**Module:** `src/abuse/detector` → `OutboundVolumeShield`

Prevents a tenant from using Hearth as an email-pumping amplifier against
third-party recipients.  Tracks *distinct* outbound recipients per realm in a
rolling window.

### Caps

| Outcome | Meaning | Required caller action |
|---------|---------|------------------------|
| `Allow` | Within budget | Proceed with send |
| `SoftCap` | Unusual breadth — review recommended | Emit `AbuseDetected` audit + A-7 security webhook; MAY still send |
| `HardCap` | Budget exhausted | MUST reject send (HTTP 429 or equivalent); emit `AbuseDetected` audit |

### Privacy

Recipient addresses are stored as `SipHash-1-3` hashes (`u64`).  Plaintext
recipient addresses are never retained in memory.

### Integration point

Callers that dispatch outbound email call
`OutboundVolumeShield::check_email(realm_id, recipient)` before the actual
send.  For SMS (when `src/identity/sms.rs` ships), call `check_sms(...)`.

```rust
match volume_shield.check_email(realm_id, recipient) {
    VolumeShieldOutcome::HardCap => return Err(EmailError::VolumeLimitExceeded),
    VolumeShieldOutcome::SoftCap => {
        // emit AbuseDetected audit + security webhook
    }
    VolumeShieldOutcome::Allow => {}
}
email_service.send_verification_email(recipient, ...)?;
```

### Failure mode: fail-open

Lock poisoning returns `VolumeShieldOutcome::Allow`.

### Configuration (`hearth.yaml`)

```yaml
security:
  outbound_volume_shield:
    window: 3600s           # rolling window (default: 1 hour)
    email_soft_cap: 1000    # distinct email recipients before SoftCap
    email_hard_cap: 5000    # distinct email recipients before HardCap
    sms_soft_cap: 100       # distinct SMS recipients before SoftCap
    sms_hard_cap: 500       # distinct SMS recipients before HardCap
```

---

## A-7 — Security Webhook Channel

**Status:** Shipped (HEA-1190)

Operators subscribe webhooks to the `security.*` event family to fan security
events out to a SIEM, Slack channel, or WAF—without polling the audit log.

### Event types

| Wire name | `AuditAction` variant | Description |
|-----------|----------------------|-------------|
| `security.login_failed` | `LoginFailed` | Credential verification failed |
| `security.account_locked` | `LoginLocked` | Account temporarily locked |
| `security.abuse_detected` | `AbuseDetected` | Abuse pattern detected (A-3 detector) |
| `security.password_compromised` | `PasswordCompromisedRejected` | Password rejected as known-compromised (HIBP) |
| `security.rate_limit_exceeded` | `IpLoginLimitExceeded` | Per-IP login rate limit hit |

The five event types appear in the webhook create/edit form in the admin UI
under a **Security events** group. The delivery mechanism is unchanged: each
matching `AuditEvent` is signed with HMAC-SHA256 and POSTed to the endpoint
with exponential-backoff retry (see `src/webhook/dispatcher.rs`).

### `X-Hearth-Event` header

The header value is the `AuditAction::as_str()` wire key (e.g.
`login_failed`), not the dot-notation display string. Consumers should match
on the wire key.

---

## A-8 — Admin Abuse Dashboard

**Status:** Shipped (HEA-1190)

`GET /ui/admin/realms/{realm}/abuse` — server-rendered security monitor.

### Counters (rolling 24-hour window)

| Counter | Source `AuditAction` |
|---------|---------------------|
| Login failures | `LoginFailed` |
| Accounts locked | `LoginLocked` |
| Rate-limit hits | `IpLoginLimitExceeded` |
| Compromised-password rejections | `PasswordCompromisedRejected` |
| Abuse detections | `AbuseDetected` |

### Top-IP aggregation

Events whose metadata carries an `"ip"` key are aggregated into a top-10
failing-IPs table. IP metadata is populated by the credential-verification
and rate-limit code paths. The `AbuseDetected` action also carries `ip`.

### Fail-open policy

Per §6/§6.1 of the abuse-prevention plan, a query failure degrades to empty
counters (status 200, zeros). An audit-engine outage never blocks operator
access to the admin UI.

### Not yet implemented on this page

- **Block / unblock IPs** — requires A-9 (CIDR allow/deny lists).
- **ASN view** — requires P-2 (`IpReputationProvider` integration).
- **Geo heat-map** — requires P-2 (MaxMind GeoIP2 or equivalent).

---

## A-50 — Cross-Realm SMS / Email Aggregation Cap

**Status:** Shipped (HEA-1201)  
**Module:** `src/abuse/detector` → `CrossRealmAggregationCap`  
**Closes:** §3.53 of the abuse-prevention plan

Complements A-4's per-realm volume shield by tracking how many **distinct
realms** have sent to the same recipient across the entire cluster.  An
attacker who splits sends across N realms to evade A-4's per-realm budget is
caught here.

### Threat closed (§3.53)

A-4 caps *per-realm* distinct recipients per hour.  Without A-50, an attacker
controlling 50 realms can target the same `+1 555-0100` from each, staying
below A-4's per-realm threshold while flooding the victim.  A-50 detects the
cross-realm pattern and escalates.

### Outcome and caller contract

| Outcome | `realm_count` | Required caller action |
|---------|--------------|------------------------|
| `Allow` | — | Proceed with send |
| `MultiRealmAlert { realm_count }` | ≥ `alert_threshold` | Emit `AbuseDetected` audit + A-7 webhook; MAY still send |
| `SoftCap { realm_count }` | ≥ `email/sms_realm_soft_cap` | MUST apply CAPTCHA or queue; SHOULD emit audit + webhook |
| `HardCap { realm_count }` | ≥ `email/sms_realm_hard_cap` | MUST reject send (HTTP 429); MUST emit audit + webhook |

Callers MUST NOT surface the `realm_count` value to the sending realm or to
any external client.

### Privacy

Recipient addresses and realm IDs are stored only as `SipHash-1-3` hashes
(`u64`).  No plaintext is retained in memory.

### Fail-open policy

Per §6/§6.1: lock poisoning returns `CrossRealmOutcome::Allow`.  A-4
per-realm caps and A-2 request shaper remain backstops.

### Integration point

Call **in addition to** `OutboundVolumeShield::check_email` / `check_sms`.
Both checks must pass before a send proceeds:

```rust
// Per-realm cap (A-4) — checked first
match volume_shield.check_email(realm_id, recipient) {
    VolumeShieldOutcome::HardCap => return Err(EmailError::VolumeLimitExceeded),
    VolumeShieldOutcome::SoftCap => { /* emit audit + webhook */ }
    VolumeShieldOutcome::Allow => {}
}
// Global cross-realm cap (A-50) — checked second
match cross_realm_cap.check_email(realm_id, recipient) {
    CrossRealmOutcome::HardCap { .. } => return Err(EmailError::CrossRealmCapExceeded),
    CrossRealmOutcome::SoftCap { .. } => { /* challenge + emit */ }
    CrossRealmOutcome::MultiRealmAlert { .. } => { /* emit audit + webhook */ }
    CrossRealmOutcome::Allow => {}
}
```

### Configuration (`hearth.yaml`)

```yaml
security:
  cross_realm_aggregation_cap:
    window: 3600s               # rolling window (default: 1 hour)
    alert_threshold: 3          # distinct realms before operator alert
    email_realm_soft_cap: 5     # distinct realms before email SoftCap
    email_realm_hard_cap: 10    # distinct realms before email HardCap
    sms_realm_soft_cap: 3       # distinct realms before SMS SoftCap
    sms_realm_hard_cap: 6       # distinct realms before SMS HardCap
```

Set all thresholds to `usize::MAX` (or use `CrossRealmAggregationCap::disabled()`)
to disable without recompiling.

---

## A-48 — OAuth `state` ↔ Session Binding (Federation Start)

**Status:** Shipped (HEA-1200)  
**Module:** `src/protocol/web/federation.rs`, `src/identity/federation/state.rs`  
**Closes:** §3.51 of the abuse-prevention plan

### Threat (§3.51)

At `begin`, Hearth stores the federation state bag (nonce, PKCE verifier,
`return_to`) under the opaque `state` token.  Without binding, any browser that
already knows the `state` value (e.g. by observing the redirect URL from a
shared tab, referrer header leak, or an attacker-initiated parallel flow) can
call the `callback` endpoint with a valid code and take over the resulting
session.

### Implementation

`begin_impl` (`federation.rs:104`):

1. Calls `FederationService::begin` to produce the upstream authorization URL
   and a random 256-bit `state_token`.
2. Computes `bind_mac = HMAC-SHA256(cookie_secret, "fed-state-bind|" || state_token)`.
3. Sets a short-lived `hearth_fed_bind=<bind_mac>; HttpOnly; Path=/; SameSite=Lax; Max-Age=600`
   cookie on the response.  `SameSite=Lax` is required because the IdP redirect
   is a top-level cross-origin navigation.

`callback_impl` (`federation.rs:184`):

1. Extracts `hearth_fed_bind` from the `Cookie` header.
2. Calls `verify_federation_state_mac(cookie_secret, q.state, mac)` — a
   constant-time HMAC comparison.
3. If missing or mismatched → 303 to `/ui/login?error=federation_failed`.

The MAC primitive lives in `src/identity/federation/state.rs::compute_federation_state_mac` /
`verify_federation_state_mac`.  It is domain-separated from the confirm-link
cookie with the prefix `"fed-state-bind|"`.

### Fail mode

Fail-**closed**.  A callback without the correct cookie is unconditionally
rejected.  No fallback, no degraded path.

### Key invariants

- `state_token` is 32 random bytes (256-bit entropy), base64url-encoded.
- The HMAC key is the server-wide `cookie_secret` (32 bytes, loaded at boot,
  zeroized on drop).
- `Max-Age=600` (10 min) — the upstream IdP redirect must complete within this
  window.  Expired cookies are automatically removed by the browser.
- No plaintext `state` value is stored in the cookie — only the MAC tag.

### Tests

| Test file | Coverage |
|-----------|---------|
| `tests/abuse_risk.rs::a48_*` | MAC primitives — determinism, roundtrip, wrong MAC, wrong secret, domain-separation |
| `tests/abuse_a48_a49.rs::a48_*` | HTTP adversarial — missing cookie, cross-state cookie, forged MAC, wrong-secret cookie |
| `tests/web_ui_federation.rs` | Integration — begin plants cookie; callback with unknown state redirects; full flow |

---

## A-49 — Refresh-Token UA/ASN Context Binding

**Status:** Shipped (HEA-1200)  
**Module:** `src/identity/engine/mod.rs`, `src/identity/oidc.rs`, `src/protocol/http.rs`  
**Closes:** §3.52 of the abuse-prevention plan

### Threat (§3.52)

Refresh tokens are bearer tokens.  Rotation catches replay *after* a first
theft-detect (mismatch family hash), but not "stolen token replayed from a
wholly different network / device before the legitimate holder next refreshes."
A-49 closes this window by flagging a context switch into the A-11 risk scorer.

### Implementation

**Grant family binding** (`src/identity/oidc.rs::StoredGrantFamily`):

| Field | Type | Purpose |
|-------|------|---------|
| `ua_hash` | `Option<String>` | SHA-256 hex of the first `User-Agent` seen on a refresh exchange |
| `bound_asn` | `Option<u32>` | ASN from the first refresh (stub — absent until P-2 ships) |

Both fields default to `None` at grant-family creation; they are recorded on
the **first refresh exchange** (lazy binding) so that clients that never
refresh do not carry stale context.

**Context detection** (`engine/mod.rs:2024-2071`):

1. `callback_impl` in `http.rs` extracts the `User-Agent` header and wraps it
   in a `RefreshBindContext { user_agent, asn }`.
2. On each refresh exchange, `ua_changed` and `asn_changed` are computed by
   comparing hashes against the stored family values.  If neither stored hash
   is present (fresh grant or pre-upgrade), both flags are `false` (fail-open).
3. When `ua_changed || asn_changed`:
   - Reads `realm.config.risk_scorer_config` (or default).
   - Builds a `RiskContext { signals: [RefreshContextDelta { ua_changed, asn_changed }] }`.
   - If `scorer.score(&ctx).step_up_required` → `Err(IdentityError::StepUpChallengeRequired)`.
4. On the first refresh, the family's `ua_hash` / `bound_asn` are written with
   the current values for future comparisons.

**Signal weight** (default `refresh_context_delta_weight = 0.35`):

| Changed dimensions | Score contribution |
|-------------------|--------------------|
| None | 0.0 |
| UA only | 0.35 |
| ASN only | 0.35 |
| Both | 0.70 → exceeds default `step_up_threshold = 0.5` |

### Fail mode

Fail-**open**.

- Scorer disabled (`security.risk_scorer.enabled: false`, the default) → never blocks.
- No stored `ua_hash` / no inbound `User-Agent` → skip check entirely.
- Risk scorer is a heuristic signal, not a hard gate; operators must explicitly
  enable it and set an appropriate threshold.

### Configuration (`security.risk_scorer` in `hearth.yaml`)

See the P-4 section for the full config reference.  The relevant field:

```yaml
security:
  risk_scorer:
    enabled: true                      # false by default — opt-in
    step_up_threshold: 0.5             # 0.70 (both dims) > 0.5 → step-up
    refresh_context_delta_weight: 0.35 # per changed dimension
```

### Tests

| Test file | Coverage |
|-----------|---------|
| `tests/abuse_risk.rs::a49_*` | Unit — disabled scorer, UA-only change, both dims, no change |
| `tests/abuse_a48_a49.rs::a49_*` | Adversarial — stolen token UA change triggers step-up; fail-open guarantee; both-dims threshold; field API |
| `tests/abuse_risk_scorer.rs::p4_refresh_*` | Scorer weight arithmetic — one/both/zero dims |

---

## A-45 — Tenant-Controlled HTML/CSS/SVG Sanitization

**Scope:** All operator- or tenant-supplied content that flows into an
unescaped render path must pass through `src/abuse/sanitize.rs` before
reaching a template.

### SVG (`logo_svg_inline`)

Inline SVG logos are rendered via the Askama `|safe` filter in
`templates/email/base.html`. The sanitizer (`sanitize_svg`) runs inside
`prepare_svg_for_email()` in `src/identity/email/service.rs` — upstream of
any template render.

**Stripped unconditionally:**

| What | Why |
|------|-----|
| `<script>` (entire subtree) | JavaScript execution |
| `<foreignObject>` (entire subtree) | Embeds arbitrary HTML |
| `<iframe>`, `<object>`, `<embed>` | External resource / frame injection |
| Attributes starting with `on` | Event-handler injection (`onload`, `onclick`, …) |
| `href` / `xlink:href` not starting with `#` | External resource pull, `data:` / `javascript:` URIs |
| `style` attrs containing `expression(`, `javascript:`, `behavior:`, `-moz-binding` | CSS-in-SVG execution vectors |

**Preserved:** All other elements and attributes, including `viewBox`, `fill`,
`stroke`, `d`, `cx`, `cy`, `r`, `class`, `id`, and CSS custom properties.

**Fail mode:** Fail-closed. If quick-xml cannot parse the input at all, the
empty string is returned rather than the raw input.

### CSS (`custom_css`)

Operator- and realm-level `custom_css` files are read from disk at startup in
`src/main.rs` and sanitized via `sanitize_css` before being concatenated into
the served theme CSS.

**Stripped lines (case-insensitive match):**

| Pattern | Why |
|---------|-----|
| `expression(` | IE CSS expression execution |
| `javascript:` | JavaScript scheme in `url()` values |
| `behavior:` | IE-specific behavior binding |
| `-moz-binding` | Firefox XUL binding injection |
| `url(data:` | Inline data exfiltration / script injection |
| `url(javascript:` | JavaScript scheme in `url()` |
| `-ms-filter` | IE `progid:` filter execution |
| `progid:` | IE expression loader |
| `@import` rules | Loads external arbitrary CSS |

**Preserved:** All other declarations and at-rules, including `@media`,
`@keyframes`, `:root {}` blocks, and CSS custom properties (`--ht-*`).

**Fail mode:** Fail-open per line. Individual dangerous declarations are
dropped; the rest of the file is returned unchanged.

### Fail-Open vs Fail-Closed

Per §6.1 of the abuse-prevention plan:

- **SVG** — fail-closed (unparse-able SVG → empty string). An SVG logo that
  cannot be parsed is rendered as nothing, which is visible but not harmful.
- **CSS** — fail-open per declaration. An unrecognised but harmless CSS line
  is better served than blanket-rejected. Only explicitly dangerous lines are
  dropped.

### Out of Scope (A-45)

- HTML body sanitization for email templates is not currently implemented
  because Hearth does not expose a tenant HTML body field. If such a field is
  added in a future phase, it must pass through an allowlist sanitizer
  (ammonia or equivalent) before rendering.
- Tera disk-based template overrides (`email.templates_dir`) are operator-
  controlled only and are not sanitized at the template level; access to the
  filesystem already implies trusted operator access.

---

## A-21 — JSON Parse-Bomb Guard (depth + array length)

**Status:** Shipped (HEA-1369)  
**Module:** `src/abuse/guards.rs` → `check_json_depth`; wired as `json_depth_guard` route middleware in `src/protocol/http.rs`

### Threat

`serde_json` faithfully traverses arbitrarily deep nesting in a JSON body, consuming thread stack proportional to depth. A 1 MiB body of `{"a":{"a":…` hundreds of levels deep can exhaust the thread stack. A large flat array (`["x","x",…×1_000_000]`) exploits serde_json's linear array allocation.

### Implementation

A `json_depth_guard` axum route middleware intercepts every `POST`, `PUT`, and `PATCH` request with `Content-Type: application/json`. Before any handler logic executes, it:

1. Collects the request body into memory (already capped at `BODY_LIMIT_DEFAULT` by the outer `DefaultBodyLimit` layer).
2. Calls `check_json_depth(bytes)`, which scans raw bytes counting bracket tokens — O(n), no full deserialization.
3. Rejects bodies where nesting depth > `MAX_JSON_DEPTH` (128) or any array length ≥ `MAX_JSON_ARRAY_LEN` (65 536) with HTTP **400 Bad Request**.
4. On success, reconstitutes the request with the collected bytes so downstream handlers receive a normal body.

The scan is O(n) and safe against UTF-8 multi-byte sequences because `{`, `}`, `[`, `]`, and `"` are all ASCII.

### Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `MAX_JSON_DEPTH` | 128 | Maximum combined object/array nesting depth |
| `MAX_JSON_ARRAY_LEN` | 65 536 | Maximum items in any single JSON array |

### Fail mode

**Fail-closed.** Oversized bodies are rejected with HTTP 400 before handler logic. Non-JSON content types (`Content-Type` not starting with `application/json`) and non-mutating methods (GET, HEAD, DELETE, OPTIONS) bypass the guard entirely.

### Tests

`tests/abuse_json_guard.rs` — 6 tests covering:
- Deeply nested JSON → 400 with `"depth"` in error body
- JSON at exactly `MAX_JSON_DEPTH` → passes guard
- Array with `MAX_JSON_ARRAY_LEN` elements → 400 with `"array"` in error body
- Normal JSON → passes guard
- Non-JSON `Content-Type` → guard skipped
- GET request → unaffected (200 from `/health`)

---

## A-22 — Decompression-Bomb Cap

**Status:** N/A — Hearth does not install an inbound `Content-Encoding: gzip` decompressor.

Compressed request bodies are treated as opaque bytes and passed through to handlers unchanged. No decompression occurs server-side, so a gzip bomb cannot expand in-process. If a future change introduces inbound decompression (e.g. for a bulk-import endpoint), `check_decompressed_size` in `src/abuse/guards.rs` must be wired at that point and this section updated.

---

## A-33 — Bounded delete_realm Cascade

**What it prevents:** A large realm deletion causing a write storm that degrades the storage layer for all tenants.

**How it works:**

- `delete_realm` first marks the realm as `DeletingInProgress` in storage and the hot-path status cache, blocking new auth operations immediately.
- The cascade is chunked (`cascade_chunk_size`, default 200 keys/chunk).
- If total item count exceeds `cascade_background_threshold` (default 1,000), deletion is backgrounded via a tokio task; the HTTP response returns immediately.
- Status is surfaced in the admin dashboard (realm shows "Deleting" state).

**Config (per global engine config, not per-realm YAML):**

```yaml
# These are engine-level defaults, not per-realm YAML keys.
cascade_chunk_size: 200
cascade_background_threshold: 1000
```

**Failure mode:** Fail-open for background progress (realm stays `DeletingInProgress` on crash; re-running `delete_realm` on restart converges via idempotent cascade).

---

## A-35 — SCIM / SAML Payload Caps

### A-35a: SCIM PATCH `Operations` count cap

**Threat**: A SCIM PATCH body with thousands of `Operations` entries causes
fan-out over the `apply_user_patch` / `apply_group_patch` loop, consuming
unbounded CPU and memory.

**Implementation**:

`src/protocol/scim/users.rs` (`patch_user`) and
`src/protocol/scim/groups.rs` (`patch_group`) check
`body.operations.len() > MAX_SCIM_OPERATIONS` (1 000) *before* any patch
logic executes and return HTTP 400 / `scimType: tooMany` if exceeded.

**Fail mode**: Fail-closed.

**Constant**: `crate::abuse::MAX_SCIM_OPERATIONS = 1_000`.

**RFC reference**: RFC 7644 §3.5.2 (PATCH; no explicit count limit — cap is
a server hardening decision).

**Residual risk**: A client can still send up to 1 000 operations in a single
request. Per-operation cost is bounded by the O(1) patch logic; no further
mitigation is planned for this phase.

### A-35b: SAML XML event cap

**Threat**: A crafted SAML `<Response>` body containing tens of thousands of
elements (no DTD or entity expansion required) exhausts the SP's CPU/memory
during parsing.

**Implementation**:

Both `parse_response` (`src/identity/federation/saml/response.rs`) and
`find_element_range` (`src/identity/federation/saml/xml.rs`) maintain an
`event_count: usize` counter.  After `MAX_SAML_XML_EVENTS` (10 000) events,
the function returns `Err(IdentityError::SamlParse { reason: "…" })`.

**XXE posture** (regression guard): `find_element_range` explicitly handles
`Event::DocType` by returning an error. `parse_response` does not call
`make_reader` (which enables expanded elements) — it initialises its own
reader with `expand_empty_elements = false`. The event cap is belt-and-
suspenders on top of the DOCTYPE rejection.

**Fail mode**: Fail-closed.

**Constant**: `crate::abuse::MAX_SAML_XML_EVENTS = 10_000`.

**RFC reference**: SAML 2.0 Core §1.2 (DTD-free messages); OWASP XXE
Prevention Cheat Sheet.

---

## A-38 — Token-Exchange Depth & DPoP `cnf.jkt` Coverage

### A-38a: DPoP sender-constraint enforcement on all access-token-issuing grants

**Threat**: A FAPI 2.0 realm or FAPI 2.0 client calls `client_credentials` or
`jwt-bearer` without a DPoP proof.  The issued token is sender-unconstrained
(a bearer token any party can replay).  Previously only the authorization-code
exchange path enforced the FAPI DPoP gate.

**Implementation**:

Both `client_credentials_token_inner` and `jwt_bearer_token_inner` in
`src/identity/engine/oauth.rs` now execute the same FAPI gate as
`exchange_code_for_tokens`:

```
if (client.profile().is_fapi2() || realm.config().fapi_profile.is_some())
   && request.dpop_jkt.is_none()
→ return Err(FapiViolation)
```

The gate checks both the per-client `profile` field *and* the realm-level
`fapi_profile` so a standard client cannot bypass a realm-wide FAPI
enforcement.

**Fail mode**: Fail-closed for FAPI realms/clients; fail-open for non-FAPI
(DPoP remains optional).

**RFC references**: FAPI 2.0 Security Profile §5.3.3 (sender-constrained
tokens mandatory on all grant types); RFC 9449 (DPoP); RFC 6749 §4.4
(client credentials grant).

### A-38b: RFC 8693 `act` delegation-chain depth cap

**Threat**: An external party constructs a JWT with a deeply-nested `act`
(actor) delegation chain per RFC 8693 §4.4. Processing such a token
iteratively still visits each node in the chain; without a bound, an
attacker-controlled depth can cause unbounded CPU consumption.

**Implementation**:

`EmbeddedIdentityEngine::validate_token` inspects `claims.custom.get("act")`
immediately after the token type check.  (The `act` claim falls into the
flattened `custom: BTreeMap` because Hearth does not issue `act` chains
today.) `act_chain_depth` traverses the chain iteratively:

```rust
fn act_chain_depth(act: &serde_json::Value) -> usize {
    let mut depth = 0;
    let mut cur = act;
    loop {
        depth += 1;
        if depth > MAX_ACT_CHAIN_DEPTH + 1 { return depth; }
        match cur.get("act") {
            Some(next) => cur = next,
            None => return depth,
        }
    }
}
```

If `depth > MAX_ACT_CHAIN_DEPTH` (3), `InvalidToken` is returned.

Depth semantics:
- `{ "sub": "x" }` (no nested act) → depth 1
- `{ "sub": "x", "act": { "sub": "y" } }` → depth 2
- Three-level chain → depth 3 (= MAX, accepted)
- Four-level chain → depth 4 (> MAX, rejected)

**Fail mode**: Fail-closed (invalid token rejected outright).

**Constant**: `crate::abuse::MAX_ACT_CHAIN_DEPTH = 3`.

**RFC reference**: RFC 8693 §4.4 (`act` claim structure and delegation chains).

**Residual risk**: Hearth does not currently *issue* `act` chains (RFC 8693
token exchange is not yet implemented). If token exchange is implemented,
the `MAX_ACT_CHAIN_DEPTH` constant MUST be used when building outbound chains
and a regression test MUST be added to `tests/abuse_dpop_act.rs`.

---

## A-11 — Step-up MFA Risk Scorer

**Source**: `src/identity/risk.rs` (re-exports from `src/abuse/risk_scorer.rs` — HEA-1205)

Aggregates risk signals at login time into a normalised score `[0.0, 1.0]`.
When `score >= step_up_threshold` (default `0.5`), the login handler returns
`IdentityError::StepUpChallengeRequired` — the same gate as the existing
device-fingerprint step-up.

### Signals

| Signal | Default weight | Source |
|--------|---------------|--------|
| `NewDevice` | 0.3 | Device-fingerprint miss (`src/identity/device_fp`) |
| `NewCountry` | 0.4 | GeoIP lookup (stub — absent until P-2 ships) |
| `PasswordAge { days }` | 0.2 (if `days >= threshold`) | `user.created_at()` (approximation) |
| `BreachCorpusHit` | 1.0 (forces step-up) | HIBP / offline corpus |
| `RefreshContextDelta` | 0.35 per dim | UA-hash or ASN change on refresh (A-49) |

### Config (`security.risk_scorer` in `hearth.yaml`)

```yaml
security:
  risk_scorer:
    enabled: true                    # default: false (fail-open)
    step_up_threshold: 0.5           # score >= this → step-up
    new_device_weight: 0.3
    new_country_weight: 0.4
    password_age_weight: 0.2
    password_age_days_threshold: 365
    breach_corpus_weight: 1.0
    refresh_context_delta_weight: 0.35
```

**Fail mode**: Fail-open. When disabled (`enabled: false`, the default) score
is always `0.0` so existing deployments are unaffected.

**Extension point (P-4)**: See [§ P-4: `RiskScorer`](#p-4-riskscorer--rule-based-step-up-mfa-risk-engine)
for the pluggable trait contract and swap-in instructions.

---

## A-16 — CAPTCHA-of-Last-Resort Challenge Plumbing

**Source**: `src/abuse/challenge.rs`

Tracks per-IP failed-authentication counts. When the threshold is crossed, the
IP enters "challenge" state for the configured TTL. In challenge state:

- **API callers** receive HTTP 403 with
  `error_code: "HEARTH_ABUSE_CHALLENGE_REQUIRED"`.
- **UI callers** receive a login/registration page that includes the configured
  CAPTCHA widget (injected at the `<!-- captcha-widget-slot -->` comment).

### State machine

```text
Allow → (threshold failures in window) → ChallengeRequired
ChallengeRequired → (clear() after CAPTCHA / window expiry) → Allow
```

### Config (`security.captcha` in `hearth.yaml`)

```yaml
security:
  captcha:
    challenge_threshold: 30  # failures per window before challenge; required
    window_secs: 60          # default: 60 s
    challenge_ttl_secs: 1800 # default: 30 min
```

**Fail mode**: Fail-open. When `challenge_threshold` is absent (the default),
the store is disabled and all calls return `Allow`.

**Extension point (P-1)**: The `CaptchaProvider` trait in
`src/abuse/challenge.rs` is the hook for HEA-1202 adapters (Cloudflare
Turnstile, hCaptcha, reCAPTCHA v3). The built-in `NoopCaptchaProvider` always
passes verification.

**Error code contract**: `HEARTH_ABUSE_CHALLENGE_REQUIRED` (HTTP 403) MUST be
the only error code returned when an IP is in challenge state. No other error
details are surfaced to callers.

---

## A-26 — `/metrics` Authentication + `Server:` Header Suppression

**Source**: `src/protocol/http.rs` (`metrics_handler`, `strip_server_header`)

### `/metrics` Bearer auth

When `metrics.bearer_token` is set in `hearth.yaml`, the Prometheus scrape
endpoint enforces `Authorization: Bearer <token>`. Comparison is
**constant-time** (`subtle::ConstantTimeEq`) to prevent timing-based
enumeration.

| Auth state | Configured token | Result |
|---|---|---|
| No header | `Some(token)` | HTTP 401 + `WWW-Authenticate: Bearer` |
| Wrong token | `Some(token)` | HTTP 401 + `WWW-Authenticate: Bearer` |
| Correct token | `Some(token)` | HTTP 200 (metrics body) |
| Any / none | `None` (default) | HTTP 200 (unauthenticated — operators should firewall or bind to loopback) |

### Config (`metrics` in `hearth.yaml`)

```yaml
metrics:
  enabled: true          # default: true — set false to disable the endpoint entirely
  bearer_token: "secret" # optional; when set, scrape requests must present this token
```

**Fail mode**: Fail-open. When `bearer_token` is absent (the default) the
endpoint is unauthenticated. This preserves backwards compatibility; operators
who need auth MUST set the field. Tip: generate a random 32-byte hex value with
`openssl rand -hex 32`.

### `Server:` header suppression

A `strip_server_header` axum middleware layer removes the `Server:` response
header from **every** response. This prevents fingerprinting of the underlying
runtime (hyper version, OS, etc.) by any unauthenticated observer.

**No config knob**: stripping is always active; there is no opt-out.

---

## A-27 — Tracing PII / Token Redaction

**Source**: `src/protocol/tracing.rs` (new), `src/protocol/web/handlers.rs`

### Contract

Any span field that could carry a credential or PII MUST be wrapped in
`crate::protocol::tracing::Redact(&value)` before passing it to a `tracing`
macro. Both `Display` and `Debug` impls emit the literal string `[REDACTED]`
so the inner value is never written into a log record, span exporter, or SIEM.

**Default-redacted field names** (all call sites must comply):

| Field name | Risk |
|---|---|
| `reset_url` | One-shot password-reset token embedded in URL |
| `magic_link_url` | One-shot magic-link token embedded in URL |
| `password` | Plaintext credential |
| `token` | Opaque bearer token |
| `cookie` | Session cookie value |
| Raw email address | PII under GDPR / CCPA |

### Usage

```rust
use crate::protocol::tracing::Redact;

tracing::warn!(
    reset_url = %Redact(&url),
    "password reset URL (no email transport configured)"
);
```

### Implementation

`Redact<T>` is a zero-cost newtype (`pub struct Redact<T>(pub T)`). Neither
constructor nor field is hidden — callers hold the real value as long as needed.
The wrapper is only applied at the `tracing!` macro call site.

**Fail mode**: No runtime fallback — this is a compile-time correctness
pattern. A field not wrapped in `Redact` is not redacted. Future work:
a `clippy` lint or proc-macro to flag unwrapped PII fields (tracked at
HEA-1196 platform follow-up).

**Per-deployment override**: `HEARTH_LOG_INCLUDE_PII=1` env toggle and
per-realm config are not yet implemented (Phase 0 ships the newtype only).
Future work tracked at HEA-1196.

---

## A-5 — Reserved Slug Registry + Post-Delete Cooldown

**What it prevents:** Squatting on reserved names (admin, api, www, …) as org or realm slugs; immediate re-registration of a just-deleted slug to harvest residual trust.

**How it works:**

- `security.reserved_slugs` in `hearth.yaml` declares a YAML list of names that are unconditionally rejected as realm names or organization slugs.  Built-in URL-routing keywords are always reserved regardless of this list.
- When a realm or organization is deleted, its name is written to a cooldown index with a 30-day TTL.  `create_realm` and `create_organization` check the index and return `HEARTH_SLUG_IN_COOLDOWN` if a live entry exists.
- The cooldown entry is cleaned up automatically on expiry; no operator action required.

**Config keys:** `security.reserved_slugs` (list of strings in `hearth.yaml`).

**Fail mode:** Fail-closed — a slug that matches a reserved name or an active cooldown entry is always rejected.  An empty list means only built-in routing keywords are reserved.

---

## A-6 — Bootstrap Endpoint Production Guard

**What it prevents:** Accidental exposure of the one-shot `POST /admin/bootstrap` endpoint in production deployments, which creates a realm, admin user, and long-lived API token.

**How it works:**

- In production mode (i.e. `--dev` flag absent), the `/admin/bootstrap` route is **not registered** in the HTTP router.  Unregistered routes return 404, preventing fingerprinting.
- Pass `--allow-bootstrap-in-prod` at startup to re-enable the route for initial provisioning of a fresh deployment.  When the flag is active, a startup-time `warn!()` is emitted to make the deviation visible in logs and alerting.
- `--dev` mode continues to register the route unconditionally.

**Config keys:** CLI flag `--allow-bootstrap-in-prod` (no `hearth.yaml` key).

**Fail mode:** Fail-closed by default (route absent).  Operator must opt in explicitly.

---

## A-10 — Per-IP JWKS / OIDC Discovery Rate Cap

**What it prevents:** Key-material enumeration and amplification attacks that hammer the JWKS or discovery endpoints to exfiltrate signing-key metadata or saturate the server.

**How it works:**

- A `JwksRateLimiter` (token-bucket, one bucket per source IP) gates `GET /.well-known/jwks.json` and `GET /.well-known/openid-configuration`.  Requests over the cap receive `429 Too Many Requests`.
- JWKS and discovery responses are pre-serialized into an `Arc<Bytes>` at startup and on key rotation.  Hot-path serves the cached bytes directly — no allocations per request.
- Default cap: 60 requests/second per source IP.

**Config keys:** `security.jwks_rps_limit` (integer, requests/second per IP; default `60`).

**Fail mode:** Fail-closed — requests exceeding the bucket are rejected.  The pre-serialized cache is rebuilt on key rotation and server reload.

---

## A-13 — WebAuthn Attestation Policy

**What it prevents:** Authenticators that do not meet operator-mandated assurance level (e.g., software FIDO2 keys masquerading as hardware tokens, or unlisted authenticators).

**How it works:**

- Per-realm config (`realms.<name>.auth.webauthn_attestation`) exposes three controls:
  - `allow_none: bool` — whether the `"none"` attestation format is accepted (default `true` for broad compatibility).
  - `aaguid_allowlist: Vec<Uuid>` — when non-empty, only authenticators whose AAGUID appears in the list are accepted.
  - `require_prf: bool` / `require_large_blob: bool` — optional extension requirements.
- Policy is enforced at registration time.  Authenticators that fail any active control receive `400 Bad Request`; no credential is stored.

**Config keys:** `realms.<name>.auth.webauthn_attestation.{allow_none,aaguid_allowlist,require_prf,require_large_blob}`.

**Fail mode:** Absent config = fail-open (all authenticators accepted).  Non-empty allowlist = fail-closed for unlisted AAGUIDs.

---

## A-14 — Per-Realm TTL Hard Caps

**What it prevents:** Excessively long password-reset or magic-link token lifetimes that widen the window for token theft, phishing, or link interception.

**How it works:**

- `to_realm_config` enforces hard upper bounds at config load time:
  - `auth.token.password_reset_token_ttl` ≤ 1 hour.
  - `auth.token.magic_link_ttl` ≤ 30 minutes.
- If a realm config exceeds either cap, the load is rejected unless `auth.token.allow_unsafe_ttl: true` is also set.  When the flag is set, a `warn!()` is emitted so operators are aware of the deviation.

**Config keys:** `auth.token.password_reset_token_ttl`, `auth.token.magic_link_ttl`, `auth.token.allow_unsafe_ttl` (all per-realm under `realms.<name>` or global under `auth.token`).

**Fail mode:** Fail-closed — config that exceeds the cap without the opt-in flag is rejected at startup.

---

## A-28 — Slug & Invitation Atomic CAS

**What it prevents:** Two concurrent requests winning the same organization slug or double-spending an invitation token.

**How it works:**

- A per-engine `org_write_lock` mutex serializes the check-then-write sequence for slug reservation and invitation acceptance.
- The primary record and slug index are written together via `put_batch` (single WAL record) for crash-safe atomicity.
- Invitation acceptance re-validates the pending status under the mutex, eliminating the double-spend window.
- RBAC assignment deduplication: `assign_write_lock` guards concurrent role assignment; idempotent if the same (subject, role, scope) already exists.

**Failure mode:** Fail-closed (mutex contention stalls the loser, then returns Conflict/NotFound).

---

## A-29 — Federation Hardening (IdP-Mixup, Unverified-Email Link Policy, SAML XXE / Sig-Wrap)

Closes §3.30 of the abuse-prevention plan.

### A-29a: RFC 9207 `iss` Authorization-Response Parameter (IdP-Mixup Defense)

**Threat**: An attacker intercepts a legitimate authorization code from
authorization server B and replays it against authorization server A's callback.
Without issuer validation, the RP cannot distinguish which server issued the
code and may accept an attacker-controlled token.

**Implementation**:

`src/identity/federation/oidc.rs::verify_iss_param(iss_hint, expected_issuer)`

When the authorization server includes an `iss` query parameter in the
redirect-back URL, `FederationService::callback()` validates it against the
configured `issuer` for the IdP connector **before** exchanging the code.

- **Present + matching** → allowed.
- **Present + mismatched** → `IdentityError::FederationIdpMixup`
  (HTTP 400, gRPC `INVALID_ARGUMENT`, wire code `HEARTH_FEDERATION_IDP_MIXUP`).
- **Absent** → allowed (fail-open; not all authorization servers send it — RFC 9207
  is optional for the AS side).

**Wire surface**: The `iss` query parameter is parsed from `CallbackQuery` in
`src/protocol/web/federation.rs`.  It is optional (`#[serde(default)]`);
absence does not block the flow.

**Fail mode**: Fail-closed on mismatch, fail-open on absence.

**RFC reference**: RFC 9207 §2.

### A-29b: Unverified-Email Account-Link Policy

**Threat**: A malicious upstream IdP (or a compromised one) asserts
`email_verified: false` with a known victim email.  Without explicit policy,
an auto-link under `LinkMode::Auto` would silently merge the attacker's
external identity with the victim's local account.

**Implementation**:

`ExternalIdentity::is_linkable_by_email()` in
`src/identity/federation/types.rs` returns `true` only when
`email_verified && !email.is_empty()`.  `FederationService::callback()` gates
**all** email-based linking (`LinkMode::Auto` and `LinkMode::Confirm`) on this
predicate.  When the predicate returns `false`, the flow falls through to JIT
provisioning — a new account is created without linking to any existing local
user.

**What this means for each `LinkMode`**:

| LinkMode  | `email_verified = true` | `email_verified = false` |
|-----------|------------------------|--------------------------|
| `Disabled` | JIT only (no linking)  | JIT only (no linking)    |
| `Confirm`  | Prompt user to confirm | JIT only (safe fallback) |
| `Auto`     | Silent link            | JIT only (safe fallback) |

**Fail mode**: Fail-closed — unverified email never auto-links.

### A-29c: SAML Signature-Wrapping Rejection

**Threat**: XML Signature Wrapping (XSW) — the attacker injects an unsigned or
differently-signed element into the SAML document so that the signature
verifier sees the legitimate signed element but the XML parser uses the
attacker-controlled one.

**Implementation**:

`src/identity/federation/saml/signature.rs::verify_signed_element`:

1. **Reference URI / element ID binding** — the `<ds:Reference URI="#id">`
   inside `<ds:SignedInfo>` MUST equal `#<ID>` where `<ID>` is the `ID`
   attribute of the located element.  A mismatch returns `SamlSignature`.
2. **Digest verification** — the SHA-256 digest of the canonicalized
   (exc-C14N) element must match the `<ds:DigestValue>`.  Any difference
   between the located element and what was actually signed returns
   `SamlSignature`.
3. **Multiple-assertion rejection** — `extract_and_validate_assertion`
   in `src/identity/federation/saml/response.rs` rejects responses with
   more than one `<Assertion>` child.  This closes the multi-assertion
   XSW class where a second attacker-controlled assertion is injected
   alongside the legitimate signed one.

**Fail mode**: Fail-closed.  Any signature discrepancy produces `SamlSignature`
without revealing which check failed.

### A-29d: SAML XXE / Entity-Expansion Caps

See **A-35b** and **A-35c** above — those sections cover entity-expansion and
DOCTYPE rejection for `parse_response`.  A-29d adds that `find_element_range`
(used by `verify_signed_element`) enforces the **same** `MAX_SAML_XML_EVENTS`
cap independently, providing belt-and-suspenders protection on the signature
verification path.

**Constants**: `crate::abuse::MAX_SAML_XML_EVENTS = 10_000` (shared).

**Fail mode**: Fail-closed.

---

## A-18: Session Lifecycle Policy (idle + absolute timeout)

**File**: `src/identity/sessions.rs`, `src/identity/engine/mod.rs`, `src/identity/types/realm.rs`

### YAML configuration

Under `auth:` (global) and per-realm:

```yaml
auth:
  session_idle_timeout_secs: 3600    # 1 hour idle timeout; null = disabled (default)
  session_absolute_timeout_secs: 86400  # 24-hour hard cap; null = disabled (default)

realms:
  my-realm:
    session_idle_timeout_secs: 1800   # override global
    session_absolute_timeout_secs: 43200
```

### Enforcement contract

| Mechanism | Trigger | Audit event |
|-----------|---------|-------------|
| Lazy eviction | `get_session()` or `refresh_session()` on a policy-expired session | `session_evicted` |
| Proactive reaper | Background task runs alongside OAuth cleanup sweep | `session_evicted` |

**Idle timeout**: Session evicted if `now ≥ last_refreshed_at + idle_timeout_secs`.
Reset on each `refresh_session()` call.

**Absolute timeout**: Session evicted if `now ≥ created_at + absolute_timeout_secs`.
Never reset — unaffected by refreshes.

Both deadlines are embedded in the `Session` record at creation time so the
hot-path `get_session()` avoids a realm config lookup on every call (zero-alloc
arithmetic only).

**Fail-open** (§6.1): when neither timeout is configured (the default), the
existing TTL governs. Removing a timeout config does not retroactively evict
existing sessions — sessions created with embedded deadlines continue to enforce
those deadlines until they naturally expire via TTL or explicit revocation.

### `session.evicted` audit event

- `reason`: `"idle_timeout"` | `"absolute_timeout"`
- `session_id`: the evicted session UUID
- `user_id`: the session owner
- `failure_policy`: `LogOnly` (fail-open)

---

## P-7: `SessionStore` Pluggable Trait

**File**: `src/identity/sessions.rs`

Defines `SessionStore` — the persistence interface for session list/lookup so
A-18's concurrent-session policy is enforceable cluster-wide in multi-node
deployments.

| Adapter | Location |
|---------|----------|
| `EmbeddedSessionStore` | `src/identity/sessions.rs` — WAL-backed reference adapter |
| Future Redis / Postgres adapters | Implement `SessionStore` and wire at construction |

The trait is `Send + Sync + 'static` and all methods are synchronous (blocking).
Async adapters wrap calls in `tokio::task::spawn_blocking`.

**Fail-open contract**: callers in the hot path treat storage errors as "session
not found" to avoid locking out users during transient outages.

---

## P-3: `BotSignalProvider` — UA + JA3/JA4 Heuristics Adapter

**Status**: Shipped (HEA-1204)  
**Source**: `src/abuse/bot_signal.rs`

### Overview

`BotSignalProvider` is the P-3 extension point for bot-signal detection.  The
built-in `HeuristicBotSignalProvider` reference adapter ships with Hearth.
External adapters (Cloudflare Bot Management, Datadome, Kasada, Akamai) implement
the trait and are wired at startup via `security.providers.bot_signal`.

### Signal layers (applied in order)

| Priority | Layer | Signal | Verdict |
|----------|-------|--------|---------|
| 1 | JA3 hash | Matches built-in or operator blocklist | `Block` |
| 2 | JA4 hash | Matches built-in or operator blocklist | `Block` |
| 3 | UA — woothee category | `"crawler"` | `Block` |
| 3 | UA — substring | Known scripting client (`curl/`, `python-requests/`, etc.) | `Block` |
| 4 | UA — substring | Headless browser / automation framework (`HeadlessChrome`, `Selenium`, etc.) | `Suspect` |
| 5 | UA — length | Shorter than 10 characters after trimming | `Suspect` |
| 5 | UA — absent | `User-Agent` header missing | `Suspect` |
| — | (none matched) | — | `Allow` |

### JA3/JA4 notes

JA3 and JA4 hashes must be injected by the proxy tier (`X-JA3-Hash` /
`X-JA4-Hash` headers set by Nginx, HAProxy, Cloudflare, etc.).  Hearth does not
perform TLS fingerprinting of its own listener — these headers are treated as
advisory.  When absent, the layers are skipped entirely.

The built-in JA3 blocklist contains 7 publicly documented automated-scanner
fingerprints (zgrab2/masscan, Nmap NSE, Metasploit, Shodan, Censys.io, etc.).
Add site-specific hashes via `security.providers.bot_signal.extra_ja3_blocklist`.

**False-positive warning**: JA3 hashes can collide between legitimate clients
and bots sharing the same TLS implementation.  Always pair JA3 blocking with
additional signals.

### Config (`security.providers.bot_signal` in `hearth.yaml`)

```yaml
security:
  providers:
    bot_signal:
      extra_ja3_blocklist:
        - "deadbeef00000000deadbeef00000000"
      extra_ja4_blocklist: []
```

### Fail-open policy (§6.1)

`BotSignal` is **fail-open**.  The default shipping configuration uses
`NoopBotSignalProvider` — no request is ever blocked until an adapter is
explicitly configured.  External adapter implementations MUST return
`BotSignalVerdict::Allow` on any transport or internal error.

### Off hot-path guarantee

The provider is consulted only at registration, forgot-password, and magic-link
flows — never during `validate_token()` or `lookup_session()`.

---

## P-4: `RiskScorer` — Rule-Based Step-Up MFA Risk Engine

**Status**: Shipped (HEA-1205)  
**Source**: `src/abuse/risk_scorer.rs`

### Overview

`RiskScorer` is the P-4 extension point for adaptive, risk-based step-up MFA.
The built-in [`RuleBasedRiskScorer`] reference adapter implements the A-11 rule
engine: it aggregates configurable risk signals observed at login time, computes
a normalised score in `[0.0, 1.0]`, and sets `step_up_required = true` when the
score meets or exceeds the operator's configured threshold.

Operators who need vendor risk models or custom ML pipelines implement the
`RiskScorer` trait and supply their adapter at startup.

### Risk signals

| Signal | Default weight | Source |
|--------|---------------|--------|
| `NewDevice` | 0.3 | Device-fingerprint miss (`(user_id, ip/24, UA)` not seen before) |
| `NewCountry` | 0.4 | GeoIP country change (stub — absent until P-2 ships) |
| `PasswordAge { days }` | 0.2 | Credential `created_at` ≥ `password_age_days_threshold` |
| `BreachCorpusHit` | 1.0 | HIBP k-anonymity / offline corpus match |
| `RefreshContextDelta` | 0.35 per dim | UA-hash or ASN change on refresh exchange (A-49) |

Weights sum additively; the total is clamped to `1.0` before the threshold
comparison.

### Fail-open policy

Per §6.1 of the abuse-prevention plan: `RiskScorer` is **fail-open**.

- The default config ships with `enabled: false` — `RuleBasedRiskScorer::disabled()`
  always returns score `0.0` and `step_up_required = false`.
- `NoopRiskScorer` always returns score `0.0` regardless of signals.
- External adapter implementations **MUST** return `step_up_required = false` on
  any transient error so that a scorer outage never blocks legitimate logins.

### Configuration (`hearth.yaml`)

```yaml
security:
  risk_scorer:
    enabled: true                    # false = fail-open (default)
    step_up_threshold: 0.5           # [0.0, 1.0] — score ≥ this triggers MFA
    new_device_weight: 0.3
    new_country_weight: 0.4
    password_age_weight: 0.2
    password_age_days_threshold: 365 # days before PasswordAge signal fires
    breach_corpus_weight: 1.0
    refresh_context_delta_weight: 0.35
```

All weights are per-signal contributions in `[0.0, 1.0]`.  Setting a weight to
`0.0` disables that signal without a code change.

### Off hot-path guarantee

The scorer is consulted only at login time (form-submit / password-grant flows).
It is **not** on the `validate_token()` or `lookup_session()` hot path.

---

## P-5: `EmailReputation` — Disposable-Domain List + Role-Address Detection

**Status**: Shipped (HEA-1204)  
**Source**: `src/abuse/email_reputation.rs`

### Overview

`EmailReputation` is the P-5 extension point for email-address reputation checks.
The built-in `BuiltinEmailReputation` reference adapter ships with Hearth.
External adapters (Kickbox, ZeroBounce, NeverBounce) implement the trait and
are wired at startup via `security.providers.email_reputation`.

### Verdict flags

| Flag | Meaning |
|------|---------|
| `is_disposable` | Domain matched the bundled (~400-entry) disposable-domain list |
| `domain_has_no_mx` | Domain could not be confirmed to have an MX record (see DNS note) |
| `is_role_address` | Local part is a well-known role address (`noreply`, `admin`, etc.) |

All flags are **advisory** — callers decide policy.  `is_clean()` is true only
when all three flags are false.

### DNS MX validation (stub)

True MX validation requires an async DNS resolver (`hickory-resolver` or
equivalent).  The built-in adapter sets `domain_has_no_mx = false` unconditionally
(assume domain is valid).  To enable real MX checking:

1. Add `hickory-resolver = "0.25"` to `Cargo.toml`.
2. Implement `lookup_mx(domain)` in `BuiltinEmailReputation::check()` using the
   `hickory_resolver::TokioAsyncResolver`.
3. Change the trait signature to `async fn check` (requires `async-trait` or
   native AFIT with a `Box<dyn Future>` return for dyn dispatch).

### Disposable-domain list

~400 entries from well-known community lists (disposable-email-domains project,
ivolo/disposable-email-domains, wesbos/burner-email-providers).  Domain matching
is exact and case-insensitive (domain is lowercased before lookup).  Subdomains
are NOT checked by default — add them via `extra_disposable_domains` if needed.

### Role-address prefixes (RFC 2142 + common additions)

`noreply`, `no-reply`, `no_reply`, `donotreply`, `postmaster`, `hostmaster`,
`webmaster`, `mailer-daemon`, `abuse`, `security`, `admin`, `administrator`,
`root`, `support`, `helpdesk`, `help`, `info`, `contact`, `sales`, `marketing`,
`billing`, `finance`, `hr`, `jobs`, `careers`, `newsletter`, `notifications`,
`alerts`, `bounce`, `bounces`, `unsubscribe`, `feedback`, `system`, `daemon`.

### Config (`security.providers.email_reputation` in `hearth.yaml`)

```yaml
security:
  providers:
    email_reputation:
      extra_disposable_domains:
        - "my-internal-throwaway.example"
```

### Fail-open policy (§6.1)

`EmailReputation` is **fail-open**.  The default shipping configuration uses
`NoopEmailReputation` — no registration is ever blocked until an adapter is
explicitly configured.  External adapter implementations MUST return a
permissive verdict (all flags `false`) on any transport or internal error.

### Off hot-path guarantee

The provider is consulted only at registration, invitation acceptance, and
similar account-creation flows — never during `validate_token()` or
`lookup_session()`.

---

## A-19 — Email-Change Re-Verification Flow

Closes §3.20. Implemented in `src/identity/engine/mod.rs`.

### Contract

When a user requests an email address change, the new address must be verified
via a separate token before the swap is committed:

1. `initiate_email_change(realm_id, user_id, new_email)` — validates and
   normalises `new_email`, checks uniqueness (including the A-20 reservation
   gate), generates a 32-byte cryptographically-random token, stores
   `SHA-256(token)` under `email:change:{hash}`, and emits
   `EmailChangeInitiated` audit.  Returns the plaintext token; the caller is
   responsible for delivering it to `new_email`.

2. `confirm_email_change(realm_id, token)` — looks up the stored record by
   `SHA-256(token)`, enforces a 24-hour expiry and single-use semantics, swaps
   the email indexes atomically, sets `email_verified = true`, revokes all
   sessions, and emits `EmailChangeConfirmed` audit.  Returns the updated
   `User`.  The caller MUST send a `security.email_changed` notification to the
   old address with a revoke link.

### Failure modes

| Error | Condition |
|-------|-----------|
| `EmailChangeTokenInvalid` (`HEARTH_EMAIL_CHANGE_TOKEN_INVALID`) | Token not found, expired, or already consumed. |
| `DuplicateEmail` | New address already registered. |
| `EmailReserved` | New address is under A-20 cooldown. |

### Fail policy

`EmailChangeConfirmed` is a security-critical audit; `FailOperation` is used if
the append fails.  All other operations are `LogOnly`.

---

## A-20 — Deleted-Account Email Reservation (90-Day Cooldown)

Closes §3.21. Implemented in `src/identity/engine/mod.rs`.

### Contract

When `delete_user` completes, it writes a JSON tombstone under
`email:reserved:{normalized_email}` within the same realm's storage namespace:

```json
{ "reserved_at_micros": 1748907483000000 }
```

The tombstone enforces a **90-day cooldown**: `create_user_with_status` and
`initiate_email_change` both check for a live tombstone before accepting the
address.

| Scenario | Result |
|----------|--------|
| Tombstone present and within 90 days | `EmailReserved` (wire: `HEARTH_DUPLICATE_EMAIL`) |
| Tombstone present but expired | Tombstone cleaned up; operation proceeds normally |
| No tombstone | Operation proceeds normally |

### Enumeration resistance

`EmailReserved` shares the same wire error code as `DuplicateEmail`
(`HEARTH_DUPLICATE_EMAIL`).  Callers cannot distinguish "address in use" from
"address under reservation".

### Identity independence

Re-registration after the cooldown creates a **wholly new identity** (new
`UserId`).  No memberships, invitations, sessions, or credentials are
inherited from the deleted account.

---

## A-37 — `prompt=none` Silent-Auth Probe Rate Limit

Closes §3.38. Implemented in `src/protocol/web/oauth_consent.rs` (web layer)
and `src/identity/engine/mod.rs` (counter persistence + audit).

### Attack model

`prompt=none` is a standard OIDC mechanism for silent token refresh, but it
doubles as a low-noise session-existence oracle: an attacker can send repeated
`prompt=none` requests to infer whether a specific subject has an active
session (`consent_required` → logged in; `login_required` → not logged in).

### Contract

Every `prompt=none` authorize request for an authenticated subject increments a
sliding-window counter stored under `rl:prompt_none:{user_uuid}` within the
realm.

| Parameter | Value |
|-----------|-------|
| Window duration | 1 hour |
| Cap per window | 50 probes |
| Counter storage | WAL-persisted JSON (`StoredPromptNoneTracker`) |

- Probes 1–50: the request proceeds normally.
- Probe 51+: the handler returns `error=login_required` (the least-informative
  RFC-defined silent-auth error per OIDC Core §3.1.2.6).
- An `OidcSilentAuthProbed` audit event is emitted on **every** probe,
  regardless of outcome, with `user_id`, `client_id`, `outcome`, and
  `probe_count` metadata.

### Fail policy

Audit emit is `LogOnly` — a failed append does not block the authorization
flow.  The rate-limit counter write is best-effort (`let _ =`); a storage
error does not block the flow either (fail-open per §6.1).

### Window reset

The window clock starts at the first probe.  Once the window expires the
counter resets to zero, and the next probe starts a new window.

### Scope

This counter is per (realm, subject) — each user has an independent counter
in each realm.  There is no cross-realm sharing.


---

## A-9 — Tenant-Managed CIDR Allow/Deny Lists

**Status:** Shipped (HEA-1191)  
**Module:** `src/abuse/cidr`  
**Storage prefix:** `abuse:{realm}:cidr:{allow|deny}:{seq}`

Per-realm IPv4/IPv6 CIDR lists that gate every public auth request.  Loaded
from storage by the admin plane and held in an `Arc<ArcSwap<CidrFilter>>`
for zero-lock hot-path lookup.

### Evaluation order

1. If the source IP matches any entry in the **allow list** → `Allow`.  
   Explicit trust cannot be overridden by the deny list.
2. If the source IP matches any entry in the **deny list** → `Deny`.
3. If the allow list is **non-empty** and the IP is **not** in it → `Deny`
   (strict allowlist mode).
4. Otherwise → `Allow` (fail-open, §6.1).

### Fail-open policy

An empty `CidrFilter` (both lists empty) always returns `Allow`.  This
ensures a misconfigured or missing policy does not lock operators out.

### Configuration surface

```yaml
# Per-realm (hearth.yaml)
realms:
  my-realm:
    security:
      cidr_policy:
        allow:
          - "10.0.0.0/8"
          - "2001:db8::/32"
        deny:
          - "198.51.100.0/24"
```

### Not yet implemented

- Admin UI action ("block this IP") wired to A-9 storage (tracked in
  the A-8 admin-abuse-dashboard stub).
- Reload-on-change without restart (requires `ArcSwap` integration in
  the realm-config reloader).

---

## A-12 — Adaptive Exponential Lockout Backoff

**Status:** Shipped (HEA-1191)  
**Module:** `src/abuse/backoff`

Tracks per-key (IP address or user ID) consecutive lockout events and
escalates the lockout duration on each repeat offense.

### Default backoff schedule

| Offense level | Lockout duration |
|:---:|---:|
| 1st | 1 minute |
| 2nd | 5 minutes |
| 3rd | 30 minutes |
| 4th+ | 24 hours (saturates) |

### Offense counter reset

The offense counter resets to zero after `offense_cooldown` (default 7 days)
has elapsed since the *end* of the most recent lockout.  A patient attacker
who waits exactly for the lockout to expire does not regain a clean slate
until the full cooldown window has passed.

### Configuration surface

```yaml
security:
  adaptive_backoff:
    durations: ["1m", "5m", "30m", "24h"]   # optional; these are the defaults
    offense_cooldown: "7d"                    # optional; default 7 days
```

Setting `durations: []` disables adaptive backoff (fail-open); the existing
flat per-account lockout from `RateLimitConfig` remains active.

### Key format

The backoff key is a free-form string.  Auth handlers use:
- `"ip:{addr}"` for per-IP throttling
- `"user:{user_id}"` for per-account throttling

---

## A-17 — Login-Event Tarpit

**Status:** Shipped (HEA-1191)  
**Module:** `src/abuse/tarpit`

Once a source IP exceeds the failure threshold, every subsequent auth `POST`
from that IP receives a deterministic fixed delay before credential
verification.  The delay is **off the hot path**: `check()` returns
immediately; the caller applies `tokio::time::sleep(delay)`.

### Hot-path contract

`TarpitStore::check()` is:
- Synchronous and allocation-free.
- Holds a `Mutex` only for the duration of a hash-map lookup.
- Completes in ≤1 µs p99; the overall `AbuseGuard::check()` budget is ≤5 µs.

### Fail-open policy

`threshold: None` (the default) means all calls return `Allow`.  The tarpit
does not activate until explicitly configured.

### Configuration surface

```yaml
security:
  tarpit:
    threshold: 5          # failures in `window_secs` before tarpit activates
    window_secs: 60       # rolling window for counting failures
    delay_ms: 200         # deterministic delay (100–500 ms per plan §4.1 A-17)
```

### Relationship to A-16 (Challenge)

A-16 **gates** the request (CAPTCHA required).  A-17 **adds latency** but
does not gate.  Both can be active simultaneously; tarpit fires before the
CAPTCHA check in handler order.

---

## A-43 — gRPC Reflection Production-Disable

### Threat

`grpc.reflection.v1.ServerReflection` exposes the full API schema
(service names, method signatures, request/response types) to any unauthenticated
caller.  In production this is an enumeration and reconnaissance primitive.

### Mitigation

`security.grpc.reflection_enabled` (default `false`) gates the reflection service.

- **`--dev` mode**: defaults to `true` — grpcurl / Postman work out-of-the-box.
- **Production (`null`/absent or `false`)**: service is omitted from the gRPC router entirely; clients that query it receive an "unimplemented" status, not schema data.
- **Production with `true`**: Hearth **refuses to start** unless `--allow-reflection-in-prod` is passed.  The error message is actionable:

  ```
  security.grpc.reflection_enabled = true is not allowed in production mode.
  Pass --allow-reflection-in-prod to override (debugging only; never in real deployments).
  ```

### Fail-closed

The guard is fail-closed.  There is no runtime fallback: if the invariant is violated the process exits before accepting any connection.

### Configuration surface

```yaml
security:
  grpc:
    reflection_enabled: false   # default; omit for production-safe behaviour
```

CLI:

```
hearth serve --allow-reflection-in-prod   # required when reflection_enabled = true in prod
```

---

## A-44 — TLS 0-RTT Disable + mTLS CRL Revocation

### Threat (0-RTT)

TLS 1.3 0-RTT (early data) allows a client to send application data in the first
flight, before the handshake completes.  Because 0-RTT data can be replayed by a
network adversary, any idempotent-appearing endpoint hit with 0-RTT data is
replayable.

### Mitigation (0-RTT)

`rustls` disables 0-RTT by default (`max_early_data_size = 0`).  Hearth asserts
this invariant at server startup:

```rust
assert_eq!(config.max_early_data_size, 0,
    "rustls changed the 0-RTT default — early data must remain disabled");
```

If a future `rustls` upgrade changes the default, the assertion panics at boot
rather than silently permitting replays.  There is no configuration knob to re-enable
0-RTT; operators who require it must modify the source.

### Threat (mTLS revocation)

`WebPkiClientVerifier` without a CRL bundle accepts any certificate signed by the
configured CA, including certificates that have been revoked (e.g. because the
private key was compromised).

### Mitigation (mTLS CRL)

`security.tls.crl_paths` accepts a list of PEM-encoded Certificate Revocation List
files.  When configured:

- Each CRL is loaded at startup and passed to `WebPkiClientVerifier::with_crls()`.
- The verifier checks every client certificate against the union of all CRLs.
- Revoked certificates are rejected with a TLS handshake alert before any
  application data is exchanged.
- Paths are reloaded on `SIGHUP` alongside the server certificate.

### Fail-closed on opt-in

If `crl_paths` is empty (the default), no revocation check is performed — existing
mTLS deployments are not broken.  Once an operator configures paths:

- A missing or unreadable CRL file causes startup to fail.
- A malformed CRL file causes startup to fail.
- A certificate absent from all CRLs is treated as not-revoked (CRL = explicit deny list).

### Configuration surface

```yaml
security:
  tls:
    crl_paths:
      - /etc/hearth/crl/client-ca.crl.pem   # PEM-encoded CRL, reloaded on SIGHUP
```

---

## A-24 — Per-Realm Resource Quotas

### Threat

Without resource caps, a single tenant can fill the disk with users, organizations,
OAuth clients, sessions, or audit rows — denying service to every other realm.

### Mitigation

`RealmConfig.quotas` (`RealmQuotaConfig`) exposes per-realm limits:

| Field | Resource guarded |
|-------|-----------------|
| `max_users` | Total user records in the realm |
| `max_orgs` | Total organizations in the realm |
| `max_clients` | Registered OAuth/OIDC clients |
| `max_sessions` | Total active sessions across all users |
| `max_audit_rows` | Hard audit-row cap (enforced by background pruner) |
| `max_disk_bytes` | Disk-usage warning threshold (sampled, non-blocking) |

All fields are `None` by default (unlimited). When a limit is set, the
corresponding create operation is rejected with `HEARTH_QUOTA_EXCEEDED` (HTTP
429) once `current >= limit`.

### Enforcement

- **Synchronous / fail-closed**: count-based quotas (users, orgs, clients,
  sessions) are checked on every create by scanning the relevant storage prefix.
  A storage scan error is treated as `current = limit` — the create is rejected
  rather than bypassing the quota.
- **Sampled / warn-only**: `max_disk_bytes` is checked once per day by the
  background pruner. Exceeding it emits a `warn!()` but does NOT block writes.
- **Background pruner**: `max_audit_rows` is enforced by the daily pruner after
  the time-based `retention_days` sweep (see A-25).

### Fail-open vs fail-closed (§6.1)

Count-based quotas are **fail-closed**: a storage failure returns `QuotaExceeded`
to prevent unbounded growth even when the storage layer is degraded.

`max_disk_bytes` is **fail-open**: it is advisory only. Operators should pair it
with OS-level disk quotas or alerting for hard enforcement.

### Configuration surface

```yaml
realms:
  my-realm:
    quotas:
      max_users: 10000
      max_orgs: 100
      max_clients: 50
      max_sessions: 50000
      max_audit_rows: 500000
      max_disk_bytes: 10737418240   # 10 GiB (warn-only, sampled daily)
```

---

## A-25 — Audit Auto-Retention + `max_rows` Backstop

### Threat

An event storm (e.g. repeated failed logins, high-frequency token issues) can
exhaust disk by filling the audit log, even when `retention_days` is set.
Without a row-count backstop, a realm can grow unboundedly between daily prune
runs.

### Mitigation

`AuditRetentionConfig` gains a `max_rows: Option<u64>` field. The background daily
pruner (already enforcing `retention_days`) now runs a second pass after the
time-based prune:

1. Count current audit events via `AuditEngine::count_events`.
2. If `count > max_rows`, delete the oldest `(count - max_rows)` events via
   `AuditEngine::prune_oldest`.

The pruner logs `info!` when rows are trimmed:
```
audit prune: max_rows backstop trimmed oldest events realm=X deleted=N max_rows=M
```

### Hash-chain integrity after pruning

Pruning intentionally breaks the hash chain for the removed window. Integrity
verification (`verify_integrity`) should only be run against the retained window
after a prune operation. This is the same design as the existing `prune_before`.

### Configuration surface

```yaml
# Set via API: PUT /admin/realms/{id}/audit/retention
# Body:
{
  "retention_days": 90,
  "max_rows": 500000
}
```

`retention_days = 0` disables time-based pruning. `max_rows = null` disables the
row backstop. Both can be active simultaneously for defence-in-depth.

---

## A-30 — Backup / Export Hardening

**Status:** Implemented (HEA-1206)

### Problem

`/admin/backup`, `/admin/backup/restore`, `/admin/users/export`, and
`/admin/realms/{r}/audit/export` were gated only by `hearth.admin`. A single
compromised admin token could exfiltrate an entire realm in one call with no
rate limit, no secondary capability gate, no audit watermark, and no restore
signature verification.

### Controls implemented

#### A-30.1 Separate `hearth.export` capability

All data-export endpoints (`POST /admin/backup`, `GET /admin/users/export`,
`GET /admin/realms/{r}/audit/export`) now require the caller's token to carry
**both** `hearth.admin` AND `hearth.export` in the `permissions` claim.

- `hearth.export` is seeded in all realms and included in the `realm.admin` role
  by default.
- Operators can grant it to dedicated service accounts (DR pipelines) without
  granting full `hearth.admin`.
- Fail-closed: missing permission → `403 Forbidden`.

#### A-30.2 Per-export rate limit

A dedicated `ExportRateLimiter` (`src/protocol/admin_auth.rs`) enforces a fixed
window of **10 exports per user per hour** (configurable via
`security.backup.export_rate_limit`).

- Exceed the limit → `429 Too Many Requests`.
- Per-user, not per-IP, so rotating IPs does not bypass it.
- Check fires AFTER the capability check, so tokens without `hearth.export` never
  consume quota.

#### A-30.3 Restore archive signature verification

`BackupManifest` gains `detached_signature_b64: Option<String>` — a base64url
Ed25519 signature over `canonical_bytes()` (the manifest JSON with the signature
field set to `null`).

Config:

```yaml
security:
  backup:
    verify_key: "<base64url-encoded 32-byte Ed25519 public key>"
```

Behaviour:
- **Key configured, signature present and valid** → restore proceeds.
- **Key configured, signature absent or invalid** → `400 Bad Request` (fail-closed).
- **Key not configured** → signature field is ignored (backwards-compatible).

The signing tool signs `manifest.canonical_bytes()` with the operator's private
key and writes the result to `detached_signature_b64` before creating the archive.

#### A-30.4 Per-export audit watermark

Every export call (regardless of outcome) emits a `RealmExportWatermarked` audit
event:

| Field | Value |
|-------|-------|
| `action` | `realm_export_watermarked` |
| `resource_type` | `export` |
| `resource_id` | unique export UUID |
| `metadata.export_id` | same UUID (stable lookup key) |
| `metadata.export_type` | `backup` \| `users` \| `audit` |
| `metadata.realm_slug` | present when a realm filter was applied |

The event is emitted **before** the export data is produced so the watermark
exists even when a subsequent step (rate limit, capability, I/O error) fails.

### Fail-open vs fail-closed

| Control | Fail mode | Rationale |
|---------|-----------|-----------|
| `hearth.export` capability check | Fail-closed (403) | Missing permission = no data leaves |
| Per-export rate limit | Fail-closed (429) | Poison-pill on limiter panic drops request |
| Restore signature verification | Fail-closed (400) | Unsigned archive = rejected when key is configured |
| Audit watermark emit failure | Fail-open (log only) | Losing a watermark is better than blocking a valid DR restore |

---

## P-8 — Pluggable SecretsBackend (HSM/KMS)

**Status:** Trait + StorageSecretsBackend + FileSecretsBackend implemented;
KmsSecretsBackend and HsmSecretsBackend are stubs (HEA-1206).

### Problem

Signing keys, encryption-at-rest keys, and Argon2 pepper were stored directly in
the embedded WAL with no abstraction layer. This made HSM/KMS integration
impossible without touching every call site.

### Design

`src/abuse/secrets_backend/mod.rs` defines:

```rust
pub trait SecretsBackend: Send + Sync {
    fn signing_key_der(&self, realm_id: &RealmId) -> Result<Vec<u8>, SecretsError>;
    fn store_signing_key_der(&self, realm_id: &RealmId, der: &[u8]) -> Result<(), SecretsError>;
    fn encryption_key(&self, realm_id: &RealmId) -> Result<[u8; 32], SecretsError>;
    fn pepper(&self) -> Result<[u8; 32], SecretsError>;
}
```

### Adapters

| Adapter | Description |
|---------|-------------|
| `StorageSecretsBackend` | Default. Keys stored in the embedded WAL under the system realm namespace (`realm:key:{uuid}`, `realm:ear:{uuid}`, `sys:secrets:pepper`). Zero-migration upgrade path. |
| `FileSecretsBackend` | Reads/writes raw files from `{root}/signing/{uuid}.der`, `{root}/ear/{uuid}.bin`, `{root}/pepper.bin`. Atomic write via `.tmp` rename. |
| `KmsSecretsBackend` | Stub — all methods return `SecretsError::NotConfigured`. Replace with AWS/GCP KMS SDK adapter. |
| `HsmSecretsBackend` | Stub — all methods return `SecretsError::NotConfigured`. Replace with PKCS#11 adapter. |

### Storage key layout (StorageSecretsBackend)

Stored under the **system realm** (nil UUID) namespace:

```
realm:key:{realm_uuid}   → raw PKCS#8 DER (Ed25519 signing key)
realm:ear:{realm_uuid}   → 32 raw bytes (encryption-at-rest key)
sys:secrets:pepper       → 32 raw bytes (Argon2id pepper)
```

This matches the layout already used by the identity engine, so no WAL migration
is required when adopting `StorageSecretsBackend`.

### Fail-open vs fail-closed

`SecretsBackend` operations are not on the hot path. Any error (missing key,
I/O failure, KMS unavailable) propagates as `SecretsError` and is mapped to an
`IdentityError::Internal` by the call site. The server does not start if the
system realm signing key cannot be loaded at startup.
