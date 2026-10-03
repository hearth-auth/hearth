# Abuse Prevention — Sanitization Contract

This document records the security contract for implemented abuse-prevention
features. See `docs/plans/HEA-1114-abuse-prevention.md` for the full
phase-by-phase threat model.

## What "Shipped" means here

**Shipped** means the guard exists, is constructed from `hearth.yaml` at
start-up, and is consulted on a production request path.

That was not always true. The 2026-08-28 audit (§4.17 finding 9) found eight of
these guards had no constructor anywhere except their own `#[cfg(test)]` block,
and that the config keys documented below had no field to deserialize into —
`security:` denies unknown fields, so pasting a documented block made the server
refuse to boot. Both halves are fixed: the keys parse, `AbuseGuards`
(`src/abuse/runtime.rs`) builds every guard from them at start-up, and
`src/config/security_keys.rs` fails start-up if a `security.*` key is ever added
again without naming the module that reads it.

**Every guard is off by default.** A guard with `enabled: false` (or an absent
threshold) is constructed in its own no-op form rather than skipped, so the
call sites have no conditional branches and the §6.1 fail-open posture is a
property of one constructor rather than of every caller. Upgrading changes no
behaviour until an operator opts in.

Where a guard is consulted:

| Guard | Production call site |
|-------|----------------------|
| A-3 distributed-attack detector | login form, pre-gate |
| A-9 tenant CIDR policy | login form, pre-gate |
| A-16 CAPTCHA challenge state | login form, pre-gate |
| A-4 outbound volume shield | self-service verification and password-reset sends |
| A-50 cross-realm aggregation cap | self-service verification and password-reset sends |
| A-11 risk scorer, A-49 refresh drift check, A-17 login tarpit, P-2 IP reputation, P-3 bot signal, P-5 email reputation | Removed in 3.0.0 |
| A-12 adaptive backoff | `POST /ui/device` approval guard |

"Pre-gate" means before a permit is taken from the Argon2 admission gate, for
the same reason the per-IP rate limit runs there: rejected traffic must not
consume hashing capacity. Every refusal renders the one generic sign-in failure
page, so none of these guards is an account-enumeration oracle.

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

## P-2 — IP Reputation

**Status:** Removed in Hearth 3.0.0. A `security.ip_reputation` block stops startup; use the per-IP rate limits and the A-16 CAPTCHA challenge.

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
2. Apply a challenge response (A-16 CAPTCHA).
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

## A-4 — Outbound Email Volume Shield

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
send.  (The SMS caps were removed in Hearth 3.0.0 with SMS one-time codes.)

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

---

## A-50 — Cross-Realm Email Aggregation Cap

**Status:** Shipped (HEA-1201)  
**Module:** `src/abuse/detector` → `CrossRealmAggregationCap`  
**Closes:** §3.53 of the abuse-prevention plan

Complements A-4's per-realm volume shield by tracking how many **distinct
realms** have sent to the same recipient across the entire cluster.  An
attacker who splits sends across N realms to evade A-4's per-realm budget is
caught here.

### Threat closed (§3.53)

A-4 caps *per-realm* distinct recipients per hour.  Without A-50, an attacker
controlling 50 realms can target the same `victim@example.com` from each, staying
below A-4's per-realm threshold while flooding the victim.  A-50 detects the
cross-realm pattern and escalates.

### Outcome and caller contract

| Outcome | `realm_count` | Required caller action |
|---------|--------------|------------------------|
| `Allow` | — | Proceed with send |
| `MultiRealmAlert { realm_count }` | ≥ `alert_threshold` | Emit `AbuseDetected` audit + A-7 webhook; MAY still send |
| `SoftCap { realm_count }` | ≥ `email_realm_soft_cap` | MUST apply CAPTCHA or queue; SHOULD emit audit + webhook |
| `HardCap { realm_count }` | ≥ `email_realm_hard_cap` | MUST reject send (HTTP 429); MUST emit audit + webhook |

Callers MUST NOT surface the `realm_count` value to the sending realm or to
any external client.

### Privacy

Recipient addresses and realm IDs are stored only as `SipHash-1-3` hashes
(`u64`).  No plaintext is retained in memory.

### Fail-open policy

Per §6/§6.1: lock poisoning returns `CrossRealmOutcome::Allow`.  A-4
per-realm caps and A-2 request shaper remain backstops.

### Integration point

Call **in addition to** `OutboundVolumeShield::check_email`.
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
```

The SMS caps (`sms_realm_soft_cap` / `sms_realm_hard_cap`) were removed in Hearth 3.0.0.

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

## A-49 — Refresh-Token Context Binding

**Status:** Drift scoring removed in Hearth 3.0.0.

The User-Agent/ASN drift check that fed the A-11 risk scorer was removed with
it. Refresh tokens keep their DPoP key binding (RFC 9449) and their binding to
the confidential client they were issued to; rotation and family-hash replay
detection are unchanged.

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

**Threat**: A client registered with `dpop_bound_access_tokens: true` (RFC 9449
§5.2) calls a token grant without a DPoP proof. The issued token would be
sender-unconstrained (a bearer token any party can replay), defeating the
client's declared binding.

**Implementation**:

Every access-token-issuing grant in `src/identity/engine/oauth.rs` and
`src/identity/engine/mod.rs` — authorization code, refresh, client
credentials, JWT bearer and device code — calls the same gate before issuing:

```
require_dpop_for_bound_client(client, request.dpop_jkt)
  if client.dpop_bound_access_tokens() && dpop_jkt.is_none()
  → return Err(InvalidDPopProof)   // wire: invalid_dpop_proof
```

A token issued with a proof carries `cnf.jkt` and `token_type: DPoP`.

**Fail mode**: Fail-closed for `dpop_bound_access_tokens` clients; for other
clients DPoP remains optional (a proof, when sent, still binds the token).

**RFC references**: RFC 9449 §5.2 (`dpop_bound_access_tokens` client
metadata) and §5 (DPoP access token request); RFC 6749 §4.4 (client
credentials grant).

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

**Residual risk**: None open. RFC 8693 token exchange is implemented and enforces
`MAX_ACT_CHAIN_DEPTH` at `src/identity/engine/mod.rs` (call site: `act.depth() >
crate::abuse::MAX_ACT_CHAIN_DEPTH`). Regression coverage lives in `tests/abuse_dpop_act.rs`
and `tests/token_exchange.rs` (delegation depth + nested `act` chain tests).

---

## A-11 — Step-up MFA Risk Scorer

**Status:** Removed in Hearth 3.0.0. A `security.risk_scorer` block stops
startup. MFA is a plain per-realm policy (`mfa_required`), never a risk score.

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
  (HTTP 400, wire code `HEARTH_FEDERATION_IDP_MIXUP`).
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

| Mechanism | Trigger | Effect on read path | Audit event |
|-----------|---------|---------------------|-------------|
| Read-path rejection | `get_session()` / `get_session_arc()` encounters a policy-expired session | Returns `None` (fail-closed); removes session from hot-tier in-process cache | None — audit is deferred |
| Background eviction sweep | `sweep_expired_sessions()` driven by cleanup task | Marks session revoked in storage, bumps session version | `session_evicted` |
| `refresh_session()` | Called on a policy-expired session | Returns error; no write | None |

**Important (HEA-1774):** The `session_evicted` audit event is emitted **only** by the background sweep, not by the read path. When `validate_token` or `lookup_session` rejects an A-18-expired session, the caller receives a `401` immediately (fail-closed), but the storage revocation record and audit entry arrive on the next background sweep cycle. This keeps the token-validation hot path free of storage writes.

**Idle timeout**: Session rejected if `now ≥ last_refreshed_at + idle_timeout_secs`.
Reset on each `refresh_session()` call.

**Absolute timeout**: Session rejected if `now ≥ created_at + absolute_timeout_secs`.
Never reset — unaffected by refreshes.

Both deadlines are embedded in the `Session` record at creation time so the
hot-path `get_session()` avoids a realm config lookup on every call (zero-alloc
arithmetic only).

**Fail-open** (§6.1): when neither timeout is configured (the default), the
existing TTL governs. Removing a timeout config does not retroactively evict
existing sessions — sessions created with embedded deadlines continue to enforce
those deadlines until they naturally expire via TTL or explicit revocation.

### `session.evicted` audit event

Emitted by `sweep_expired_sessions()` (background cleanup loop), not by the
read path. A rejected session may not have its audit record until the next sweep
cycle (typically within seconds, depending on cleanup task cadence).

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

## P-3 — Bot Signals; P-5 — Email Reputation

**Status:** Removed in Hearth 3.0.0. A `security.providers` block stops startup; use the per-IP and per-account rate limits and the A-16 CAPTCHA challenge.

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

Per-realm IPv4/IPv6 CIDR lists that gate every public auth request.  The
realm's `security.cidr_policy` is compiled into a `CidrFilter` on each
pre-auth check (`abuse::runtime::compile_filter`); no shared cell holds it.

### Evaluation order

Evaluation is deny first, then allow: a `deny` match refuses outright;
otherwise a non-empty `allow` list refuses every address it does not
contain. Both lists empty means no network restriction.

1. If the source IP matches any entry in the **deny list** → `Deny`, even when
   it is also inside the allow list (a deny exception in an allowed range).
2. If the allow list is **non-empty** and the IP is **not** in it → `Deny`
   (strict allowlist mode).
3. Otherwise → `Allow` (fail-open, §6.1).

Deny-first loses no expressible policy — a non-empty allow list already
refuses everything outside it — and it is the only order in which a deny entry
inside an allowed range has any effect. (Until the 2026-09-28 G3 follow-up the
code let an allow match override deny, contradicting CONFIGURATION.md.)

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
- Reload-on-change without restart (requires a hot-swapped holder, such as
  `core::SwapCell`, in the realm-config reloader).

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

**Status:** Removed in Hearth 3.0.0. A `security.tarpit` block stops startup; use the A-12 adaptive backoff, the per-IP rate limits and the A-16 CAPTCHA challenge.

---

## A-43 — gRPC Reflection Production-Disable (retired in 3.0.0)

Hearth 3.0.0 removed the public gRPC API, and with it the gRPC reflection service
this control gated. There is no reflection endpoint to enumerate. The
`security.grpc.reflection_enabled` key and the `hearth serve --allow-reflection-in-prod`
flag are gone; a configuration that still sets `security.grpc` refuses to start with an
error naming the removed key (see `CONFIGURATION.md`).

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
# Set via API: PUT /admin/api/realms/{realm}/audit/config
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
`GET /admin/realms/{r}/audit/export`) and `POST /admin/backup/restore` require
the caller's token to carry `hearth.export` **in addition to** an admin
permission in the `permissions` claim — `hearth.admin`, or the sub-admin
permission the endpoint accepts. Two operations require `hearth.admin` itself,
and refuse a sub-admin plus `hearth.export` (`403`):

- **Every backup restore.** A restore writes users and credentials, clients,
  roles and role assignments, agents and retiring signing keys at once — every
  sub-admin domain, and no sub-admin permission is a superset of the others. A
  tenant sub-admin could otherwise bring back, from a signed archive of its own
  realm, a role assignment an administrator revoked (live role management needs
  `hearth.realm.admin`), or clients and keys its permission never reaches.
- **A backup export by a system-realm caller**, which is not scoped to one
  realm (it reaches every realm, operator accounts and the system signing key
  included).

Both permission checks run before the per-export rate limit (A-30.2), so a
refused caller sees `403`, never `429`, and spends no quota.

- `hearth.export` is seeded in all realms and included in the `realm.admin` role
  by default.
- Operators can grant it to dedicated service accounts (DR pipelines) that
  **export** a tenant realm without granting full `hearth.admin`; a service
  account that backs up every realm from the system realm, or that restores
  any realm, needs `hearth.admin`.
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

Behaviour (`crate::backup::check_restore_signature`, shared by the HTTP route
and `hearth backup restore`):
- **Key configured, signature present and valid** → restore proceeds.
- **Key configured, signature absent or invalid** → refused (`400 Bad Request`
  over HTTP with `error` = `missing_manifest_signature` or
  `invalid_manifest_signature`, exit `2` on the CLI). Nothing overrides a
  configured key, and the CLI refuses `--skip-verify` alongside one: the
  signature covers only the manifest, and members are authenticated solely by
  the manifest checksums that flag would skip.
- **Key not configured** → refused outside dev mode (`error` =
  `backup_verify_key_not_configured` over HTTP). The HTTP route has no
  override; the CLI accepts `--allow-unsigned` as an explicit operator opt-in.
  A `--dev` server restores with a warning.

Both restore paths read the archive through one private, unlinked copy, so the
bytes imported are the bytes whose signature and checksums were verified — the
input path is never reopened between the check and the import.

Signing: `hearth backup create --sign-key <key.pem>` or `hearth backup sign`
signs `manifest.canonical_bytes()` with the operator's Ed25519 private key
(`hearth backup keygen` generates one) and writes the base64url result to
`detached_signature_b64`. `checksums` is an ordered map so the canonical bytes
are identical for signer and verifier.

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
