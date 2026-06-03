# Abuse Prevention — Sanitization Contract

This document records the security contract for tenant-supplied content that
Hearth renders without HTML escaping. See `docs/plans/HEA-1114-abuse-prevention.md`
for the full Phase-0 threat model.

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

**Source**: `src/identity/risk.rs`

Aggregates risk signals at login time into a normalised score `[0.0, 1.0]`.
When `score >= step_up_threshold` (default `0.5`), the login handler returns
`IdentityError::StepUpChallengeRequired` — the same gate as the existing
device-fingerprint step-up.

### Signals

| Signal | Default weight | Source |
|--------|---------------|--------|
| `NewDevice` | 0.3 | Device-fingerprint miss (`src/identity/device_fp`) |
| `NewCountry` | 0.4 | GeoIP lookup — **stub until HEA-1205** |
| `PasswordAge { days }` | 0.2 (if `days >= threshold`) | `user.created_at()` (approximation) |
| `BreachCorpusHit` | 1.0 (forces step-up) | HIBP / offline corpus — **stub at login until HEA-1205** |

### Config (`security.risk_scorer` in `hearth.yaml`)

```yaml
security:
  risk_scorer:
    enabled: true          # default: false (fail-open)
    step_up_threshold: 0.5 # score >= this → step-up
    new_device_weight: 0.3
    new_country_weight: 0.4
    password_age_weight: 0.2
    password_age_days_threshold: 365
    breach_corpus_weight: 1.0
```

**Fail mode**: Fail-open. When disabled (`enabled: false`, the default) score
is always `0.0` so existing deployments are unaffected. Scoring errors are
suppressed and treated as `score = 0.0`.

**Extension point (P-4)**: The `RiskScorer` trait in `src/identity/risk.rs` is
the hook for HEA-1205 pluggable adapters (vendor ML models, remote risk APIs).

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

**File**: `src/identity/sessions.rs`, `src/identity/engine/mod.rs`, `src/identity/types.rs`

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
