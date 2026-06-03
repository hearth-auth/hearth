# HEA-1114 — Abuse Prevention: Audit & Plan

**Status:** Draft plan rev3 (planning-only heartbeat, no implementation)
**Owner:** CTO
**Updated:** 2026-06-03 (rev3 — third-pass gap sweep; see §10 for diff vs rev2; §9 for rev2 vs rev1)

## 1. Goal

Make Hearth rock-solid against credential attacks, bots, scrapers, resource
exhaustion, billing abuse (email/SMS pumping), and common OWASP attack vectors —
while keeping the hot path zero-allocation and operators able to tune policy
per realm without recompiling. Ship a coherent **abuse policy plane**, not a
pile of ad-hoc checks.

## 2. What Hearth already does (audit)

The codebase is unusually mature for pre-1.0. The following protections are
already implemented and exercised by tests:

### Credential & account
- Per-IP failed-login sliding-window rate limit + per-account
  consecutive-failure lockout (`RateLimitConfig` in `src/identity/engine.rs`,
  YAML under `security.rate_limiting`).
- Constant-time dummy-hash verification on missing users to flatten timing
  (`engine.rs::~3894`).
- Argon2id password hashing off the hot path; PBKDF2 verify-only for
  Keycloak-imported credentials.
- HIBP k-anonymity breach check on password set/change
  (`src/identity/hibp.rs`, `src/identity/breach_corpus.rs`, opt-in per realm).
- TOTP brute-force lockout (5 attempts / 5 min) + replay protection
  (per-time-step single-use).
- SMS OTP resend throttle (15 min window, max 5 sends per phone).
- Magic link per-IP + per-account rate limit; enumeration-resistant 202
  responses.
- WebAuthn counter-replay rejection, RP-ID validation, tampered
  clientDataJSON detection.

### Enumeration resistance
- `register_user` returns synthetic `UserId` on duplicate email.
- `forgot_password`, `magic_link_request`, `get_session`, `get_user`
  cross-realm — all conflate not-found / forbidden / expired into a single
  `Ok(None)` or generic error variant.
- Realm 404 vs 403 indistinguishable.

### OAuth/OIDC
- PKCE **mandatory** for all clients including confidential (RFC 9700 §2.1.1,
  `oidc.require_pkce_for_confidential_clients` defaults true).
- Non-empty `state` enforced (CSRF).
- Per-`(realm, client)` token endpoint rate limit returning `429 +
  Retry-After` (F-06, `tests/security_phase_b.rs`).
- Refresh token rotation with grant-family theft detection (mismatch → revoke
  family + session).
- Device-code polling rate limit (`slow_down`), 8-char user codes from
  unambiguous alphabet.
- `jti` claim + JTI-blocklist for sessionless client-credentials revocation.

### Transport & headers
- TLS 1.3 only, weak ciphers rejected, downgrade prevention.
- mTLS support for `/admin/*`.
- `Secure` + `HttpOnly` + `SameSite=Lax` cookies (auto-secure under TLS).
- CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy on UI routes
  (F-03).
- CORS scoped per-client redirect-URI base origin (F-05) — no wildcards.
- `DefaultBodyLimit` (1 MiB) on JSON endpoints (F-04).

### Tenant & cross-cutting
- Realm-scoped storage keys → no cross-tenant leak by construction.
- OWASP rightmost-non-trusted XFF parser (`src/protocol/client_info.rs`),
  default = peer IP, only trusts explicit `server.trusted_proxies`.
- Tamper-evident hash-chained audit log per realm.
- Zeroize-on-drop for passwords, tokens, signing keys; `Debug`/`Display`
  redacted.
- Error sanitization (`tests/cross_cutting_phase1.rs::assert_no_leaks`).

### UI
- CSRF double-submit cookie (`hearth_ui_csrf`) with constant-time compare,
  enforced on every mutating UI POST.
- OAuth consent ticketing with cross-user replay rejection.

## 3. Where the gaps are

Even with the above, an attacker has unmitigated levers. Grouped by threat,
ordered by P0/P1/P2:

### P0 — Bots, volumetric, billing abuse
1. **No bot signal / proof-of-work / CAPTCHA hook.** Anything publicly
   POSTable (`/v1/{realm}/users/register`, `/v1/{realm}/auth/magic-link`,
   `/v1/{realm}/auth/forgot-password`, `/v1/{realm}/auth/sms-otp`,
   self-service org invite acceptance) can be hit at line rate by a botnet.
   Per-IP limits help against single-IP attackers but do nothing against
   residential-proxy / distributed botnets.
2. **No email/SMS pumping shield.** A single tenant can attack a *third*
   party (the email/SMS recipient) at provider expense — the existing
   per-phone/email throttles cap repeat targets but not breadth (10k distinct
   targets/hour from one tenant is allowed).
3. **No global request shaper.** Per-(realm, client) token endpoint limit
   exists, but `/v1/oidc/discovery`, `/v1/{realm}/jwks`, `/v1/{realm}/userinfo`,
   `/admin/*`, gRPC, and the entire `/ui/*` surface have no per-IP or
   per-tenant volume cap. Slow-loris / connection-flooding has no defense
   beyond OS-level `SO_BACKLOG`.
4. **No suspicious-pattern detection.** Credential stuffing across a *list*
   of usernames (one attempt each, never tripping per-account lockout) is
   undetectable today. Same for "low-and-slow" password spraying paced to
   stay under the IP window.

### P1 — Tenant policy & operator visibility
5. **No abuse-policy plane.** Limits are configured per-feature in YAML.
   There is no single per-realm `abuse_policy` (with reputation thresholds,
   bot-signal requirements, allow/deny lists, geo policy) that handlers can
   consult uniformly.
6. **No IP/ASN reputation or denylist hook.** No way to plug in MaxMind,
   AbuseIPDB, Spamhaus DROP, or a tenant-managed blocklist. Tor/known-VPN
   exit nodes pass freely.
7. **No anomaly/risk scoring on login.** Adaptive-MFA scaffolding exists in
   `oidc.rs` (device-fingerprint step-up) but there is no signal aggregator
   (new-country login, impossible travel, new-device, breach-corpus
   hit-rate, time-of-day anomaly).
8. **No abuse dashboard / incident view.** Audit log carries the data but
   there is no `/ui/admin/realms/{id}/abuse` page surfacing rate-limit hits,
   lockouts, top failing IPs, suspicious-pattern counters, or a one-click
   "block this IP/ASN/subnet" action.
9. **No webhook for security events.** Operators can't fan out
   `LoginFailed`/`PasswordCompromised`/`RateLimited` to a SIEM, Slack, or a
   custom WAF without polling audit.

### P2 — Hardening & edges
10. **`/admin/bootstrap` is dev-only but easy to leave on.** Worth a hard
    refusal in non-dev unless an explicit `--allow-bootstrap-in-prod` flag is
    passed.
11. **Magic-link / verification tokens have generous TTLs (default 30 min /
    7 days).** Per-tenant TTL caps already exist, but no policy guard prevents
    operators choosing an unsafe default.
12. **No proof-of-possession / DPoP for refresh tokens.** Refresh tokens
    today are bearer tokens; theft-detection catches reuse *after* the fact.
13. **JWKS / discovery cacheability.** Currently public, no per-IP cap.
    Trivially weaponized as a cache-busting amplification target if any
    attacker can append `?cb=<rand>`.
14. **WebAuthn attestation policy.** Hearth accepts any attestation; a
    "phishing-resistant credentials only" policy switch (no `none`/self
    attestation, allowlisted AAGUIDs) is not exposed.
15. **gRPC has no analog to the HTTP rate limiter.** Same surface, same risk.
16. **Slug squatting on realm/org create.** No reserved-name list, no
    cooldown after deletion → squatting `admin`, `support`, `<celebrity>`.
17. **No body limit on the migration import endpoint** by design (large
    Keycloak exports); but it has no rate limit either.
18. **No CAPTCHA-of-last-resort on UI login** when an IP is hot but not yet
    locked — currently a hot IP can keep guessing right up to the threshold.

### P0 — Second-pass gaps (rev2, 2026-06-03)

19. **No session lifecycle policy.** No `max_sessions_per_user`, no idle
    timeout, no absolute timeout. Refresh-token rotation catches theft only
    *after* replay. A stolen long-lived cookie/refresh can run indefinitely;
    a single user can open thousands of sessions to exhaust per-realm session
    storage. Search of `src/identity/sessions.rs` + `engine.rs` for
    `max_sessions|idle_timeout|absolute_timeout` returned zero hits.
20. **Email change has no dedicated re-verification.** `src/identity/engine/mod.rs:6337`
    flips `email_verified = true` inline; there is no "verify new address
    before swap" flow. An attacker with a short session window can pivot to
    permanent control via email change → forgot-password.
21. **Deleted-account email reuse.** No cooldown / reservation when an
    account is deleted and the same email re-registers; historic invitations
    and audit references may attach to the new identity.
22. **Inbound JSON parse bombs.** Multiple admin endpoints accept
    `axum::Json<serde_json::Value>` (e.g. `realms.rs:1728`). `DefaultBodyLimit`
    caps compressed bytes; nothing caps depth or array length post-parse.
    Untyped `Value` parses bypass typed-struct limits.
23. **Decompression-bomb on inbound bodies.** `Content-Encoding: gzip`
    requests have no post-decode cap. The 1 MiB body limit is on the
    compressed stream.
24. **Pagination has no trait-level hard cap.** Handlers pass `10_000` to
    `list_realms`, `list_users` (`handlers.rs:1888`, `:1900`, `:1909`).
    Adversary can request page-size in the millions if any caller forwards a
    user-supplied limit; trait does not refuse.
25. **No per-tenant resource quotas.** `RealmConfig` documents an explicit
    "unlimited" default (`types.rs:863`). One tenant can fill the disk with
    users/orgs/clients/audit rows, denying service to all.
26. **Audit retention is manual only.** `prune_before` exists at
    `src/audit/engine.rs:291`; no automatic retention window, no per-realm
    cap on audit rows, no disk-pressure backstop.
27. **`/metrics` has no authentication.** `src/protocol/http.rs:603` registers
    `/metrics` GET with no auth extractor; `metrics_handler` at line 1055
    enumerates per-realm volumes — unauthenticated cardinality leak.
28. **PII / token-bearing URLs in logs.** `handlers.rs:2498`
    `tracing::warn!(reset_url = %reset_url, "password reset URL …")` logs the
    full one-shot reset URL when no email transport is configured. Any
    deployment shipping `warn` to a SIEM leaks the bearer-equivalent token.
29. **Slug & invitation TOCTOU.** A-5 covers reserved-list / cooldown but
    not the atomic compare-and-swap needed against concurrent acquisition;
    same applies to one-shot `accept_invitation` double-spend.
30. **Federation IdP-mixup & unverified-email account-linking.** OIDC + SAML
    + GitHub federation paths exist (`src/identity/federation/`). SAML SP at
    `sp.rs:130` defaults `email_verified: false`; OIDC at `oidc.rs:500`
    falls back to `false`. No RFC 9207 `iss` check enforcement, no audience
    pinning policy, no explicit "never auto-link to a local account on an
    unverified upstream email" rule.
31. **Backup / export blast radius.** `/admin/backup`, `/admin/backup/restore`
    (4 GiB body), `/admin/users/export`, `/admin/realms/{r}/audit/export` and
    `export_all_credentials` are gated by admin role only. A compromised
    admin token exfiltrates a whole realm in one call; restore archive is
    not signature-verified. No rate limit, no separate "export-grade"
    capability, no per-export audit watermark.
32. **Hardcoded 60s JWT clock skew, not per-realm.**
    `engine/mod.rs:119` and `federation/oidc.rs:440` hardcode 60s leeway.
    A flaky federated IdP cannot have a wider tolerance; a strict tenant
    cannot have a narrower one.
33. **`trusted_proxies` config has no wildcard guard.**
    `src/protocol/web/mod.rs:154` accepts `Vec<IpAddr>` without startup
    refusal of `0.0.0.0` / `::` / loopback-as-trusted. Operator footgun:
    one wildcard entry hands XFF spoofing to the public.
34. **Delete-cascade amplification.** `delete_realm` synchronously scans
    11 key prefixes (per MEMORY). One DELETE on a large realm = a write
    storm; no chunking, no backgrounding, no per-realm "deletion in
    progress" guard exposed to the dashboard.
35. **Consent page lacks `frame-ancestors 'none'`.** Global CSP (F-03)
    doesn't pin the consent surface specifically; consent ticket lacks an
    explicit cross-realm-bound check beyond user pinning.
36. **SCIM PATCH bulk-op cap absent; SAML XXE / sig-wrap defenses implicit.**
    `src/protocol/scim/types.rs:279` parses `PatchOp` with no `Operations`
    count cap. SAML c14n exists but no exposed entity-expansion cap.
37. **AGENT_AUTH partial-shipped surface.** Per CLAUDE.md / AGENT_AUTH.md,
    Agent entity / delegation / MCP / approval / AATs are NOT YET
    IMPLEMENTED. Need an explicit startup refusal if operator enables an
    `agent_auth.enabled = true`-style config switch before those land.
38. **OIDC `prompt=none` silent-auth probing.** No per-(realm, subject) cap
    on `prompt=none` outcomes; usable as a low-noise session-existence oracle.
39. **PAR / `request_uri` SSRF surface (FAPI track).** `oidc.rs:158` JAR
    JWKS URI is "stored for future use." When PAR / JAR land, the
    `request_uri` fetcher needs an explicit host allowlist & SSRF guard.
40. **Token-exchange (RFC 8693) `act` chain depth & DPoP coverage gaps.**
    `mod.rs:476-478` documents `cnf.jkt` on *refreshed* access tokens; no
    equivalent guard on `client_credentials` / token-exchange access
    tokens, and no maximum `act` actor-chain depth.
41. **Test-quality gate.** Plan §5 mentions `tests/abuse_*.rs` but does not
    enumerate required adversarial scenarios per feature ID. Risk: controls
    ship without negative cases.

### P0 — Third-pass gaps (rev3, 2026-06-03)

42. **HTTP/2 rapid-reset (CVE-2023-44487).** No `max_concurrent_streams`
    or per-conn RST budget visible (`http2-rapid-reset` grep returned no
    output). Per-IP req-rate (A-2) doesn't see stream RST patterns.
43. **No `Host` header / SNI allowlist.** `host-header-allowlist` grep
    returned no output. DNS rebinding against `127.0.0.1:8420` or a
    misconfigured public binding can present arbitrary `Host` values; issuer
    and cookie-domain scope are assumed but unverified at the request edge.
44. **Session-id not rotated on auth events.** No `rotate_session` /
    `regenerate_session_id` paths. `complete_login` at
    `src/protocol/web/federation.rs:528` calls `create_session` without
    invalidating any pre-existing session cookie → classic session-fixation
    surface (also MFA step-up, federation linking, password-change).
45. **Password change does not revoke other sessions or refresh families.**
    `change_password` / `set_password` impls at `src/identity/engine/mod.rs:3900,4145`
    do not reference session revocation or refresh-family invalidation.
    A phished session survives the victim's password rotation.
46. **gRPC reflection enabled unauthenticated.** `src/protocol/grpc/mod.rs:28`
    documents `grpc.reflection.v1.ServerReflection | unauth`;
    `server.rs:89,107` adds the reflection service unconditionally.
    Attacker enumerates the entire RPC surface for free.
47. **TLS 0-RTT replay & no OCSP/CRL for mTLS client certs.**
    `src/protocol/tls.rs:282` `with_client_cert_verifier` has no OCSP/CRL
    plumbing. Revoked admin client certificates continue to authenticate;
    if 0-RTT is on, idempotent requests are replayable.
48. **Tenant-controlled email branding HTML/SVG injection.**
    `src/identity/email/templates.rs:629` comment explicitly notes "inline
    SVG should appear as raw markup (not HTML-escaped)". Tenant admin sets
    `EmailBranding.custom_html` → rendered into emails of that realm's
    users; if cross-realm rendering is ever possible, phishing-with-victim-branding
    is trivial. Same risk applies to any unescaped Askama/Tera variable
    populated from tenant input.
49. **Argon2 pepper has no rotation story.**
    `src/identity/credentials.rs:194` handles parameter rehash but no
    `pepper_version` field or dual-pepper verify path. Pepper compromise
    forces a single-shot invalidation of all credentials with no graceful
    migration.
50. **No `deny_unknown_fields` on admin/auth JSON shapes.** Across the
    codebase, zero `#[serde(deny_unknown_fields)]` hits. Newer client fields
    are silently dropped on the server (downgrade replay potential); admin
    extension fields slip past typed structs into permissive `Value` shapes.
51. **OAuth `state` not cryptographically bound to caller's session.**
    Consent ticket binding exists (`oauth_consent.rs:553,573`) for the
    consent flow, but federation start at
    `src/protocol/web/federation.rs:100` stores `bag` without binding
    `state` to the originating UI session cookie. Login-CSRF / state-reuse
    surface remains.
52. **Refresh-token replay across UA/IP unflagged.** Refresh exchange has
    no UA/IP fingerprint binding; rotation catches replay-after-rotation
    but not "stolen token replayed from a wholly different network context."
    A-11 risk scorer is login-only.
53. **Cross-realm SMS phone-number aggregation absent.** A-4 caps per-realm
    breadth; the same `+1...` can be hit from 50 distinct realms to slip
    past the 15-min per-phone cap. `phone-number-cross-realm` grep returned
    no output.
54. **Audit log has no external attestation / sealing.**
    `src/audit/mod.rs:34,54` describe an append-only SHA-256 hash chain;
    integrity verification only proves *self*-consistency. A compromised
    storage layer that rewrites both payload and chain looks valid. A-30
    signs backups; the live audit stream is not anchored or detach-signed.
55. **`return_to` open-redirect on federation/SAML.** `sanitize_return_to`
    is used in `handlers.rs:807,932`, but SAML at
    `src/protocol/web/saml.rs:222` calls
    `Redirect::to(bag.return_to.as_deref().unwrap_or("/ui/account"))`
    with no sanitizer; federation at `federation.rs:98,541` passes the
    string raw. `return_to=//evil.com` slips through.
56. **No COOP / COEP / Permissions-Policy headers; cookies lack
    `__Host-`/`__Secure-` prefixes or `Partitioned` for CHIPS.**
    `security-headers-extras` grep showed only HSTS at `security.rs:21`.
    Cross-window-opener leaks and cross-site cookie ambiguity remain
    addressable but unaddressed.

> Note: rev2 listed DPoP nonce challenge as a gap. Re-check confirmed
> `src/identity/dpop.rs:363-475` + `protocol/http.rs:2119` already
> implement server-issued DPoP nonces. A-38 stands for *token-exchange*
> actor-chain depth + `cnf.jkt` on `client_credentials` access tokens;
> DPoP nonce coverage itself is already shipped.

> Note: rev2 §3.32 referenced 60s clock-skew as "hardcoded." Closer read
> shows existing config field at `engine/mod.rs:119` ("Maximum tolerated
> clock skew between issuer and validator, in seconds") with the 60s
> default. A-31 is still needed because **federation** path at
> `federation/oidc.rs:440` hardcodes 60s separately; first-party already
> reads from config. Plan retains A-31 but scoped to federation only.

> Note: rev2 §3.37 AGENT_AUTH guardrail is corroborated by MEMORY
> (`feedback_verify_complete_claims.md`).

## 4. Proposed work — built-in + pluggable split

The unifying design idea: introduce an **AbusePolicy** trait that every
publicly reachable handler consults via a small `AbuseGuard` middleware.
Built-in defaults ship in `src/abuse/`. Operators can swap in pluggable
adapters (CAPTCHA provider, IP reputation feed, ML risk scorer) via config
without touching handler code.

### 4.1 Built-in (ships in Hearth core)

| ID | Feature | Layer | Notes |
|----|---------|-------|-------|
| A-1 | **`AbuseGuard` middleware + `AbusePolicy` trait** | `src/abuse/` (new) | Per-realm policy struct, hot-path safe (Arc-swap on reload, zero-alloc lookup). Every public handler calls `guard.check(ctx)` returning `Allow` / `Challenge` / `Deny(reason)`. |
| A-2 | **Global request shaper** | `src/protocol/http.rs` middleware | Per-IP + per-realm token-bucket on *all* public routes (configurable; default off-tier: 100 rps/IP, 1000 rps/realm). Tower `tower::limit::ConcurrencyLimit` for connection cap. |
| A-3 | **Distributed-attack detector** | `src/abuse/detector.rs` | Cardinality sketch (HyperLogLog or count-min) per realm of *distinct usernames tried per IP per window* and *distinct IPs hitting one username per window*. Trips `Challenge` at threshold; emits `AbuseDetected` audit. |
| A-4 | **Volume / breadth limiter for outbound email & SMS** | `src/identity/email/` + `src/identity/sms.rs` | Per-realm rolling window of distinct recipients/hour. Hard cap + soft cap (soft = require operator approval). Closes the email-pumping hole. |
| A-5 | **Reserved-name + cooldown registry** | `src/identity/realms.rs`, `src/identity/orgs.rs` | YAML-driven reserved list (`admin`, `api`, `support`, `www`, …) + 30-day post-delete cooldown for slugs. |
| A-6 | **Hardened bootstrap guard** | `src/main.rs` | Refuse `/admin/bootstrap` unless `--dev` *or* explicit `--allow-bootstrap-in-prod` + warning log. |
| A-7 | **Security webhook channel** | `src/identity/webhooks.rs` (exists) | Add `security.*` event family: `login.failed`, `account.locked`, `abuse.detected`, `password.compromised`, `rate_limit.exceeded`. Operator wires Slack/SIEM/WAF. |
| A-8 | **Admin abuse dashboard** | `src/protocol/web/admin/abuse.rs` (new) | `/ui/admin/realms/{id}/abuse`: live counters, top failing IPs, recent lockouts, one-click block/unblock, ASN view, geo heat-map (server-rendered). |
| A-9 | **Tenant-managed allow/deny lists** | new storage prefix `abuse:{realm}:cidr:*` | IPv4/IPv6 CIDR allow + deny lists, evaluated in `AbuseGuard`. Per-realm. |
| A-10 | **JWKS / discovery query cap** | reuse A-2 | Per-IP `60 rps` default; serve from in-memory `Arc<bytes>` no allocation. |
| A-11 | **Step-up MFA risk scorer** | `src/identity/risk.rs` (new) | Aggregates signals (new-country, new-device, password-age, breach-corpus history). Threshold triggers MFA on next login. Pluggable signal sources via trait. |
| A-12 | **Adaptive lockout backoff** | extend `RateLimitConfig` | Exponential backoff (1m → 5m → 30m → 24h) on repeat-offender IPs/accounts. Today's flat lockout duration is brittle. |
| A-13 | **WebAuthn attestation policy** | `src/identity/webauthn.rs` | Per-realm: `none` allowed Y/N; AAGUID allowlist; PRF/large-blob required. |
| A-14 | **Per-tenant TTL hard caps** | `src/config/types.rs` | Refuse load if a realm sets `password_reset_token_ttl` > 1h or `magic_link_ttl` > 30m unless `allow_unsafe_ttl: true`. |
| A-15 | **gRPC rate-limit interceptor** | `src/protocol/grpc/` | Mirror the HTTP shaper. |
| A-16 | **CAPTCHA-of-last-resort hook** | UI + `AbuseGuard` | When an IP enters "challenge" state, UI login/registration forms inject a configurable challenge widget (slot for the pluggable provider in 4.2). API responses return `HEARTH_ABUSE_CHALLENGE_REQUIRED` with a challenge token. |
| A-17 | **Login-event tarpit** | `src/abuse/tarpit.rs` | Once an IP is over threshold, add deterministic ~100–500ms delay (off hot path) to all auth POSTs from that IP. Cheap deterrent against brute-force CPU. |
| A-18 | **Session lifecycle policy** | `src/identity/sessions.rs` | Per-realm `max_sessions_per_user`, `idle_timeout`, `absolute_timeout`. Session reaper task. Emits `session.evicted` audit. Closes gap §3.19. |
| A-19 | **Email-change re-verification flow** | `src/identity/engine.rs` | New address must be verified via separate token before swap; old address gets a `security.email_changed` notification with revoke link. Closes §3.20. |
| A-20 | **Deleted-email reuse cooldown** | `src/identity/users.rs` | 90-day reservation on the email of a deleted account; re-registration creates a wholly new identity with no inheritance of memberships/invitations. Closes §3.21. |
| A-21 | **JSON parse-bomb guard** | `src/protocol/http.rs` middleware | `serde_json` depth + array-length caps on every `Json<…>` and `Json<Value>` extractor; reject with 413. Closes §3.22. |
| A-22 | **Decompression-bomb cap** | `src/protocol/http.rs` middleware | `Content-Encoding: gzip` requests: cap decoded size ≤ 4 × body-limit; abort stream on overrun. Closes §3.23. |
| A-23 | **Trait-level pagination hard cap** | `src/identity/mod.rs` | Refuse `limit > MAX_PAGE_SIZE` at trait boundary (1000 default, per-realm override). Handlers' current `10_000` is removed in favor of the cap. Closes §3.24. |
| A-24 | **Per-tenant resource quotas** | `src/identity/types.rs` + storage | `RealmConfig.quotas`: max users / orgs / clients / sessions / audit rows; reject create when over. Disk-usage accounting per realm-prefix (sampled). Closes §3.25. |
| A-25 | **Audit auto-retention** | `src/audit/engine.rs` | Per-realm `audit.retention_days` with background pruner; hard backstop at `audit.max_rows`. Plus disk-pressure warning hook. Closes §3.26. |
| A-26 | **`/metrics` authentication + bind-address lock** | `src/protocol/http.rs` | Default: bind `/metrics` to loopback or a separate internal listener; require Bearer auth for the public binding. Strip `Server:`/build banners. Closes §3.27. |
| A-27 | **Tracing PII / token redaction policy** | `src/protocol/tracing.rs` (new) | Span-field redactor: strip `reset_url`, `magic_link_url`, `password`, `token`, `cookie`, and full email by default; per-deployment override. `tracing::warn!(reset_url = …)` patterns must use a `Redact` newtype. Closes §3.28. |
| A-28 | **Slug & invitation atomic CAS** | storage layer | Single WAL record for "reserve slug *or* fail" and "accept invitation *or* 410"; no read-then-write. Closes §3.29. |
| A-29 | **Federation hardening** | `src/identity/federation/` | (a) RFC 9207 `iss` parameter enforced on OIDC callback; (b) `aud` pinning; (c) never auto-link to a local account on an `email_verified=false` upstream — require manual link confirmation; (d) SAML signature-wrap + entity-expansion caps explicit. Closes §3.30. |
| A-30 | **Backup/export hardening** | `src/protocol/http.rs` admin routes | Separate `realm:export` capability (not just admin role); per-export rate limit; restore archive must carry a detached signature verified against operator public key; every export emits a single watermarked audit row. Closes §3.31. |
| A-31 | **Per-realm + per-issuer JWT leeway config** | `src/config/types.rs` | Replace the hardcoded 60s with `security.jwt.leeway_seconds` (realm) and `federation.<idp>.leeway_seconds` (idp); range-check [0, 300]. Closes §3.32. |
| A-32 | **`trusted_proxies` config validator** | `src/config/validate.rs` | Startup refusal of `0.0.0.0/0`, `::/0`, public CIDRs, and loopback if a public listener is bound. Closes §3.33. |
| A-33 | **Bounded delete-cascade** | `src/identity/engine.rs` | Chunked cascade (configurable batch size), backgrounded for realms over threshold; "deletion in progress" state surfaced in admin dashboard. Closes §3.34. |
| A-34 | **Consent page CSP + ticket realm-binding** | `src/protocol/web/oauth/consent.rs` | Explicit `frame-ancestors 'none'` on `/oauth/consent`; ticket carries `realm_id` and is rejected if presented in a different realm. Closes §3.35. |
| A-35 | **SCIM/SAML payload caps** | `src/protocol/scim/`, `src/identity/federation/saml/` | SCIM PATCH `Operations` count ≤ 1000; SAML response entity expansion ≤ N; XXE off by construction (validated at parser config level). Closes §3.36. |
| A-36 | **AGENT_AUTH partial-implementation guardrail** | `src/main.rs` | If config enables agent-auth features before the spec is fully shipped, refuse to start with an explicit error pointing at the AGENT_AUTH.md status banner. Closes §3.37. |
| A-37 | **`prompt=none` per-(realm, subject) probe limit** | `src/identity/oidc.rs` | Track `prompt=none` outcomes per (realm, sub) and rate-limit; emit `oidc.silent_auth_probed` audit. Closes §3.38. |
| A-38 | **Token-exchange (RFC 8693) depth + DPoP coverage** | `src/identity/tokens.rs` | Cap `act` actor-chain depth (default 3); extend `cnf.jkt` requirement to all access tokens, not just refresh. (DPoP nonce challenge itself already lives at `src/identity/dpop.rs:363-475`.) Closes §3.40. |
| A-39 | **HTTP/2 rapid-reset defense** | `src/protocol/http.rs` server config | Set `max_concurrent_streams` (e.g., 100); per-conn RST budget with drop-conn on overrun; surface as `security.http2.*` config. Closes §3.42. |
| A-40 | **`Host` header / SNI allowlist + cookie/header prefixes** | `src/protocol/web/middleware.rs` | (a) Reject requests whose `Host` is not in `security.allowed_hosts` (default = listener bind hostnames); (b) cookies emitted with `__Host-` / `__Secure-` prefixes where applicable; (c) emit `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp` on UI; (d) `Permissions-Policy` denying sensors / payment by default; (e) optional `Partitioned` (CHIPS) on session cookies. Closes §3.43, §3.56. |
| A-41 | **Session-id rotation on every authentication event** | `src/identity/sessions.rs` + UI handlers | Invariant: on successful primary-auth, MFA step-up, federation link, password-change, or admin impersonation, the session record is destroyed and a fresh ID is minted; old cookie is invalidated. Test: pre-planted cookie must not survive login. Closes §3.44. |
| A-42 | **Sensitive-mutation mass-revocation** | `src/identity/engine.rs` | `change_password` / `set_password` / `change_email` / `mfa_disable` revoke all sessions and refresh-families for the user, with a `keep_current = true` opt-in for the active session. Emits `security.sessions_revoked` audit + webhook. Closes §3.45. |
| A-43 | **gRPC reflection production-disable** | `src/protocol/grpc/server.rs` | `security.grpc.reflection_enabled` default `false`; under `--dev` defaults to `true`. Production startup refuses if reflection is on without explicit `--allow-reflection-in-prod`. Closes §3.46. |
| A-44 | **TLS 0-RTT off + mTLS revocation (OCSP/CRL)** | `src/protocol/tls.rs` | (a) Disable 0-RTT by default; (b) optional OCSP-stapling check + CRL bundle for `with_client_cert_verifier`, refresh interval per realm; (c) per-realm cert revocation list cache. Closes §3.47. |
| A-45 | **Tenant-controlled HTML/CSS sanitization for branding** | `src/identity/email/templates.rs` + `src/protocol/web/themes.rs` | All tenant-supplied HTML/CSS/SVG passes through an allowlist sanitizer (DOMPurify-equivalent for HTML, CSS-property allowlist for `custom_css`, SVG sanitizer rejecting `<script>`/event handlers / external refs). Document the contract in `docs/specs/THEME.md`. Closes §3.48. |
| A-46 | **Argon2 pepper rotation policy** | `src/identity/credentials.rs` | Add `pepper_version` in PHC string; verify against active + previous pepper during grace window; expose a `hearth migrate rotate-pepper` CLI subcommand that rewrites credentials lazily on next successful login. Closes §3.49. |
| A-47 | **`deny_unknown_fields` on admin/auth shapes** | derive macro audit | Audit every `#[derive(Deserialize)]` on a request body in `src/protocol/web/handlers.rs`, `src/protocol/grpc/`, `src/identity/oidc.rs`; apply `deny_unknown_fields` unless a documented forward-compat exception is recorded. Closes §3.50. |
| A-48 | **OAuth `state` ↔ session binding for federation start** | `src/protocol/web/federation.rs` | At `/auth/federation/start`, derive `state` = HMAC(session_secret, nonce); at callback, require the originating UI session cookie present and matching the binding. Closes §3.51. |
| A-49 | **Refresh-context binding & anomaly detection** | `src/identity/oauth.rs` | Bind refresh tokens to a UA hash and ASN; on exchange, surface a delta (UA changed / ASN changed / country changed) into the risk scorer (A-11) and optionally require re-auth. Distinct from A-12 (DPoP nonce, refresh-only). Closes §3.52. |
| A-50 | **Cross-realm SMS / email cross-aggregation** | `src/abuse/detector.rs` | Add a global (cluster-wide) counter keyed by E.164 (and email-hash) covering *all* realms; trips a soft cap that requires CAPTCHA / queues, then a hard cap. Operator alert when one target is hit by ≥ N realms in window. Closes §3.53. |
| A-51 | **External audit-log attestation** | `src/audit/engine.rs` + new `src/audit/attestation.rs` | Periodic (e.g., hourly) head-hash signed with the realm's dedicated audit key and shipped to operator-supplied destination (S3 bucket, transparency log, webhook). On restart, verify last shipped attestation against current chain. Closes §3.54. |
| A-52 | **`return_to` / federation-redirect allowlist enforcement** | `src/protocol/web/{federation,saml,handlers}.rs` | Single `validate_return_to` helper used everywhere; rejects scheme-relative (`//evil`), `\evil`, off-origin (unless in `security.allowed_return_to_origins`), and `data:` / `javascript:`. SAML `bag.return_to` and federation `bag.return_to` MUST flow through it. Closes §3.55. |

### 4.2 Pluggable integrations (trait + reference adapter)

Ship the trait and at least one reference adapter; ecosystem can add more.

| ID | Trait | Reference adapter | Pluggable |
|----|-------|-------------------|-----------|
| P-1 | `CaptchaProvider` | `cloudflare-turnstile` | hCaptcha, reCAPTCHA v3, Friendly Captcha, on-prem PoW (`mCaptcha`-compatible) |
| P-2 | `IpReputationProvider` | static `Spamhaus DROP` list (refresh daily) | MaxMind GeoIP2, AbuseIPDB, IPQualityScore, Cloudflare, tenant-uploaded CSV |
| P-3 | `BotSignalProvider` | `User-Agent` + JA3/JA4 heuristics (built-in) | Cloudflare Bot Management, Datadome, Kasada, Akamai |
| P-4 | `RiskScorer` | rule-based (A-11 default) | Vendor risk engines, custom HTTP endpoint |
| P-5 | `EmailReputation` | DNS MX validity + disposable-domain list | Kickbox, ZeroBounce, NeverBounce |
| P-6 | `WafEgress` | none (no-op) | Forward security events to AWS WAF, Cloudflare WAF, Fastly via the security webhook channel (A-7) |
| P-7 | `SessionStore` | in-memory (today) | Externalize session list/lookup so A-18 concurrent-session policy is enforceable cluster-wide (Redis, Postgres, custom). Required for A-18 in multi-node deployments. |
| P-8 | `SecretsBackend` | storage-under-system-realm (today) | Pluggable HSM/KMS for signing keys, encryption-at-rest keys, and Argon2 pepper. Reduces blast radius of backup theft (A-30) and removes raw PKCS#8 from the WAL. |

All adapters are configured under `security.providers.<name>` in YAML, loaded
at startup via the same Tokio runtime as email transports. Hot path stays
zero-alloc: providers are consulted **off** the hot path (login is hot;
registration / forgot-password / consent are not).

### 4.3 Documentation & specs

| ID | Artifact |
|----|----------|
| D-1 | `docs/specs/ABUSE.md` — normative spec for the abuse plane: trait contracts, policy YAML schema, threat model, fail-open vs fail-closed rules. |
| D-2 | `docs/guides/operating-hearth-under-attack.md` — runbook: how to read the dashboard, common attack signatures, mitigation playbook, when to engage the deny list. |
| D-3 | Update `docs/specs/ARCHITECTURE.md` to add the `abuse` layer (sibling to `audit`, depends on `core` + `identity`). |
| D-4 | Update `docs/specs/TESTING.md` with an Abuse layer test taxonomy (volumetric simulation, botnet model, fail-open scenarios). |

## 5. Sequencing (proposed child-issue plan)

Phase 0 — Foundation (must land first, single PR):
- HEA-1114-A: `src/abuse/` skeleton, `AbusePolicy` trait, `AbuseGuard` middleware,
  YAML schema, no-op default behavior + tests. Wire into HTTP + gRPC routers
  behind a feature flag (default ON for new realms, opt-in for existing).
  Output: D-1 spec + A-1 + A-2 + A-15.

Phase 1 — High-leverage builtins (parallelizable):
- HEA-1114-B: A-3 distributed-attack detector + A-4 email/SMS volume shield.
- HEA-1114-C: A-7 security webhook channel + A-8 admin abuse dashboard.
- HEA-1114-D: A-9 tenant allow/deny CIDR + A-12 adaptive backoff + A-17 tarpit.
- HEA-1114-E: A-11 risk scorer + A-16 challenge plumbing.

Phase 2 — Pluggable adapters (independent):
- HEA-1114-F: P-1 Turnstile reference adapter + UI integration on register /
  forgot-password / magic-link forms.
- HEA-1114-G: P-2 Spamhaus DROP + MaxMind ASN feed loader.
- HEA-1114-H: P-3 JA3/JA4 + UA classifier; P-5 disposable-email list.
- HEA-1114-I: P-4 risk-scorer trait + reference rule engine.

Phase 3 — Hardening edges (cleanup):
- HEA-1114-J: A-5 reserved/cooldown slugs, A-6 bootstrap guard, A-10 JWKS cap,
  A-13 WebAuthn attestation, A-14 TTL hard caps.

### 5.1 Rev2 additions to sequencing

Phase 0 (foundation, fold into HEA-1114-A):
- A-21 JSON parse-bomb guard, A-22 decompression-bomb cap, A-23 trait-level
  pagination cap — all are HTTP-layer primitives the abuse layer depends on.
- A-41 (Test-quality gate, §3.41): the foundation PR ships the
  `tests/abuse_*.rs` taxonomy doc enumerating required adversarial scenarios
  per feature ID. No subsequent feature merges without filling its row.

Phase 1 (high-leverage builtins, parallelizable, new child issues):
- HEA-1114-K: A-18 session policy + P-7 `SessionStore` trait. (Coupled.)
- HEA-1114-L: A-19 email-change re-verification + A-20 deleted-email cooldown
  + A-37 silent-auth probe limit.
- HEA-1114-M: A-24 per-tenant resource quotas + A-25 audit auto-retention.
- HEA-1114-N: A-27 tracing PII/token redaction + A-26 `/metrics` auth.
- HEA-1114-O: A-29 federation hardening (IdP-mixup, unverified-email link
  policy, SAML defenses).

Phase 2:
- HEA-1114-P: A-30 backup/export hardening + P-8 `SecretsBackend` (HSM/KMS).
- HEA-1114-Q: A-33 bounded delete-cascade + A-28 atomic slug/invitation CAS.
- HEA-1114-R: A-35 SCIM/SAML payload caps + A-38 token-exchange depth & DPoP
  for access tokens.

Phase 3:
- HEA-1114-S: A-31 per-realm JWT leeway config (federation path only) +
  A-32 `trusted_proxies` validator + A-34 consent CSP/ticket binding +
  A-36 AGENT_AUTH guardrail + PAR/`request_uri` SSRF guard (lands when
  PAR feature lands).

### 5.2 Rev3 additions to sequencing

Phase 0 (foundation, fold into HEA-1114-A):
- A-39 HTTP/2 rapid-reset defense, A-40 Host allowlist + COOP/COEP/
  Permissions-Policy + cookie prefixes, A-47 `deny_unknown_fields` audit,
  A-52 unified `return_to` allowlist helper. All are HTTP-layer primitives
  the abuse plane depends on and are cheap to ship together.

Phase 1 (high-leverage, parallelizable, new child issues):
- HEA-1114-T: A-41 session rotation on auth + A-42 sensitive-mutation
  mass-revocation. Coupled — same session-table touchpoints.
- HEA-1114-U: A-45 tenant HTML/CSS/SVG sanitization for branding +
  `EmailBranding` / theme `custom_css` contract update in
  `docs/specs/THEME.md`.
- HEA-1114-V: A-48 federation `state`↔session binding + A-49 refresh
  context binding & anomaly detection.
- HEA-1114-W: A-50 cross-realm SMS/email cross-aggregation cap.

Phase 2:
- HEA-1114-X: A-43 gRPC reflection production-disable + A-44 TLS 0-RTT off
  + mTLS OCSP/CRL.
- HEA-1114-Y: A-46 Argon2 pepper rotation + CLI subcommand.
- HEA-1114-Z: A-51 external audit-log attestation.

Each child issue is small (≤ ~3 days), independently testable, and lands its
own changelog entry and adversarial tests in the matching `tests/abuse_*.rs`
file.

## 6. Risks & tradeoffs

- **Fail-open vs fail-closed** for pluggable providers. Default: fail-open
  for `BotSignal` / `IpReputation` (availability > paranoia), fail-closed
  for `Captcha` (if the provider is down, registration pauses with operator
  alert). Documented in D-1.
- **Hot-path budget.** `AbuseGuard.check()` must be ≤ 5µs p99 on `Allow`
  cases. Achievable with Arc-swapped policy + flat hashset lookups for CIDR
  / denylist. Bench gate in CI.
- **Operator footgun.** Every new lever is a new way to lock yourself out.
  All deny-list and rate-limit changes must be reversible from the admin
  UI without restart and must never deny the realm-owner's own admin session
  (sentinel rule in `AbuseGuard`).
- **Privacy.** IP/ASN logging conflicts with some GDPR postures. Make
  retention configurable; default 30 days; truncate to /24 in audit if
  `privacy.truncate_ip = true`.
- **Pluggable adapter security.** Providers receive request metadata; we
  must redact tokens/passwords before handoff and document the data contract.

### 6.1 Cross-cutting risks (rev2)

- **Hardcoded constants are policy surfaces.** 60s clock skew, 10k list
  page, 4 GiB restore body, "unlimited" per-realm caps — all currently
  constants in code; all become per-realm/per-issuer policy in this plan.
- **`serde_json::Value` parses bypass typed limits.** Multiple admin
  endpoints accept arbitrary JSON; without depth/length caps, body-size
  limits alone won't stop parse bombs (A-21).
- **Federation surface is large and was missing from rev1 entirely.**
  OIDC + SAML + GitHub are all wired in `src/identity/federation/`; A-29
  brings them under the abuse plane.
- **Admin-token blast radius is too wide.** Backup, export, signing-key
  export are gated only by admin role — A-30 splits out an `realm:export`
  capability and watermarks every export.
- **Hot-path/cold-path split blinds long-tail surfaces.** `/metrics`, JWKS,
  exports, federation callbacks are all cold paths but rate-unlimited;
  A-2 + A-26 + A-30 close this together.
- **Cascade + quota gaps amplify each other.** No per-tenant quota → one
  tenant grows huge → one DELETE = write storm. A-24 and A-33 must land
  together.
- **Per-provider fail-open default needs to be per-provider, not blanket.**
  `CaptchaProvider` fail-closed; `IpReputation` fail-open; `BotSignal`
  fail-open; `RiskScorer` fail-open; `EmailReputation` fail-open;
  `SecretsBackend` fail-closed (no fallback to file). Documented in D-1.
- **Test-quality is implicit and must be made explicit.** Every A-N row
  ships with at least one `tests/abuse_<feature>.rs` negative scenario;
  Phase 0 lands the taxonomy doc and CI gate (A-41 / §3.41 — note:
  this is "test gate A-41", distinct from "session rotation A-41" added
  in rev3; we keep the IDs distinct in §4.1 by feature scope; if the
  numbering collision proves awkward at child-issue time, rename the test
  gate to A-T in implementation).

### 6.2 Cross-cutting risks (rev3 additions)

- **Transport-layer hardening lags application-layer.** Rev1/rev2 focused
  on application logic; H2 rapid-reset, 0-RTT, mTLS revocation, and
  Host-header validation are below the abuse plane but feed into it.
  A-39, A-40, A-44 cover this together.
- **Cross-realm aggregation is a recurring blind spot.** Per-realm caps
  (rev2 A-4) don't compose. SMS pumping, audit attestation, and email
  pumping all need a global-key sidebar in addition to per-tenant counters.
- **Sensitive events should propagate revocation.** Auth events / password
  rotations / MFA changes should fire a single invariant: "old security
  context dies." A-41 + A-42 codify this.
- **Tenant-controlled rendered content is a fresh attack surface.**
  `EmailBranding.custom_html`, theme `custom_css`, SVG — all stored in
  per-realm config and rendered later. A-45 is the only sanitizer line
  between tenant input and downstream end-user inboxes / browsers.
- **Strictness-by-default is cheap.** `deny_unknown_fields`,
  `__Host-` cookies, `COOP`/`COEP` are one-line wins that compound; rev3
  bundles them under A-40 / A-47 to land in Phase 0.
- **Federation response paths under-defended.** Even with rev2 A-29,
  `return_to` and OAuth `state` binding on the federation start/callback
  edges are still vectors. A-48 and A-52 close this.

## 7. What this plan does **not** include (out of scope, captured for future)

- Full WAF replacement (we sit behind a real WAF in any serious deployment).
- DDoS mitigation at L3/L4 (operator infra problem).
- Customer-facing fraud detection (beyond login risk) — that's a product on
  top of the platform, not the platform itself.
- Bot mitigation for embedded JS SDK UI (browser-side).

## 8. Next steps

1. Board confirmation on this rev3 plan (`request_confirmation` on HEA-1114,
   `confirmation:HEA-1114:plan:rev3-2026-06-03`).
2. On confirmation, create child issues HEA-1114-A … HEA-1114-J (rev1) plus
   HEA-1114-K … HEA-1114-S (rev2 additions) plus HEA-1114-T … HEA-1114-Z
   (rev3 additions), with HEA-1114-A blocking the rest.
3. Phase 0 lands in the next sprint; subsequent phases parallelize across
   engineers.

## 9. Rev2 changelog (2026-06-03)

Second-pass audit triggered by board comment "another pass at plan just to
make sure we're not leaving anything important out of working with
incomplete information." Cross-referenced 24 search dimensions against the
live codebase. Concretely added vs rev1:

**New gaps in §3:** items 19–41 (session lifecycle, email-change
re-verification, deleted-email cooldown, JSON & decompression bombs,
pagination cap, per-tenant quotas, audit auto-retention, `/metrics` auth,
tracing PII redaction, atomic CAS for slug/invite, federation hardening,
backup/export blast radius, per-realm JWT leeway, `trusted_proxies`
validator, bounded delete-cascade, consent CSP+ticket, SCIM/SAML caps,
AGENT_AUTH guardrail, `prompt=none` probe limit, PAR/`request_uri` SSRF,
token-exchange depth & DPoP coverage, explicit test-quality gate).

**New built-ins in §4.1:** A-18 through A-38 (21 entries).

**New pluggables in §4.2:** P-7 `SessionStore`, P-8 `SecretsBackend`.

**New phasing in §5.1:** Phase 0 folds A-21/A-22/A-23/A-41 into the
foundation PR; Phase 1 adds child issues HEA-1114-K…O; Phase 2 adds
HEA-1114-P/Q/R; Phase 3 adds HEA-1114-S.

**New risk themes in §6.1:** hardcoded constants as policy surfaces;
`Value` parses bypass typed limits; federation surface omission corrected;
admin-token blast radius; cold-path long-tail; cascade-quota coupling;
per-provider fail policy; explicit test-quality gate.

**Methodology:** parallel-grep sweep across session, redirect_uri, email
change, audit, storage quota, metrics, DPoP/token-exchange, SCIM/SAML,
agent-auth, compression, JSON depth, websocket, CORS, listing pagination,
email transport, PRNG, federation, clock skew, backup/export, logging PII,
TOCTOU, headers, delete cascade, OIDC response modes, consent/clickjack,
CIBA/PAR/JAR, trusted_proxies, and test files. Each gap is grounded in a
file:line citation captured during the audit.

## 10. Rev3 changelog (2026-06-03, second-revision)

Third-pass audit triggered by board comment "One more time." Cross-referenced
27 *additional* search dimensions (HTTP/2 rapid-reset, Host allowlist,
HSTS/COOP/COEP, `__Host-` cookies, `continue_url`/`return_to` open
redirects, DPoP nonce challenge, signing-key rotation, Argon2 pepper,
session fixation, password-change session invalidation, federation account
linking, gRPC reflection, TLS 0-RTT / OCSP / CRL, template injection in
tenant branding, cross-realm phone aggregation, audit-log attestation,
admin debug endpoints, cookie prefixes, `deny_unknown_fields`, OAuth
`state` binding, OAuth scope downgrade, introspection rate, recovery
MFA bypass, RBAC concurrent assign, device fingerprint binding,
client-secret rotation, user-controlled response headers). Items
deliberately distinct from rev1/rev2 sweeps.

**Items rev2 thought were gaps but rev3 found already covered in code:**

- DPoP server-issued nonce challenge (`src/identity/dpop.rs:363-475`).
- Signing key rotation grace (already 86 400s default).
- TOTP recovery-code MFA rate limit (test at `engine/mod.rs:14278`).
- First-party JWT leeway IS configurable; federation path is the only
  hardcoded one (A-31 retained, scope clarified).
- CSRF double-submit details (`verify_csrf_form_field` ubiquitous, already
  comprehensive).
- Token introspection rate (per-(realm, client) at `http.rs:113`).
- Admin debug endpoints (`/rbac/debug` only, gated by admin; no
  `/debug`/`/env`/`/pprof` exposed).
- RBAC concurrent-assign TOCTOU folds under A-28's atomic-CAS pattern
  (do not create a separate ID).
- Client-secret rotation folds under A-30 (export-grade rotation) — same
  shape, single ID.

**New gaps in §3:** items 42-56 (HTTP/2 rapid-reset, Host header allowlist,
session-id rotation on auth, password-change mass-revocation, gRPC reflection
in production, TLS 0-RTT + mTLS OCSP/CRL, tenant HTML/SVG template
injection, Argon2 pepper rotation, `deny_unknown_fields` default, OAuth
`state` binding for federation, refresh-context fingerprint binding,
cross-realm SMS aggregation, external audit-log attestation, `return_to`
open redirect on federation/SAML, COOP/COEP/Permissions-Policy + `__Host-`
cookies).

**New built-ins in §4.1:** A-39 through A-52 (14 entries).

**Pluggables in §4.2:** no rev3 additions (P-7/P-8 from rev2 absorb the
new work — `SessionStore` covers A-41/A-42 multi-node, `SecretsBackend`
absorbs pepper rotation).

**New phasing in §5.2:** Phase 0 absorbs A-39/A-40/A-47/A-52 (HTTP-layer
+ strictness defaults). Phase 1 adds HEA-1114-T (session invariants),
U (tenant content sanitization), V (federation `state` + refresh
binding), W (cross-realm aggregation). Phase 2 adds X (gRPC reflection +
TLS revocation), Y (pepper rotation), Z (audit attestation).

**New themes in §6.2:** transport-layer hardening parity; cross-realm
aggregation as recurring blind spot; sensitive-event-propagates-revocation
invariant; tenant rendered content as fresh attack surface;
strictness-by-default; federation response-path defenses.

**Confidence notes:** OAuth scope downgrade and full deserialization
strictness coverage were not confirmable from grep alone — recommend
manual code review during HEA-1114-A foundation work to validate scope-set
intersection logic at token issue.

## CI Enforcement (§3.41 adversarial test-quality gate)

The `scripts/check-abuse-coverage.sh` script (wired into the `abuse-coverage` CI
job and `make abuse-check`) scans this file for `A-N` identifiers, then verifies
each appears at least once in `tests/abuse_*.rs`. Any uncovered row fails the
build with a clear message.

**Rollback:** set `SKIP_ABUSE_COVERAGE_CHECK=1` as a GitHub Actions secret or
repo-level environment variable. Document the reason and the tracking issue when
activating the escape hatch. The flag is logged visibly in CI output so accidental
bypass is observable.

### Adding New Rows

1. Add the row to the A-N table above with a unique identifier (increment the
   largest existing N).
2. Land at least one adversarial test in `tests/abuse_*.rs` that references the
   identifier before (or in the same PR as) the plan doc change.
3. CI will fail the PR if step 2 is missing — that is the gate working correctly.
