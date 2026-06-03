# Changelog

All notable changes to Hearth will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Hearth has not yet cut a versioned release; all shipped work appears under `[Unreleased]`.

## [Unreleased]

### Security

- **A-45 Tenant-content sanitization** — all operator- and tenant-supplied
  SVG and CSS is sanitized before unescaped render (HEA-1199):
  - **SVG** (`logo_svg_inline` in email templates) — `<script>`,
    `<foreignObject>`, `on*` event handlers, external `href`/`xlink:href`,
    and `style` values containing `expression()` / `javascript:` are stripped
    by `sanitize_svg()` inside `prepare_svg_for_email()`.
  - **CSS** (`branding.custom_css` and per-realm `web.custom_css`) —
    `expression()`, `javascript:`, `behavior:`, `-moz-binding`, `@import`,
    `url(data:...)`, and `progid:` patterns are stripped by `sanitize_css()`
    at startup before the CSS is served to browsers.
  - See `docs/specs/ABUSE.md` §A-45 for the full contract.

### Added

- **A-11 Step-up MFA risk scorer** — new `src/identity/risk.rs` aggregates
  signals (new device, new country, password age, breach corpus hit) into a
  normalised score `[0.0, 1.0]`; when score ≥ threshold (default 0.5),
  `StepUpChallengeRequired` is returned at login.  Disabled by default
  (fail-open); enable via `security.risk_scorer.enabled: true` in `hearth.yaml`.
  P-4 extension point (`RiskScorer` trait) ready for HEA-1205 adapters (HEA-1192).
- **A-16 CAPTCHA-of-last-resort challenge plumbing** — new
  `src/abuse/challenge.rs` tracks per-IP failed-auth counts; IPs over the
  threshold enter "challenge" state and callers receive
  `HEARTH_ABUSE_CHALLENGE_REQUIRED` (HTTP 403).  UI forms carry a widget
  injection slot; `NoopCaptchaProvider` ships as the built-in (P-1 Turnstile
  adapter in HEA-1202).  Disabled by default; activate via
  `security.captcha.challenge_threshold` (HEA-1192).
- **Phase-0 abuse-prevention builtins** — HTTP-layer and strictness-default
  primitives that the rest of the abuse plane depends on (HEA-1188):
  - **A-2 Global request shaper** — per-IP (100 rps) + per-realm (1 000 rps)
    sliding-window rate limiter applied to all public routes.  Configurable
    via `security.request_shaper` in `hearth.yaml`.
  - **A-15 gRPC rate-limit interceptor** — mirrors the HTTP shaper on all
    gRPC methods; the per-IP interceptor is wired via `Server::layer()`.
  - **A-21 JSON parse-bomb guard** — inbound JSON bodies are rejected with
    413 if nesting depth > 128 levels or any single array has ≥ 65 536
    elements.
  - **A-22 Decompression-bomb cap** — `Content-Encoding: gzip` payloads are
    capped at 4 MiB decompressed; oversized streams are aborted.
  - **A-23 Pagination hard cap** — `cap_page_size(limit)` helper enforces a
    1 000-row maximum at the trait boundary; handlers' hardcoded 10 000 limit
    is superseded.
  - **A-39 HTTP/2 rapid-reset defense** — TLS connections set
    `max_concurrent_streams = 100` and `max_pending_reset_streams = 10`
    (CVE-2023-44487 mitigations).
  - **A-40 COOP / COEP / Permissions-Policy headers** — the UI security-
    headers middleware now emits `Cross-Origin-Opener-Policy: same-origin`,
    `Cross-Origin-Embedder-Policy: require-corp`, and
    `Permissions-Policy: camera=(), microphone=(), geolocation=(), …` on
    every UI response.  Configurable via `SecurityConfig.coop_coep_enabled`.
  - **A-47 `deny_unknown_fields` on admin request bodies** — key admin
    request shapes (`ImportUsersBody`, `HttpBulkUsersRequest`,
    `PatchRealmBrandingRequest`, RBAC role/group bodies) now reject extra
    fields.  OAuth/OIDC protocol bodies are explicitly exempted (RFC 6749
    extension-parameter allowance documented).
  - **A-52 Unified `return_to` allowlist** — `crate::abuse::redirect::validate_return_to`
    consolidates all open-redirect prevention.  Federation start and SAML ACS
    handlers now validate `return_to` before persisting it in the state bag.
    Operator-whitelisted absolute origins are supported via
    `security.allowed_return_to_origins`.

- **A-41 Session-ID rotation on every authentication event** (HEA-1198):
  Every successful primary-auth, MFA challenge completion, passkey login, and
  forced TOTP enrollment now revokes the pre-existing session cookie before
  minting a fresh one via `revoke_prior_session_cookie`.  Pre-planted session
  cookies (session-fixation attack vector §3.44) cannot survive a login.

- **A-42 Sensitive-mutation mass-revocation** (HEA-1198):
  `set_password`, `change_password`, `disable_mfa`, and email changes (via
  `update_user`) now revoke all active sessions and their refresh-token grant
  families for the affected user.  A single `sessions_revoked` audit event
  is emitted with the count.  The new `revoke_all_user_sessions` engine
  method accepts an optional `keep` session ID so callers can preserve the
  user's own active device session if desired.

- **A-35 SCIM/SAML payload caps** (HEA-1208):
  - **SCIM PATCH `Operations` count cap** — SCIM PATCH requests with more than
    1 000 `Operations` entries are rejected with HTTP 400 / `scimType: tooMany`.
    Closes the resource-exhaustion vector where a single PATCH could fan out
    over an unbounded operations loop.
  - **SAML XML event cap** — `parse_response` and `find_element_range` now
    abort with `SamlParse` after 10 000 XML events.  Closes the complementary
    exhaustion vector for crafted responses with thousands of elements
    (DOCTYPE/XXE was already blocked; this cap adds depth against non-DTD bulk).

- **A-38 Token-exchange depth & DPoP `cnf.jkt` coverage** (HEA-1208):
  - **`client_credentials` + JWT-bearer FAPI enforcement** — when a realm has
    `fapi_profile` set or the client was registered with `profile: Fapi2`, the
    token endpoint now rejects `client_credentials` and `jwt-bearer` requests
    that omit `dpop_jkt`.  Previously only the authorization-code exchange path
    was guarded; all access-token-issuing grant types are now consistent.
  - **RFC 8693 `act` chain depth cap** — `validate_token` rejects inbound
    access tokens whose `act` delegation chain exceeds 3 levels (constant
    `MAX_ACT_CHAIN_DEPTH`).  Hearth does not issue `act` chains itself; this
    cap defends against externally-crafted delegation-bomb tokens.

### Changed

- **`validate_token` hot-path allocation reduced** — two in-process `ArcSwap` caches were added
  to `EmbeddedIdentityEngine`: a session cache (keyed by `(RealmId, SessionId)`) eliminates the
  `StorageEngine::get` call on every token validation for active sessions, and a token claims cache
  (keyed by SHA-256 of the raw JWT) eliminates the `serde_json::from_slice::<TokenClaims>`
  allocation for repeated validations of the same access token. The `validate_token` allocation
  gate (`benches/validate_token.rs`) is tightened from 64 to 20 allocations per warm call.
  (HEA-1183)

- **`PATCH` replaces `PUT` for partial-update admin endpoints** — `PUT /admin/realms/{id}`,
  `PUT /admin/roles/{id}`, `PUT /admin/groups/{id}`, and `PUT /admin/applications/{id}` are now
  `PATCH` to correctly signal partial-update semantics (RFC 5789). All four endpoints and their
  gRPC HTTP annotations (`identity.proto`, `rbac.proto`, `oauth.proto`) have been updated. The Go
  and TypeScript SDKs have been updated accordingly. HTTP clients that hard-code `PUT` will receive
  `405 Method Not Allowed`. (HEA-1184)

- **DPoP state moved to identity layer** — `DPopJtiCache` and the HMAC nonce secret are now
  managed by a new `DPopProcessor` type in `src/identity/dpop` rather than being fields on
  `AppState`. The HTTP protocol layer holds only an `Arc<DPopProcessor>`. Operator-visible
  behaviour is unchanged. (HEA-1184)

- **`HEARTH_` prefix now covers all error codes** — four error codes previously returned as bare
  strings (`session_limit_exceeded`, `invalid_sms_otp`, `sms_resend_limit_exceeded`,
  `session_version_disabled`) are now named constants with the `HEARTH_` prefix. (HEA-1184)

### Fixed

- **`proto_to_rest_json` serialization failures now logged** — previously, a `serde_json`
  serialization error in the proto-to-REST JSON helper was silently swallowed via
  `unwrap_or_default()`. Failures are now logged at `error` level so operators can detect them.
  (HEA-1184)

- **Audit failure error message no longer leaks subsystem name** — the `AuditFailure` error
  previously returned `"internal error: audit record failed"` as the HTTP error body, disclosing
  the internal audit subsystem. It now returns `"internal error"`. (HEA-1184)

### Added

- **Offline breach corpus for air-gapped realms (HEA-96)** — `BreachCheckConfig` gains a new
  `mode` field (`online` | `offline`). When set to `offline`, a locally-provided binary corpus
  of sorted 20-byte SHA-1 hashes is binary-searched instead of calling the HIBP API, enabling
  NIST SP 800-63B breach checking in networks without outbound internet access. Configure via
  `breach_check.mode = offline` and `breach_check.mode.corpus_path = /path/to/corpus.bin`.
  Existing configs that omit `mode` continue to behave as `online` with no changes required.

- **`fapi_profile` realm config key** — operators can now set `fapi_profile: "baseline"` or
  `fapi_profile: "advanced"` under `realms.<name>` in `hearth.yaml` to enforce FAPI 2.0 Security
  Profile constraints on all clients in that realm at startup. Unknown values are a hard error.
  (HEA-1040)

- **`PATCH /admin/realms/{id}/config` accepts `fapi_profile`** — the admin config patch endpoint
  now accepts `"fapi_profile": "baseline"`, `"fapi_profile": "advanced"`, or `"fapi_profile": null`
  (to clear). Returns 400 for unrecognised values. (HEA-1040)

- **`profile` application config key** — per-client FAPI 2.0 profile can now be declared in
  `realms.<name>.applications.<key>.profile: "fapi2"` in `hearth.yaml`. The reconciler applies it on
  create and detects drift on subsequent restarts. (HEA-1040)

### Security

- **User deletion now purges RBAC state** — `delete_user` previously omitted the RBAC cascade,
  leaving stale role assignments and group memberships in storage after a user was deleted. An
  attacker who later claimed the same user UUID could inherit the deleted user's privileges. The
  identity engine now calls `RbacEngine::purge_user_from_realm` as step 12 of the deletion
  sequence, removing all direct role assignments and group memberships within the realm before
  the audit event is written. Realm isolation is preserved: RBAC state in other realms is not
  affected. (HEA-1185)

- **JTI corruption no longer bypasses replay protection** — a malformed (wrong-length) WAL entry for
  a JWT Bearer assertion JTI previously silently decoded as epoch-0 expiry, causing the replay check
  to pass and enabling token replay. The engine now returns an `Internal` error on unexpected byte
  length, preventing silent overwrites of valid entries (HEA-1136).

### Fixed

- **Admin UI defect batch** — 15 confirmed bugs from the 2026-05-31 QA audit (HEA-1089):
  - Audit log org events no longer display raw UUIDs — resource type mismatch between write path
    (`"org"`) and display resolver (`"organization"`) is now handled by matching both strings.
  - Audit "via" metadata pills now show human-readable values: `admin_api` → Admin API, `ui` → UI,
    `scim` → SCIM, `self` → Self-service.
  - System Info page shows `(in-memory)` instead of blank when no data directory is configured.
  - User create/edit validation errors now use human-readable field labels ("First name", "Last name")
    instead of snake_case identifiers.
  - Admin actor filter placeholder updated to "email, name, or 'system'".
  - Audit log expand column now has an accessible `sr-only` header label ("Details").
  - User list page title now shows "Admin Users" for the system-realm route.
  - Settings breadcrumb separator changed from `/` to `›`; "Admin" is now a link to `/ui/admin`.
  - "Admin" breadcrumb link on user list corrected to `/ui/admin` (was `/ui/admin/realms`).
  - User detail page now renders a breadcrumb (was missing entirely).
  - Duplicate breadcrumb from `_workspace_tabs.html` removed from user list body.
  - Admin JS initializers isolated in per-component `try/catch` so a single failure cannot freeze
    the sidebar "Loading…" spinner.
  - Bootstrap endpoint returns `409 Conflict` instead of `500` when dev-realm exists but admin user
    is missing.
  - Realm-scoped 404 pages now render inside the admin chrome (sidebar, user pill, theme) rather
    than as a bare unstyled page.
- **Permission Check UX overhaul** — six operator-visible improvements to the RBAC debug page (HEA-1094):
  - Empty-state: resolving a user with zero assignments now shows the Roles / Groups / Permissions
    grid with "—" in each column instead of hiding the panel entirely.
  - Resolved-user banner: a "Resolved for: Name (email)" summary appears above the results grid
    after any successful resolution.
  - Code chips + copy buttons: permission, role, and group items render as `<code>` chips with
    per-item one-click copy buttons.
  - Org ID validation: a non-empty malformed org_id now shows an inline error immediately instead
    of silently running without org scoping.
  - Scope hint: the OAuth scope input gains a `placeholder` (`openid profile email`) and a
    short description line below it.
  - Realm label: the realm line in both tabs now shows `realm_name · <uuid>` so the human label
    is visible alongside the identifier.
- **Token Preview endpoint returns 405 no more** — the RBAC debug token-preview route was
  registered as POST-only while the JS client sends a GET with a `?user_id=` query param; every
  button click returned 405 and the result panel never appeared. Route changed to GET; handler
  extractor changed from `axum::Form` (body) to `axum::extract::Query` (query params) (HEA-1092).

### Changed

- **_hyperscript removed** — all admin-UI interactivity now expressed as vanilla-JS components via
  `data-component` attributes backed by `components.js`. CSP unchanged (still `script-src 'self'`).
  No operator action required (HEA-1049).

- **CI required-check renamed: `sdk-conformance (docs/sdk-spec.md)` → `sdk-conformance (docs/specs/SDK.md)`.**
  The SDK common-spec doc moved from `docs/sdk-spec.md` to `docs/specs/SDK.md` to co-locate
  with the other canonical specs in `docs/specs/`. The CI job name in `.github/workflows/ci.yml`
  and the entry in `scripts/ci-required-checks-migrate.sh` updated to match. **Operators must
  re-run `scripts/ci-required-checks-migrate.sh --apply` (or update GitHub branch protection
  manually) so the required-check name matches the new job.** All inbound SDK README,
  CHANGELOG, and code-comment links updated.

### Fixed

- **Storage: memtable flushed before WAL rotation** — the storage engine now
  flushes the active memtable to an SST before truncating the WAL on rotation.
  Previously, up to `storage.memtable_flush_bytes` (default 4 MiB) of data
  could be lost if the process crashed between a WAL rotation and the next
  flush cycle. Triggered only when WAL size exceeds `storage.wal_max_bytes`
  (default 64 MiB), so small/dev deployments were not at risk (HEA-1050).

### Added

- **Startup panel shows env and storage stats (HEA-1032)** — the info panel printed after bind
  now includes a stats section: realm count, email transport, TLS status, OIDC issuer (when
  configured), federation connector count (when > 0), cluster peer count (when in cluster mode),
  WAL file size, SST file count, total data-directory size, and startup duration in ms. Stats are
  derived from config (zero-cost) or a single `fs::read_dir` pass (cheap). No storage-engine
  lock and no heap allocation after startup.

- **ASCII HEARTH banner + consolidated startup info panel (HEA-1047)** — `hearth serve` now
  prints a block-letter ASCII art banner before tracing init, followed by a single info panel
  after the server binds showing API URL, Admin UI URL, first-run Setup URL (when a
  `.setup_token` exists), and Mail inbox URL + password (when mailcatcher is active). Both are
  suppressed when `log_format: json` so machine-readable log pipelines are unaffected.
  The mid-init mailcatcher box that previously appeared during startup has been removed and
  consolidated into the panel.

- **Dev-mode pretty log formatter (HEA-1046)** — when `--dev` is active or stdout is a TTY,
  the log output switches to a compact human-readable format: `HH:MM:SS` timestamps, ANSI-colored
  level labels (TTY only), and abbreviated target paths (last two `::` segments, e.g.
  `identity::engine` instead of `hearth::identity::engine`). JSON output (`log_format: json`) is
  unaffected.

### Fixed

- **"Generate YAML" button on Admin → Migration History now works** — the per-orphan
  disclosure button on `/ui/admin/migrations` carried an inline hyperscript expression
  (`closest <div.p-4/>`) whose hyphenated class selector was parsed as a math subtraction,
  causing the hyperscript parser to reject the whole handler and leaving the button inert.
  The handler now targets the form panel by id (`#orphan-form-{loop.index}`), matching the
  existing convention in `templates/ui/admin/organizations/_member_row.html`.

- **Default log filter now suppresses noisy third-party crates (HEA-1045)** — globset, h2,
  hyper, and tower are capped at `warn` in the default `EnvFilter`, eliminating regex-conversion
  debug lines from normal `make dev` output. `RUST_LOG` still overrides everything when set.

- **Migration history timestamps now human-readable (HEA-1037 / BUG-13)** — the Completed and
  Detected columns in the Migration History admin page were displaying raw RFC 3339 strings
  (e.g. `2024-03-15T14:30:00Z`). The view layer now formats them as `15 Mar 2024 14:30 UTC`.

- **Org/user create forms now show the free-form attribute section (HEA-1031)** — when no
  attribute definitions are configured for a realm, the create forms for organizations and users
  showed nothing under the Attributes heading. The `{% else %}` branch rendering the dynamic
  add/remove UI was missing. Also removed CSP-violating inline `<script>` blocks from all four
  affected templates (create + edit for org and user); logic moved to the new
  `/ui/static/admin/attr-rows.js` external file which is served from the same origin and
  therefore permitted by `script-src 'self'`.

- **Org and user attribute fields now submit correctly with a single attribute row (HEA-1031)**
  — submitting a create or edit form for an organization or user with exactly one attribute
  row produced a 400 error. Root cause: `serde_urlencoded` 0.7.x calls `visit_str` (not
  `visit_seq`) when a repeated key appears once, but `Vec<String>` only accepts `visit_seq`.
  A new `string_or_vec` deserializer handles both shapes; applied to `attr_keys`/`attr_vals`
  in `CreateOrgForm`, `EditOrgForm`, `CreateUserForm`, and `EditUserForm`.

- **Org and user attribute forms now submit correctly with two or more attribute rows (HEA-1031)**
  — submitting a create or edit form with ≥2 attribute rows (i.e. in realms that have
  schema-defined attribute definitions) produced a 400 "We couldn't read that form" error.
  Root cause: serde's struct deserializer rejects duplicate field names before
  `deserialize_with` is invoked, making the `string_or_vec` helper ineffective for the
  multi-row case. All four form structs (`CreateUserForm`, `EditUserForm`, `CreateOrgForm`,
  `EditOrgForm`) now implement `axum::extract::FromRequest` directly, parsing the raw body
  with `form_urlencoded::parse` so all occurrences of `attr_key` and `attr_val` are
  collected in order without hitting serde's duplicate-field guard.

- **Optional enum/boolean attribute fields no longer produce validation errors when left blank (HEA-1031)**
  — selecting no option on an optional enum or boolean select (e.g. "Is Contractor") submitted an
  empty string that the server rejected as "not in allowed values". The four attribute form
  handlers now strip pairs with empty values before validation; optional blank fields are treated
  as absent. Required attribute fields left blank now correctly surface a "required attribute
  missing" server error, and all four templates add the HTML `required` attribute to schema-
  defined inputs so the browser blocks submission before the server is reached.

- **Submit buttons now show a loading state immediately on form submission (HEA-1031)**
  — clicking Save/Create multiple times while the server processed the request could trigger
  duplicate submissions. `initFormSubmitProtection()` in `admin.js` disables the submit button
  and shows "Saving…" as soon as the form passes browser validation, preventing double-submits.

- **Organization slug field now enforces valid slug characters client-side (HEA-1037 / BUG-14)**
  — the Create Organization form was missing an HTML `pattern` attribute on the slug input,
  allowing browsers to accept strings that the server would reject. `pattern="[a-z0-9][a-z0-9-]*"`
  now matches the server-side constraint (3–63 chars, lowercase alphanum + hyphens).

- **Unlabeled action column headers in admin tables (HEA-1037 / BUG-15)** — axe-core flagged
  empty `<th></th>` cells at the rightmost position of every list table as accessibility
  violations. All 16 affected table headers now carry `aria-label="Actions"`.

- **Audit hash chain integrity preserved across server restarts (HEA-1036)** — the in-memory
  chain cursor was lost on restart, causing the first post-restart `append()` to incorrectly
  treat the realm as empty and chain from the genesis hash. The engine already recovered
  correctly via `get_last_hash()` (a storage scan), but the regression test was absent,
  leaving the invariant unverifiable. Test added; integrity check now passes across restart.

### Security

- **Backup restore body capped at 4 GiB (HEA-1130)** — `POST /admin/backup/restore` previously
  used `DefaultBodyLimit::disable()`, allowing any admin-token holder to stream an arbitrarily
  large body and exhaust heap memory. The limit is now `4 GiB` — sufficient for the largest
  expected backup archives while preventing OOM-kill from malicious uploads. The handler
  already streams the body to a temporary file rather than buffering in memory, so this limit
  gates TCP ingress rather than in-process RAM.

- **DPoP nonce secret wired from config (HEA-1125)** — `AppState` was initialised with
  `dpop_nonce_secret = [0u8; 32]` in all three constructors, making the HMAC-SHA256 nonce
  generation trivially predictable and defeating DPoP replay protection. The secret is now
  derived at startup from `security.dpop_nonce_secret` in `hearth.yaml`: a 64-character
  lowercase hex value pins the key across restarts; `"auto"` (the default) generates a
  fresh 32-byte key via `ring`'s CSPRNG on every startup. A startup assertion rejects the
  zero key in all deployment modes.

- **JAR `response_mode` override now enforced (HEA-1008)** — `JarClaims` lacked a
  `response_mode` field, so a JAR JWT could not override the outer query-string
  `response_mode`.  A network attacker who stripped the outer parameter could downgrade
  a JARM response to plain `query` mode.  `response_mode` is now deserialized from the
  JAR and takes precedence over the outer value in both `authorize()` and
  `push_authorization_request()` (RFC 9101 §4).  `StoredPushedAuthorizationRequest`
  also persists the effective `response_mode` so the PAR→authorize path honours it.

- **JAR JTI replay store now expires entries (HEA-1009)** — JAR (RFC 9101) JTI entries
  were previously stored indefinitely, allowing unbounded storage growth for any
  authenticated client. Each entry now carries an 8-byte expiry timestamp
  (`claims.exp + 60 s clock-skew margin`) and is purged by the existing periodic
  cleanup sweeper (`sweep_expired`). Replay prevention is unaffected — the read-path
  check is value-format agnostic.

- **FAPI 2.0 profile mutation now guarded against client_secret retention (HEA-1021)** —
  `update_client` rejected the `profile → Fapi2` transition if the existing client already
  held a `client_secret_hash`, closing a gap where a Standard confidential client could be
  silently "upgraded" to FAPI 2.0 while retaining its symmetric secret in violation of
  FAPI 2.0 §5.3.1.1. Additionally, `regenerate_client_secret` now returns `FapiViolation`
  for any FAPI 2.0 client before reaching the `is_confidential` check, so no admin can
  issue or refresh a secret on a FAPI 2.0 client regardless of stored state.

- **DPoP sender-constraint now enforced for all clients in FAPI Baseline realms (HEA-1022)** —
  The realm-level DPoP gate in `exchange_authorization_code` only checked for
  `FapiProfile::Advanced`; a `Standard`-profile client in a FAPI Baseline realm could
  exchange an authorization code without a DPoP proof, receiving a non-sender-constrained
  access token. The gate now uses `fapi_profile.is_some()`, covering both Baseline and
  Advanced — consistent with FAPI 2.0 Baseline §5.3.3.

- **JAR `request` field now propagated through HTTP PAR endpoint (HEA-1019)** —
  The HTTP PAR body deserialiser (`HttpParRequest`) was missing the `request`
  field, so signed JAR JWTs sent by FAPI Advanced clients were silently dropped
  before reaching the engine. This caused every HTTP PAR call to an Advanced
  FAPI realm to return `invalid_request` (JAR required) regardless of whether
  the client supplied one. The field is now forwarded to the domain layer;
  FAPI Advanced clients can complete PAR using the HTTP endpoint.

- **RFC 9126 §4 `client_id` mismatch check in PAR-backed authorize (HEA-1018)** —
  The `POST /v1/authorize` and `GET /ui/oauth/authorize` handlers previously did
  not verify that the `client_id` in the request matched the `client_id` stored
  with the pushed authorization request. An attacker who obtained a `request_uri`
  (e.g. via referrer leakage) could have submitted it under a different client
  identity. Both handlers now return `invalid_request` when the `client_id`
  parameter is present and does not match the stored PAR entry. Two new HTTP-layer
  regression tests cover replay attacks (FAPI-B-09) and `client_id` mismatch
  (FAPI-B-10).

- **PAR `request_uri` now consumed in HTTP authorize handler (HEA-1017)** —
  `GET /ui/oauth/authorize` and `POST /v1/authorize` previously ignored the
  `request_uri` query/body parameter, causing FAPI 2.0 Baseline realms to
  reject every browser-based authorization request (the handler always passed
  `via_par = false`). Both handlers now call `consume_par` when `request_uri`
  is present, expand the pre-validated stored parameters, and set `via_par =
  true` — enabling FAPI 2.0 Baseline and Advanced clients to complete the
  authorization code flow. The gRPC `OAuthService.Authorize` RPC gains the
  same PAR expansion. `AuthorizationRequest` in the gRPC/REST proto gains an
  optional `request_uri` field (field 10).

- **FAPI 2.0 DPoP enforcement on `refresh_token` grant — realm-level gate added (HEA-1024)** —
  The realm-level DPoP gate was only applied to `exchange_authorization_code`, not
  `refresh_tokens`. A standard-profile client in a FAPI Baseline or Advanced realm could
  refresh its access token without a DPoP proof, receiving an unbounded token with no
  `cnf.jkt` claim. `rotate_grant_family` now checks both the per-client profile and the
  realm's `fapi_profile`; refreshes without DPoP are rejected with `invalid_dpop_proof`
  when either gate applies. The HTTP `refresh_token` response also now correctly sets
  `token_type: DPoP` when a DPoP thumbprint is present (RFC 9449 §7). Regression test:
  FAPI-B-11.

- **FAPI 2.0 DPoP enforcement on `refresh_token` grant (HEA-1016)** — FAPI 2.0
  clients must now supply a DPoP proof on every token endpoint call, including
  `grant_type=refresh_token`. Requests without a DPoP header are rejected with
  `invalid_dpop_proof`. The refreshed access token carries `cnf.jkt` bound to
  the thumbprint extracted from the proof, preventing unbounded token issuance.
  Standard clients are unaffected.

- **JARM JWT token-type confusion fix (HEA-1004)** — JARM JWTs now carry
  `typ: "oauth-authz-resp+jwt"` (IANA-registered media type per JARM §4.1 /
  RFC 9101 §2) instead of the generic `"JWT"`. This gives explicit RFC 8725
  §3.11 token-type discrimination: `validate_token` rejects JARM JWTs
  as Bearer tokens at the `typ`-header check before any claim parsing.
  JARM JWT lifetime capped at 300 s (FAPI 2.0 §5.3.2.2) and `iat` claim added.

### Added

- **JAR on direct `/authorize` (HEA-983)** — the `GET /authorize` endpoint now
  accepts a `request=<signed-JWT>` parameter (RFC 9101). When present, Hearth
  verifies the JWT signature against the client's registered JWKS (EdDSA, RS256,
  PS256, ES256), enforces `iss == client_id`, `aud == realm issuer URL`, `exp`,
  `nbf`, and per-realm JTI replay prevention, then uses the JWT claims to
  override the outer query parameters before processing the authorization request.
  Discovery now advertises `request_object_signing_alg_values_supported:
  ["RS256", "PS256", "ES256", "EdDSA"]`.

- **JARM — JWT Authorization Response Mode (HEA-979)** — clients may request
  `response_mode=jwt`, `query.jwt`, or `fragment.jwt` to receive the
  authorization response wrapped in a realm-signed EdDSA JWT containing
  `{iss, aud, exp, code, state}`. The redirect carries `response=<jwt>` instead
  of plain `code=...&state=...`, providing end-to-end integrity for the browser
  redirect. Discovery now advertises `query.jwt`, `fragment.jwt`, and `jwt` in
  `response_modes_supported` (OAuth 2.0 JARM).

- **FAPI 2.0 Security Profile — per-client `ClientProfile::Fapi2` (HEA-980)** —
  individual OAuth 2.0 clients may now be registered with `"profile": "fapi2"`.
  Clients in this profile must use `private_key_jwt` (no `client_secret`), must
  register a JWKS, must submit every authorization request via PAR (`via_par`),
  must supply a DPoP proof at the token endpoint, and receive `s_hash` in JARM
  responses when `state` is present. Standard clients in the same realm are
  completely unaffected. See `docs/specs/OIDC.md §2.2` for the full normative
  spec (HEA-980).

- **FAPI 2.0 Security Profile enforcement (HEA-987)** — realms may now declare
  `fapi_profile: baseline` or `fapi_profile: advanced` in their configuration.
  **Baseline** mandates PAR (RFC 9126) and PKCE (S256) on every authorization
  request. **Advanced** additionally requires JAR (RFC 9101) in the PAR body,
  JARM (`authorization_signed_response_alg` on the client), and a registered
  client JWKS (`private_key_jwt`). The OIDC discovery document now advertises
  `fapi_profile` when a realm is in either mode. Clients in non-FAPI realms are
  unaffected (HEA-987).

- **Mandatory JARM per client (HEA-986)** — `OAuthClient` now carries an
  `authorization_signed_response_alg` field (`EdDSA` only). When set via
  `RegisterClientRequest` or `UpdateClientRequest`, every authorization response
  for that client is automatically promoted to JARM regardless of the
  `response_mode` in the request — a plain `query` or `fragment` request is
  silently upgraded to `query.jwt`. Registration rejects unsupported algorithm
  values at creation time. Discovery advertises
  `authorization_signing_alg_values_supported: ["EdDSA"]` (HEA-986).

- **`private_key_jwt` client authentication (HEA-984)** — confidential clients
  can now authenticate to the token endpoint by presenting a self-signed EdDSA
  JWT assertion (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`)
  instead of a `client_secret`. Hearth verifies the assertion against the
  client's registered Ed25519 public key, enforces `iss`/`sub == client_id`,
  `aud == realm issuer URL`, `exp` in the future, and replay prevention via
  per-realm JTI tracking. Discovery advertises `private_key_jwt` in
  `token_endpoint_auth_methods_supported` (RFC 7523 §2.2 / OIDC Core §9).

### Security

- **JWT Bearer grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`) hardening (HEA-999)** —
  several security gaps in the RFC 7523 JWT Bearer token endpoint are resolved:
  - `jti` is now mandatory; assertions without a JWT ID are rejected (`invalid_grant`).
  - `sub` must equal `client_id` (RFC 7523 §3 / OIDC Core §9); mismatches are rejected.
  - Assertion lifetime is capped at 10 minutes; requests with `exp > now + 600 s` fail.
  - JTI store migrated to exp-bounded values with `saturating_add` overflow safety; entries
    auto-expire after their validity window so storage does not grow unboundedly.
  - The JTI check-and-consume is now atomic per realm (per-realm mutex), eliminating the
    TOCTOU race between `storage.get` and `storage.put`.

- **Token endpoint client-auth error normalization (HEA-994)** — all client
  authentication failures on the token endpoint now return HTTP 401
  `"invalid_client"` regardless of whether the client ID is unknown or the
  credential is wrong. Previously `InvalidClient` returned HTTP 400, creating
  a distinguishable oracle for client ID enumeration (OAuth 2.0 Security BCP
  §2.2 / RFC 6749 §5.2). gRPC `InvalidClientAssertion` also no longer leaks
  the internal reason string to callers (HEA-992).

- **`private_key_jwt` JTI replay-store purged on realm deletion (HEA-995)** —
  `oauth:ca-jti:*` sentinels are now swept during cascade realm delete,
  preventing unbounded storage growth when realms are recycled.

- **Session limit enforcement hardening (HEA-982)** — five findings from the
  HEA-981 security review are resolved:
  - **SEC-1 (TOCTOU):** The per-user lock now covers the session write; the
    count → evict → write sequence is fully atomic under one guard.
  - **SEC-2 (Default policy):** `SessionLimitPolicy` default changed from
    `EvictOldest` to `RejectNew`. Operators opt in to eviction via
    `session_over_limit_policy = "evict_oldest"`. Prevents attacker-driven
    silent eviction of victim sessions.
  - **SEC-3 (Silent fallback):** An unrecognised `session_over_limit_policy`
    string now returns a hard `RegistryError::InvalidRealmConfigField` at
    config parse time instead of silently falling back to the default.
  - **SEC-4 (gRPC information leak):** The gRPC error message for session
    limit exceeded is now the generic string `"session limit reached"`;
    active count and configured limit are no longer exposed to callers.
  - **SEC-5 (Fail-open):** A `get_realm` storage error during session
    creation now propagates to the caller and rejects the session, rather
    than skipping limit enforcement and proceeding.

- **Unknown `response_mode` rejected with `invalid_request` (HEA-1005)** —
  two call sites in the OAuth authorization handler previously used `.ok()` to
  silently discard `response_mode` parse failures, causing unrecognized values
  (typos, unsupported modes such as `"form_post.jwt"`) to fall through to plain
  `query` mode. A client requiring JARM would receive an unprotected plain-text
  redirect with no error signal, defeating the integrity guarantee JARM provides.
  Both the bypass path (direct code issue without consent page) and the consent
  completion path now return an `invalid_request` redirect immediately when the
  `response_mode` value cannot be parsed (FAPI 2.0 / RFC 9207 / JARM spec
  compliance, Medium severity).

### Added

- **`private_key_jwt` client authentication (HEA-984)** — Confidential clients can now
  authenticate to the token endpoint using RFC 7523 §2.2 `private_key_jwt` assertions instead
  of a `client_secret`. Clients register an Ed25519 public key via `assertion_public_key`;
  the AS verifies the self-signed JWT, enforces `iss == sub == client_id`, checks `aud` against
  the realm issuer URL, validates `exp`, and prevents JTI replay. Both `authorization_code` and
  `client_credentials` grant types are supported. Discovery advertises
  `token_endpoint_auth_methods_supported: ["none", "client_secret_post", "private_key_jwt"]`.

- **RFC 9207 authorization response `iss` — formal test coverage (HEA-985)** —
  Added `tests/rfc9207_iss.rs` with 6 integration tests confirming that every
  successful authorization response carries a non-empty `iss` parameter matching
  the OIDC discovery document issuer, that the discovery document advertises
  `authorization_response_iss_parameter_supported: true` (both global and per-realm),
  and that `iss` is stable across repeated requests.

- **Helm chart lint + template-test CI (HEA-974)** — `make helm-lint` runs `helm lint` against
  `deploy/helm/hearth/`; `make helm-template` renders the chart with both `values.yaml` and the
  new `values-prod.yaml` production profile and diffs the output against committed snapshots in
  `deploy/helm/hearth/tests/`. A new `.github/workflows/helm.yml` CI job runs both gates on every
  PR or push that touches `deploy/helm/**`. `deploy/README.md` now includes an end-to-end
  production install walkthrough (`helm install hearth deploy/helm/hearth -f values-prod.yaml`).

- **Proto governance gates (HEA-973)** — `buf` is now required and governed across the full
  development workflow. `buf lint` and `buf format` run in the pre-commit hook whenever
  `.proto` files are staged (format → lint → regenerate, atomic commit). A dedicated
  `.github/workflows/proto.yml` CI job runs `buf lint`, `buf format --diff --exit-code`, and
  `buf breaking --against main` on every proto-touching PR. New Makefile targets:
  `make proto-format` (in-place reformat), `make proto-format-check` (CI drift gate).
  `docs/specs/PROTO.md` documents RPC naming conventions, `google.api.http` bindings,
  `json_name` usage, backward-compatibility rules, and pre-existing lint exceptions.

- **OpenAPI 3.0 spec served from binary (HEA-972)** — `GET /openapi.json` and
  `GET /openapi.yaml` now serve a merged OpenAPI 3.0 spec; `GET /docs` serves Swagger UI.
  All 63 proto RPCs annotated with `google.api.http` bindings; `docs/api/openapi.json` is the
  canonical committed artifact (82 paths, produced by `make openapi`).  A drift gate in
  `tests/openapi.rs` fails the build if the committed spec diverges from the route table.
  `docs/api/grpc-only.txt` enumerates the 21 RPCs that are intentionally gRPC-only (HEA-972).

- **Concurrent session limits (HEA-971)** — `RealmConfig` gains `max_concurrent_sessions: Option<u32>`
  and `session_over_limit_policy: SessionLimitPolicy` (`reject_new` | `evict_oldest`, default
  `reject_new`). When the limit is reached, `RejectNew` returns HTTP 429 / gRPC
  `RESOURCE_EXHAUSTED` with error code `session_limit_exceeded`; `EvictOldest` revokes the
  oldest active session and allows the new one. Configurable globally under `[session]`
  (`session_max_concurrent`, `session_over_limit_policy`) and per-realm in `hearth.yaml`.
  Each enforcement writes a `session_limit_enforced` audit event (HEA-971).

- **Kotlin SDK spec conformance (HEA-964)** — `Claims` gains four new accessors:
  `inOrg(o)`, `tokenType()`, `organizationId()`, `orgGroups()`; new `RequiredActionError`
  with `requiredActions: List<String>` and optional `redirectUri`; `requirePermission`
  middleware rejects `token_type=required_action` tokens with `RequiredActionError` across
  all modes (EMBEDDED/DECISION/INTROSPECTION) before any network call (spec §6 rule 6);
  `AdminClient` gains `realmId` constructor param + `X-Realm-ID` header on every request,
  full CRUD for OAuth clients (`/admin/clients`), roles (`/admin/roles`),
  groups (`/admin/groups`), and org memberships (`/admin/orgs/{id}/members`) with
  corresponding types (`Role`, `Group`, `OrgMember`, etc.) (HEA-964).

- **Rust SDK spec conformance (HEA-965)** — `Claims` gains six new accessors:
  `scope()`, `inGroup(g)`, `inOrg(o)`, `tokenType()`, `organizationId()`,
  `orgGroups()`; new `RequiredActionError` variant with `required_actions: Vec<String>`
  and optional `redirect_uri`; Tower middleware short-circuits `token_type=required_action`
  tokens with HTTP 401 before any permission check (spec §6 rule 6); `AdminClient`
  gains full CRUD for OAuth clients (`/admin/clients`), roles (`/admin/roles`),
  groups (`/admin/groups`), and org memberships (`/admin/orgs/{id}/members`) with
  corresponding request/response types.

- **Go SDK spec conformance (HEA-961)** — `Claims` gains six new accessors:
  `Scope()`, `InGroup(g)`, `InOrg(o)`, `TokenType()`, `OrganizationId()`,
  `OrgGroups()`; new `RequiredActionError` with `RequiredActions []string` and
  optional `RedirectURI`; middleware adds `OnRequiredAction` callback and rejects
  `token_type=required_action` tokens with HTTP 401 (spec §6 rule 6); `AdminClient`
  gains full CRUD for OAuth clients (`/admin/clients`), roles (`/admin/roles`),
  groups (`/admin/groups`), and org memberships (`/admin/orgs/{id}/members`);
  `ListUsers` and `ListRealms` now accept `ListOptions{Limit, Cursor}` for cursor
  pagination.

- **Python SDK spec conformance (HEA-962)** — `Claims` gains six new accessors:
  `scope()`, `in_group(g)`, `in_org(o)`, `token_type()`, `organization_id()`,
  `org_groups()`; new `RequiredActionError` with `required_actions: list[str]`
  and optional `redirect_uri`; WSGI + ASGI middleware now return `401` (not `403`)
  for `required_action` tokens (spec §6 rule 6); `AdminClient` gains full CRUD for
  OAuth clients (`/admin/clients`), roles (`/admin/roles`), groups (`/admin/groups`),
  and org memberships (`/admin/orgs/{id}/members`).

- **TypeScript browser SDK spec §4/§5/§7 conformance (HEA-960)** — `Claims` class
  gains six new accessors: `scope()`, `inGroup(g)`, `inOrg(o)`, `tokenType()`,
  `organizationId()`, `orgGroups()`; new `RequiredActionError` type with
  `requiredActions: string[]` and optional `redirectUri`;
  `HearthApiClient.handleCallback()` exchanges the PKCE auth code and throws
  `RequiredActionError` when the returned token has `token_type === "required_action"`
  or the callback URL carries `required_action_redirect_uri`.

- **Node SDK spec conformance (HEA-959)** — `@hearth/node` now fully implements the
  SDK spec (§4 Claims, §5 Errors, §6 Middleware, §12 AdminClient):
  - Claims: `audiences()` (was `audience()`), `expiry()` (was `expiresAt()`), plus new
    `jwtID()`, `inGroup()`, `inOrg()`, `tokenType()`, `organizationId()`, `orgGroups()`.
  - Errors: `JWKSFetchError` (renamed from `JwksFetchError`), `TokenNotYetValidError`,
    `TokenInvalidError`, `TokenIssuerError`, `TokenAudienceError`, `RequiredActionError`
    (with `requiredActions: string[]` and optional `redirectUri`).
  - Middleware: detects `token_type === "required_action"` and responds 401 + throws
    `RequiredActionError` (Express and Fastify adapters).
  - `AdminClient` — new separate entry point; takes `(base_url, realm_id, access_token)`;
    sends `X-Realm-ID` header on every request; full CRUD + list for users, realms,
    clients, roles, groups, and org memberships.

- **PHP SDK Phase 1** — core scaffold at `sdks/php/`: `composer.json` (PHP 8.1+,
  PSR-4/PSR-12, `lcobucci/jwt` v5, Guzzle, PSR-7/15/17/18 interfaces),
  10 exception classes, 4 type classes (`IntrospectionResult`, `TokenResponse`,
  `UserInfoResponse`, `PageResponse<T>`), `Claims` (17 spec-compliant accessors),
  `JwksClient` (OKP/Ed25519 with 5-rule JWKS caching contract), `TokenVerifier`
  (libsodium Ed25519 + exp/iss/aud/iat validation), `IntrospectionClient` (RFC 7662),
  `HearthClient` (OIDC discovery, code exchange, verifyToken, getUserInfo),
  `AdminClient` (CRUD + paginated list for users, realms, clients, roles, groups,
  org memberships), `Middleware/HearthMiddleware` (PSR-15 Bearer auth, required-action
  detection). Includes PHPUnit 10 stub test suite and PHPStan level-8 config (HEA-954).

### Security

- **ReDoS fix in Node SDK error sanitizer** — replaced the backtracking regex in
  `sdks/node/src/errors.ts` `sanitize()` with a linear O(n) charcode scan; a crafted
  input like `eyJeyJeyJ…` (no dots) caused O(n²) regex backtracking in V8 on any
  `HearthError` message containing JWT-shaped tokens (HEA-958, CodeQL CWE-1333).

- **Patch example project vulnerabilities (Groups C + D)** — upgraded Go example
  (`examples/go-gin`) via `go get -u ./...`: `gin` 1.10→1.12, `golang.org/x/crypto`
  0.29→0.52, `net` 0.25→0.55, plus all transitive stdlib-linked deps. Upgraded
  TypeScript example (`examples/typescript-nextjs`) to `next@15.5.18` (fixes
  GHSA-9g9p-9gw9-jx7f DoS) with `postcss` override `^8.5.15` (fixes GHSA-qx2v-qp2m-jg93
  XSS). Both examples now build with `npm audit` reporting 0 vulnerabilities. Resolves
  60 Group C + D security alerts (HEA-953).

- **Patch docs-site npm vulnerabilities (Group B)** — upgraded `@docusaurus/core` and
  `@docusaurus/preset-classic` from 3.5.2 → 3.10.1; added `overrides` for
  `serialize-javascript` (→ ^7.0.0, fixes GHSA-5c6j-r48x-rmvq HIGH XSS/code-injection),
  `uuid` (→ ^11.0.0, fixes GHSA-w5hq-g745-h8pq buffer-bounds), and `webpackbar`
  (existing). Resolves all 9 Group B security alerts; `npm audit` now reports 0
  vulnerabilities in docs-site (HEA-952).

- **Pin GitHub Actions to SHA hashes** — all `uses:` references in `release.yml`,
  `docs-site.yml`, and `sdk-smoke.yml` are now pinned to immutable 40-char commit SHAs
  (e.g. `actions/checkout@34e114...` `# v4`) to eliminate supply-chain risk from mutable
  tags. Resolves 26 Dependabot/security alerts. `slsa-framework/slsa-github-generator` is
  exempt as a reusable-workflow call; that alert is dismissed as a false positive (HEA-951).

### Changed

- **License** — re-licensed from AGPL-3.0-only (dual-license) to Apache-2.0. `LICENSE-COMMERCIAL`
  and `NOTICE` dual-license overlay removed. `LICENSE` now contains the Apache 2.0 text (HEA-912).

### Added

- **Session-version (`sv`) revocation** — access tokens now carry an `sv` claim (monotonic
  `u64`) when `session_version.enabled = true` in the realm config. Resource servers can
  poll the delta feed to detect revoked sessions without waiting for token expiry. The `sv`
  counter is bumped automatically on: logout, admin session revoke, password change, role
  assignment/unassignment, and group membership add/remove. New endpoints:
  - `GET /oauth/session-versions?realm=<id>&since=<seq>` — paginated delta feed; returns
    `null` when `since` is behind the retention window (`delta_retention_seconds`, default
    3600). Requires `hearth.sv_feed` or `hearth.admin` permission.
  - `GET /oauth/session-versions/snapshot?realm=<id>` — gzip-compressed full snapshot of
    current per-session minimum `sv` values.
  - `POST /admin/sessions/{id}/sv-bump` — admin: force-bump a single session.
  - `POST /admin/realms/{id}/sv-bump-all` — admin: force-bump every tracked session in the
    realm (returns count).
  The `hearth.sv_feed` permission is seeded in all new realms via `seed_realm`. When
  `session_version.enabled = false` (default) the claim is omitted and all sv endpoints
  return 404 (HEA-932).

- **Session-version revocation operator guide (HEA-934)** — new how-to at
  `docs/guides/session-version-revocation.md` covering: when to enable `sv`, poll interval
  and stale threshold tradeoffs, bump trigger table, `sv-bump-all` use cases, fail-closed
  behavior (`reject` vs `introspect` fallback), DPoP/MFA interaction notes, and delta feed
  reference. `AUTHORIZATION.md` § 14 updated from roadmap placeholder to implemented status.

- **Admin UI client form exposes `access_token_authorization` mode** — the application
  create and edit forms in the Admin UI now include a Permission delivery mode picker
  (`Embedded`, `Introspection`, `Decision`) bound to `OAuthClient.access_token_authorization`.
  The client list and detail pages display the current mode. A warning banner appears when
  `Decision` mode is selected on a public (SPA/mobile) client (HEA-931).

- **Org-scoped group paths in OIDC token claims** — tokens issued in an organization
  context now carry an `org_groups` claim (`Vec<String>`) alongside the existing flat
  `groups` claim. Each entry uses the `/org-slug/group-name` path format, matching
  Keycloak 26.6 conventions and enabling downstream services to determine org-membership
  context in multi-org tenancy scenarios. The flat `groups` claim is preserved unchanged
  for backward compatibility. Tokens without an org context do not emit `org_groups`
  (HEA-909).

- **JWT Bearer Token Grant (RFC 7523)** — clients can now authenticate using a self-signed
  Ed25519 JWT assertion instead of a client secret. Register a 32-byte base64url-encoded
  Ed25519 public key on any `OAuthClient` via `assertion_public_key`. The grant type
  `urn:ietf:params:oauth:grant-type:jwt-bearer` is now listed in OIDC discovery
  `grant_types_supported`. JTI replay prevention is enforced per-realm. Supported on both
  `POST /token` and `POST /realms/{realm}/token` endpoints (HEA-908).

- **Permission-delivery modes guide (HEA-929)** — new operator how-to at
  `docs/guides/permission-delivery.md` covering `embedded`, `introspection`, and `decision`
  modes: decision tree, latency tradeoff table, wire-shape examples, security rules per mode,
  and Keycloak comparison table. `docs/specs/AUTHORIZATION.md` extended with normative
  §15 (wire shapes, security rules, revocation caveat, latency targets, client config).
  `docs/specs/ARCHITECTURE.md` §4.2.1 updated to classify `/introspect` and
  `POST /oauth/authorize` as off-hot-path.

- **Node SDK: `authorize()` + mode-aware middleware (HEA-924)** — the Node.js server SDK
  at `sdks/node/` now exposes the three permission-delivery modes introduced in HEA-922:
  - `HearthClient.authorize(token, permission, opts?)` — calls `POST /oauth/authorize` for
    Decision-mode resource servers. Fail-closed: returns `{ allowed: false }` on any network
    or server error. Pass `realm_id` in `HearthConfig` to include `X-Realm-ID`.
  - `IntrospectionResult` extended with `mode`, `permissions`, `roles`, and `groups` fields
    populated by Hearth for Introspection/Decision clients.
  - `hearthMiddleware` / `hearthFastifyHook` accept `expectedMode` (`"embedded"` |
    `"introspection"` | `"decision"`). MUST NOT silently fall back to a different mode when
    `permissions` is absent from the JWT — absence of `permissions` never changes authorization
    behavior unless `expectedMode` is changed. Fail-closed: network errors on `/introspect`
    or `/oauth/authorize` result in 403.
  - Mode-echo validation: in `introspection` mode, if the server echoes a different
    `mode` than `expectedMode`, the request is rejected (fail-closed 403).
  New exports: `AccessTokenAuthorizationMode`, `AuthorizationModeError`, `AuthorizeError`,
  `AuthorizeClient`, `AuthorizeOptions`, `AuthorizeResult`.
  New config fields: `realm_id`, `authorize_endpoint`.

- **TypeScript SDK: `authorize()` + mode-aware middleware (HEA-923)** — the TypeScript SDK
  at `sdks/typescript/` now exposes the three permission-delivery modes introduced in HEA-922:
  - `HearthClient.authorize(token, permission, opts?)` — calls `POST /oauth/authorize` for
    Decision-mode resource servers. Fail-closed: returns `false` on any network or server error.
    Requires `realmId` in `HearthClientConfig`.
  - `HearthClient.introspect(token)` — wraps RFC 7662 introspection with optional mode-echo
    validation. Throws `AuthorizationModeMismatchError` when `expectedMode` is configured and
    the server returns a different `mode` field.
  - `requirePermission(permission, opts)` — framework-agnostic middleware factory. Takes an
    explicit `mode` (`"embedded"` | `"introspection"` | `"decision"`); MUST NOT silently fall
    back to a different mode when `permissions` is absent from the JWT. Returns a
    `(token: string) => Promise<boolean>` checker.
  New exports: `AccessTokenAuthorizationMode`, `AuthorizePermissionOptions`,
  `AuthorizationModeMismatchError`, `requirePermission`, `PermissionChecker`,
  `RequirePermissionOptions`.

- **Three access-token authorization modes (HEA-922)** — `OAuthClient` now has an
  `access_token_authorization` field with three modes:
  - `embedded` (default) — RBAC claims (`permissions`, `roles`, `groups`) are embedded in
    the JWT at issuance, enabling fully stateless validation by resource servers.
  - `introspection` — JWT carries only identity claims; resource servers call
    `POST /realms/{realm}/introspect` for live RBAC data. The introspection response
    now includes `mode`, `permissions`, `roles`, and `groups` fields for
    Introspection/Decision clients.
  - `decision` — JWT carries only identity claims; resource servers call the new
    `POST /oauth/authorize` endpoint per-request for a binary allow/deny answer.
  The `POST /oauth/authorize` endpoint validates the bearer token (signature, expiry,
  session liveness) and then resolves live RBAC to check the requested permission.
  Fails closed on any validation error. Admin API and gRPC `OAuthService.Decide` rpc
  updated accordingly. Existing clients without an explicit mode default to `embedded`
  for full backward compatibility.

- **DPoP (Demonstrating Proof-of-Possession — RFC 9449)** — token endpoints now
  validate DPoP proof JWTs (`alg`, `jwk`, `htu`, `htm`, `iat`, `jti`). Access tokens
  issued with a proof carry `cnf.jkt` (JWK thumbprint) binding. Replay prevention via
  in-process JTI cache with TTL-based eviction. Stateless HMAC-SHA256 nonce generation
  with 5-minute sliding windows. `DPoP-Nonce` header returned on every token response.
  `dpop_signing_alg_values_supported: [ES256, EdDSA]` added to OIDC discovery (HEA-907).

### Security

- **Required-actions bypass via ROPC closed (HEA-905)** — `password_grant_token` now checks
  `user.required_actions()` after credential verification and returns `RequiredActionsBlocking`
  when any actions are pending. HTTP surface maps this to `400 {"error":"required_actions_pending",
  "actions":[...]}`. Previously only the browser-path interstitial enforced this gate, allowing
  clients using the direct password grant to obtain valid access tokens despite pending
  `UPDATE_PASSWORD`, `VERIFY_EMAIL`, or `ENROLL_PHONE_OTP` requirements.

- **GDPR Art.17: device fingerprint erasure cascade + admin API (HEA-875)** — `delete_user`
  now cascades to all `dfp:user:{uid}:*` storage entries so right-to-erasure is complete.
  New endpoint `DELETE /admin/users/{id}/device-fingerprints` (AC-11) lets operators satisfy
  DSAR erasure requests without deleting the entire account; returns `{"erased": N}` and
  emits a `DeviceFingerprintsErased` audit event. Also fixed: `derive_fingerprint_key` helper
  was producing keys with the stale `dev:fp:` prefix instead of the correct `dfp:user:` prefix.

- **CSP regression fix: inline styles eliminated (HEA-876)** — Two regressions from the
  HEA-850 `style-src 'self'` hardening are resolved. Theme CSS is now served via external
  `<link>` tags (`/ui/static/theme.css`, `/ui/static/realm-theme/{id}`) instead of inline
  `<style>` blocks. HTMX's startup `insertAdjacentHTML` style injection for `.htmx-indicator`
  is suppressed with `<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>`;
  indicator styles are declared in `app.css` instead.

- **CSP hardened: `unsafe-eval` and `unsafe-inline` removed (HEA-850)** — Alpine.js
  has been fully replaced by HTMX + Hyperscript across all ~40 admin templates.
  Layout reactivity (sidebar toggle, realm nav tree, toast notifications, realm pill)
  is now handled by vanilla JS classes (`SidebarManager`, `RealmNav`, `ToastManager`)
  in `admin.js`. Template interactions use Hyperscript `_="..."` attributes, which are
  eval-free. The CSP is now `script-src 'self'; style-src 'self'` with no unsafe
  keywords. Resolves GAP-4 and GAP-5 from the original security audit.

- **Pushed Authorization Request endpoint (RFC 9126, HEA-906)** — `POST /as/par` (global)
  and `POST /{realm}/as/par` (realm-scoped) accept authorization parameters from clients and
  return a `request_uri` with a 90-second TTL. The `request_uri` is single-use; replaying it
  returns `invalid_request`. PKCE (`S256`) is required for public clients. The OIDC discovery
  document now includes `pushed_authorization_request_endpoint`. Expired PAR entries are
  removed by the periodic background sweeper (`CleanupStats.par_requests_deleted`).

- **`make ci-local-full`** — full container reproduction of PR-blocking GHA
  workflows via `nektos/act`; catches workflow-file errors and toolchain drift
  that the host-side `ci-local-fast` cannot. Targets 10–15 min cold on a
  developer's host. See `CONTRIBUTING.md` for install instructions and
  known-skipped workflows ([HEA-891](/HEA/issues/HEA-891)).
- **`make ci-local-fast`** — single target that runs the seven PR-blocking CI
  checks on the developer's host in ~5 min cold: `test-quality`, `check`
  (clippy + fmt + nextest), `css-check`, `proto-check`, `cargo deny`,
  `sdk-conformance`, and `sdk-smoke-local` (HEA-890).
- **`make sdk-smoke-local`** — builds hearth (debug), boots `--dev` on a random
  free port, runs TypeScript/Next.js and Go/Gin SDK example smokes, then tears
  down. Mirrors the `sdk-smoke` CI workflow without requiring Docker (HEA-890).

### Fixed

- **Admin sidebar chevron icon (HEA-886)** — the realm-tree expand chevron in
  the admin sidebar was rendered as `<polyline points="M9 18 15 12 9 6">` —
  path-language passed to a polyline element silently produced no output. The
  helper now dispatches `d` for `<path>` and `points` for `<polyline>`/
  `<polygon>` based on the requested SVG tag.

### Security

- **CSP `script-src 'self'`: 10 inline `<script>` blocks extracted (HEA-886)** —
  Per-page inline scripts in admin templates (`groups/new`, `webhooks/new`,
  `settings/editor`, `users/import`, `users/list`, `users/new`,
  `organizations/new`, `organizations/edit`, `rbac/debug`) and the dev
  mailcatcher (`dev/mail_detail`) now load from cacheable external files under
  `/ui/static/admin/*.js` and `/ui/static/dev/mail-detail.js`. Template-rendered
  values are passed via `data-*` attributes (e.g. `data-slug-touched`,
  `data-test-ping-url`, `data-total-users`). The dev mail detail page also
  loses its inline `onclick="showTab(...)"` and `onsubmit="return confirm(...)"`
  handlers in favour of `addEventListener`-based dispatch. CSP stays
  `script-src 'self'` (no nonce, no `'unsafe-inline'`).

- **GDPR Art.17: device fingerprint erasure cascade + admin API (HEA-875)** — `delete_user`
  now cascades to all `dfp:user:{uid}:*` storage entries so right-to-erasure is complete.
  New endpoint `DELETE /admin/users/{id}/device-fingerprints` (AC-11) lets operators satisfy
  DSAR erasure requests without deleting the entire account; returns `{"erased": N}` and
  emits a `DeviceFingerprintsErased` audit event. Also fixed: `derive_fingerprint_key` helper
  was producing keys with the stale `dev:fp:` prefix instead of the correct `dfp:user:` prefix.

- **CSP regression fix: inline styles eliminated (HEA-876)** — Two regressions from the
  HEA-850 `style-src 'self'` hardening are resolved. Theme CSS is now served via external
  `<link>` tags (`/ui/static/theme.css`, `/ui/static/realm-theme/{id}`) instead of inline
  `<style>` blocks. HTMX's startup `insertAdjacentHTML` style injection for `.htmx-indicator`
  is suppressed with `<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>`;
  indicator styles are declared in `app.css` instead.

- **CSP hardened: `unsafe-eval` and `unsafe-inline` removed (HEA-850)** — Alpine.js
  has been fully replaced by HTMX + Hyperscript across all ~40 admin templates.
  Layout reactivity (sidebar toggle, realm nav tree, toast notifications, realm pill)
  is now handled by vanilla JS classes (`SidebarManager`, `RealmNav`, `ToastManager`)
  in `admin.js`. Template interactions use Hyperscript `_="..."` attributes, which are
  eval-free. The CSP is now `script-src 'self'; style-src 'self'` with no unsafe
  keywords. Resolves GAP-4 and GAP-5 from the original security audit.

### Added

- **Device fingerprint proactive TTL sweeper (HEA-862)** — a background task now
  runs every 6 hours (configurable via `identity.cleanup.dfp_sweeper_interval_secs`)
  and evicts expired `dfp:user:*` storage entries across all realms. This satisfies
  the GDPR 30-day retention window for users who stop logging in. Two new Prometheus
  metrics are exported: `hearth_dfp_sweeper_evicted_total` (cumulative counter of
  evicted entries) and `hearth_dfp_keys_active` (gauge, sampled per sweep). Errors
  are logged at `WARN` level and do not crash the process.

- **Device fingerprint HMAC secrets pipeline (HEA-858)** — operator guidance, Helm
  wiring, and CI guard for the per-realm `adaptive_mfa.fingerprint_hmac_secret`
  introduced by HEA-836. `hearth.example.yaml` now documents the
  `${HEARTH_REALM_<NAME>_FINGERPRINT_HMAC_SECRET}` env-substitution pattern;
  `deploy/helm/hearth/values.yaml` documents the matching `secret.env` naming
  convention; `docs/guides/security-hardening.md` adds a "Device fingerprint HMAC
  secret" section with generation, storage, and a step-by-step rotation runbook
  (including blast-radius notes — rotation invalidates the per-realm device
  recognition cache, briefly increasing step-up MFA challenges). A new CI guard
  (`scripts/check-secret-hygiene.sh`, run from the `filter` job on every PR)
  fails the build if any tracked file contains a `fingerprint_hmac_secret`
  literal that is not an empty string, a `${VAR}` substitution, or a documented
  test sentinel.

- **SMS MFA realm config (HEA-855)** — `RealmConfig` gains two new optional fields:
  `sms_otp_expiry_seconds` (override default OTP lifetime per realm) and
  `sms_otp_max_attempts` (override maximum guess attempts per realm). Both are
  configurable via `PATCH /admin/realms/{realm}/config` (JSON API) and the admin
  realm settings UI. `"sms"` is now a valid value in the `mfa_methods` array.

- **Admin user phone management (HEA-855)** — the admin user detail page now shows
  the user's phone number in masked form (`+1***-***-1234`) alongside its verification
  status. A **Remove Phone** button clears the number and automatically adds
  `ENROLL_PHONE_OTP` to the user's required actions so they are prompted to
  re-enroll on next login. Exposed as `POST /ui/admin/realms/{realm}/users/{id}/remove-phone`.

### Security

- **Sensitive config fields wrapped in `SecretString` (HEA-869)** — `AdaptiveMfaConfig.fingerprint_hmac_secret`
  and `BreachCheckConfig.hibp_api_key` were typed as `String` with `#[derive(Debug)]`, which exposed
  their plaintext values in any `{:?}` output (tracing debug logs, assertion panics, `dbg!` macro).
  Both fields are now `secrecy::SecretString`; `Debug` is implemented manually and emits `[REDACTED]`.
  Call sites updated to call `.expose_secret()` only at the point of cryptographic use (CWE-532, High).

- **Step-up MFA follow-up hardening (HEA-861)** — four deferred findings from the
  HEA-836 SecurityAuditor re-review resolved: (1) duplicate `record_device_fingerprint`
  call removed from the `Recognised` path (triple write on every recognised login);
  (2) silent `let _ =` discard on `StepUpMfaTriggered` audit replaced with
  `tracing::warn` so broken audit pipelines surface in logs; (3) `StepUpMfaCompleted`
  audit event added to `step_up_mfa_grant_token` on success, enabling
  trigger → resolution correlation; (4) `fingerprint_hmac_secret` minimum-length
  guard tightened to ≥ 32 bytes (NIST SP 800-107 / SHA-256 output length) — secrets
  shorter than 32 bytes with `adaptive_mfa.enabled=true` now fail-secure with a
  configuration error.

- **Step-up MFA rate-limit gaps closed (HEA-836)** — three additional findings
  from the SecurityAuditor re-review resolved: the pre-flight IP rate-limit check
  now covers `grant_type=urn:hearth:params:grant-type:step-up-mfa` (previously
  only `password` was guarded); `verify_recovery_code` now enforces the same
  per-user 5-attempt MFA lockout as TOTP so recovery codes cannot bypass the
  rate limit; failed MFA codes in the step-up handler now advance the IP-level
  login-attempt counter so MFA failures feed back into adaptive IP blocking.

- **Step-up MFA security hardening (HEA-836)** — five SecurityAuditor findings
  resolved: `enabled=true` with an empty `fingerprint_hmac_secret` now returns a
  hard configuration error instead of silently bypassing step-up (fail-secure);
  non-UTF-8 HMAC secret degradation to empty string removed at the type level;
  `EnrollMfaRequired` path now uses `update_user()` (atomic read-modify-write)
  instead of a direct `storage.put()` that was subject to a TOCTOU race;
  User-Agent is normalised to major version only before HMAC so minor browser
  auto-updates no longer trigger spurious step-up challenges.

- **Step-up MFA completion endpoint (HEA-836)** — added
  `grant_type=urn:hearth:params:grant-type:step-up-mfa` token endpoint that
  re-verifies the user's password, validates TOTP (or recovery code), records
  the device fingerprint as trusted, and issues a full token pair.  Without this
  endpoint users with enrolled MFA on an unrecognised device received 401 forever.

- **Phone number PII masking in SMS transport logs (HEA-857)** — all three SMS
  transports (Twilio, AWS SNS, Log) now emit only the masked form of the recipient
  phone number in tracing output (`+***4567` instead of the full E.164 number),
  satisfying AC 3.5.2. The `mask_phone` helper lives in `src/identity/sms/mod.rs`.

- **CSP GAP-4 remediation (HEA-824)** — vendored Hyperscript 0.9.13 as the
  eval-free replacement for Alpine.js; tooltip patterns migrated to pure CSS
  (`group-hover`/`group-focus-within`); audit row expand and migrations accordion
  migrated to Hyperscript. Documented the `unsafe-eval` trade-off with threat-model
  rationale in `docs/security/csp.md`. Remaining Alpine components tracked for
  removal in child issues; `unsafe-eval` removal from CSP blocked until complete.

- **WebAuthn Alpine components migrated to eval-free vanilla JS (HEA-849)** —
  `passkeyLogin`, `passkeyManager`, and `passkeyRow` Alpine components replaced
  with `passkey.js`, a plain IIFE that wires WebAuthn ceremonies to static DOM
  elements via `id` / `data-*` selectors. All three WebAuthn POST calls now
  include `X-CSRF-Token` from the layout `<meta name="csrf">` tag (previously
  absent). No change to the WebAuthn ceremony logic or server API contract.

### Added

- **ENROLL_PHONE_OTP required action (HEA-853)** — realms with `mfa_methods: [sms]`
  now interrupt the OIDC and browser login flows for users who have no verified phone
  number. The enrollment interstitial collects an E.164 phone number, sends a 6-digit
  SMS OTP, and verifies the code before completing the flow. On success the phone number
  is stored as verified and the action is cleared. Enumeration resistance: uniform
  HTTP 200 responses, timing-safe sends, no notification to the existing holder of a
  claimed number.

- **SMS transport layer** — new `sms:` config block with three providers:
  `log` (dev default), `twilio` (Messaging REST API), and `awssns` (SNS
  Transactional tier, Signature Version 4). Fail-fast startup validation for
  missing Twilio / SNS credentials. `HEARTH_SMS_OTP_HMAC_KEY` env var is
  required in production to cryptographically bind OTP codes to the server
  instance (HEA-851).

- **Adaptive step-up MFA on unrecognised device** — when `adaptive_mfa.enabled = true` on a
  realm, the `password_grant_token` ROPC flow checks an HMAC-SHA256 fingerprint of
  `(user_id, IP /24 subnet, User-Agent)` against a rolling recognition window stored in the
  embedded WAL. Unknown devices return `HEARTH_STEP_UP_CHALLENGE_REQUIRED` (HTTP 401) for
  users with an enrolled factor, or `HEARTH_ENROLL_MFA_REQUIRED` (HTTP 403) for users without
  one (injecting `RequiredAction::EnrollMfa` on the user record). Recognised devices continue
  normally with TTL refresh. A `StepUpMfaTriggered` audit event is emitted on every
  unrecognised-device login attempt. Empty HMAC secrets or disabled config skip the check
  (fail-open). gRPC surfaces both errors via `UNAUTHENTICATED` and `PERMISSION_DENIED`
  respectively (HEA-836).

- **Required-action UI interstitials** — five new browser-facing routes handle the
  required-action flow without API clients:
  - `GET /ui/required-actions/update-password` — password-update form (ra-JWT in query param).
  - `POST /ui/required-actions/update-password` — validates and applies the new password;
    issues UI session cookies and redirects to `/ui/account` on success, or to the next
    required-action page when further actions remain (HEA-765).
  - `GET /ui/required-actions/verify-email` — "check your email" interstitial showing the
    address the verification link was sent to.
  - `POST /ui/required-actions/verify-email/resend` — sends a new verification email;
    redirects back with a flash message on success or rate-limit (HEA-765).
  - `GET /ui/required-actions/verify-email/success` — success page with a 3-second
    auto-redirect countdown (HEA-765).

- **`POST /v1/required-actions/update-password`** — new endpoint that accepts a
  required-action JWT, validates the new password against the realm policy, rotates the
  credential to Argon2id, clears `UPDATE_PASSWORD` from the pending-action set, and returns
  a fresh full-access token pair (or a new required-action token if other actions remain).
  Replay attacks on a completed token are rejected with 401 via stored-state check (HEA-753).

- **VERIFY_EMAIL required-action handler** — `GET /required-action/VERIFY_EMAIL` renders a
  "check your email" page and sends a verification email; if the user's email is already
  verified the action is auto-cleared and the OIDC flow resumes immediately (emits a
  `RequiredActionAutoCleared` audit event with reason `email_already_verified`).
  `GET /required-action/VERIFY_EMAIL/confirm?token={token}` validates the single-use token,
  marks the user `email_verified=true`, clears the action, emits a
  `RequiredActionCompleted` audit event, and resumes the OIDC authorization flow (HEA-808).

- **UPDATE_PASSWORD required-action handler** — `GET /required-action/UPDATE_PASSWORD`
  renders a password-change form; `POST /required-action/UPDATE_PASSWORD` validates the new
  password against realm policy, updates the credential, clears the action from the user
  record, emits a `RequiredActionCompleted` audit event, and resumes the OIDC authorization
  flow (or advances to the next pending action in multi-action sequences) (HEA-809).

- **Required-actions admin API** — two new admin endpoints manage required actions
  without a full user-object PATCH:
  `PATCH /admin/realms/{id}/users/{id}/required-actions` (body `{"add":[],"remove":[]}`)
  assigns or removes actions on a specific user; each change emits a
  `RequiredActionAssigned` or `RequiredActionRemoved` audit event.
  `PATCH /admin/realms/{id}/config` (body `{"default_required_actions":[]}`)
  replaces the realm-level default list applied to newly created users.
  Unknown action strings return 400 (HEA-807).

- **Required actions on users** — user records now carry a `required_actions`
  list (`VERIFY_EMAIL`, `UPDATE_PASSWORD`). Realms may set
  `default_required_actions` so every new user is created with those actions
  pre-populated. Existing stored users deserialize with an empty list (no manual
  migration needed). Admins may clear or replace the list via the update-user API
  (HEA-801).

- **Docusaurus docs site** — `docs-site/` scaffolds a Docusaurus 3.5 site that publishes
  all `docs/guides/*` pages to GitHub Pages via `.github/workflows/docs-site.yml`.
  Hearth-branded dark theme (ember gradient, Fraunces/Manrope/JetBrains Mono), local
  full-text search, and version selector initialized at `next`. Triggered on push to `main`
  when `docs-site/**` or `docs/guides/**` change (HEA-746).

- **Release signing workflow** — every `v*` tag now produces signed release
  binaries for `linux-amd64`, `linux-arm64`, `darwin-amd64`, and `darwin-arm64`
  via `.github/workflows/release.yml`.  Supply-chain trust artefacts included in
  each GitHub Release:
  - **cosign keyless signatures** (`.sig` + `.pem`) — signed with a GitHub Actions
    OIDC identity via Sigstore Fulcio/Rekor; no long-lived key.
  - **SLSA L1 provenance** (`hearth.intoto.jsonl`) — generated by
    `slsa-github-generator`; records the git ref and workflow that produced each binary.
  - **CycloneDX SBOM** (`hearth-sbom.cdx.json`) — full dependency inventory in CycloneDX JSON
    format, signed with cosign.
  - Operator verification instructions: `docs/guides/verify-release.md` (HEA-747).

- **HA failover simulation suite** — four deterministic multi-node Raft simulation tests
  covering network partition heal, leader kill mid-write, rolling restart with zero read
  errors, and snapshot-based catch-up for a cold follower. All tests run in-process via an
  in-memory network factory with no TLS or real ports (HEA-738).

- **Cluster admin HTTP endpoints** — three operator-facing routes on the admin API:
  - `POST /admin/cluster/bootstrap` — initializes Raft membership from `hearth.yaml`
    `cluster.peers` on the designated bootstrap node. Idempotent (409 on
    double-initialization). Requires a `cluster:` block in config; returns 503 in
    single-node mode.
  - `GET /admin/cluster/status` — returns `{role, term, last_applied_index,
    peers: [{id, addr, is_healthy}]}` for the local node. Peer health is derived
    from the leader's replication map.
  - `POST /admin/cluster/transfer-leadership` — gracefully steps the leader down
    and returns `{new_leader_id, exact_target}`. Accepts `target_node_id` for
    forward-compatibility; `exact_target` indicates whether the election winner
    matched the requested target (openraft 0.9 has no targeted-transfer API).
    **Note:** writes are briefly unavailable (~1.5–3 s) during the step-down
    window — do not initiate during write bursts. 409 if this node is not leader.

  All three endpoints require `Authorization: Bearer <admin-token>` with
  `hearth.admin` permission and `X-Realm-ID`; 401 without auth, 403 without
  admin permission (HEA-737).

### Fixed

- **Realm-not-found 404 now renders inside admin chrome (HEA-1116)** — navigating to any
  `/ui/admin/realms/{nonexistent-realm}/*` URL now shows the 404 error inside the normal admin
  sidebar and header instead of a bare unstyled page. The `TargetRealm` extractor re-reads the
  session cookie on the not-found path and renders with chrome when the user is authenticated.

- **Sidebar REALMS section no longer shows "Loading…" indefinitely** — the sidebar realm tree
  now uses synchronous `init()` with explicit proxy capture instead of `async init()`, ensuring
  the fetch's `.finally()` handler always fires and clears the loading state regardless of Alpine
  version behaviour (HEA-1106).
- **Dual ember gradient on empty-state pages** — the secondary CTA in the empty-state panels
  for Webhooks and Organizations no longer uses `btn-ember`; it now uses the muted outline
  button style, so `btn-ember` appears at most once per visible region as required by THEME.md
  (HEA-1106).
- **Missing breadcrumbs on RBAC sub-pages** — the Permissions, Scope Bundles, and Permission
  Check pages now render `Realms › {realm} › {page}` breadcrumb nav in the header, consistent
  with the Roles page (HEA-1106).

- **Browser login bypassed required-action gates** — `login_submit_impl` now intercepts
  pending required actions between credential verification and session issuance.  Users with
  `UPDATE_PASSWORD` or `VERIFY_EMAIL` actions are redirected to the required-action
  interstitial; on completion a full browser session cookie is issued and the user is
  returned to their original destination (`return_to`).  Previously the browser login path
  issued a session immediately, skipping all required-action enforcement (HEA-797).

### Security

- **gRPC cross-realm BFLA: realm management now requires system-realm admin token** — all five
  realm-management gRPC handlers (`list_realms`, `get_realm`, `create_realm`, `update_realm`,
  `delete_realm`) previously authenticated the caller but discarded the returned realm context
  (`_auth`), allowing any legitimate realm-A admin to destroy or read realm B. Handlers now
  enforce that the `x-realm-id` metadata header is the nil UUID (system realm); all other callers
  receive `PermissionDenied` (HEA-799; OWASP API Top 10 — BFLA).

- **VERIFY_EMAIL cross-user token substitution** — the `verify_email_confirm` handler now
  validates that the `UserId` bound to the submitted email-verification token matches the
  user in the RA session cookie.  Previously the handler discarded the returned user ID,
  allowing an attacker to clear another user's `VERIFY_EMAIL` required-action by submitting
  a token minted for a different account (HEA-815; security review HEA-810 FINDING-1 HIGH).

- **Cluster admin endpoints now require system-realm token** — `POST /admin/cluster/bootstrap`,
  `GET /admin/cluster/status`, and `POST /admin/cluster/transfer-leadership` previously
  accepted any valid tenant-realm admin token, allowing a tenant admin to invoke
  node-wide Raft operations (privilege escalation). All three endpoints now return
  `403 Forbidden` with `"cluster admin requires system realm"` when the `X-Realm-ID`
  header is not the nil UUID (HEA-763).

- **Zeroize intermediate PKCS#8 and DEK heap copies** — plaintext key material in transit no
  longer relies on the OS/allocator to zero freed heap pages. Specifically: `decrypt_bytes` now
  returns `Zeroizing<Vec<u8>>`; the DEK (`dek_vec`) in `load_signing_key` is wrapped in
  `Zeroizing`; and every `key_bytes` local in `create_realm`, `import_realm`,
  `seed_system_realm_if_absent`, and `rotate_realm_signing_key` is wrapped in `Zeroizing` so the
  active overwrite fires on drop. No public-API behavior change (HEA-750).
- **Replaced unsound `serde_yml` dependency** — `serde_yml 0.0.12` (RUSTSEC-2025-0068) is
  unsound (segfault via `Serializer.emitter`) and its GitHub project has been archived.
  Migrated to `serde_norway 0.9`, a maintained fork with an identical API surface (HEA-793).

- **Realm status cache: fail-closed on corrupted storage records** — `populate_realm_status_cache`
  now returns an error on deserialization failure instead of silently skipping records; the engine
  refuses to start rather than booting with an incomplete realm-suspension cache (HEA-742).
- **Realm suspension ordering tightened** — `update_realm` now updates the `realm_status_cache`
  before writing the audit record, closing a brief window where a `validate_token` call could
  observe stale realm status between the storage write and cache update (HEA-742).

- **Argon2id defaults confirmed at OWASP 2023 minimum** — `CredentialConfig::default()` uses
  `m=19456` (19 MiB), `t=2`, `p=1`, meeting the OWASP Password Storage Cheat Sheet 2023
  minimum for Argon2id. A pinning unit test (`default_credential_config_meets_owasp_2023_minimum`)
  now fails CI if these values are ever accidentally regressed below the security floor (HEA-823).

### Fixed

- **Restore preserves realm signing keys** — `BackupImporter::import_realm` previously
  detected the encrypted `signing_key.json` in each archive but silently discarded it,
  letting `IdentityEngine::import_realm` regenerate a fresh Ed25519 key. Every JWT issued
  before the backup (per-realm-signed OIDC tokens: `client_credentials`, `authorization_code`,
  ID tokens, RP-initiated logout tokens) was therefore invalidated post-restore, and every
  RP that cached the realm's JWKS `kid` began failing verification. Restore now decrypts
  `signing_key.json` with the manifest's DEK and installs the original PKCS#8 bytes
  atomically with the realm record via a new `signing_key_pkcs8: Option<&[u8]>` parameter
  on `IdentityEngine::import_realm`. New regression test `test_restore_preserves_signing_keys`
  in `tests/backup.rs` asserts PKCS#8 byte equality, JWKS `kid` continuity, and end-to-end
  JWT verification against the restored key — it fails against pre-fix `main`. Migration
  importers (Auth0, Keycloak) pass `None` and continue to generate a fresh key per realm.
  See [docs/guides/disaster-recovery.md](./docs/guides/disaster-recovery.md) for the
  post-incident rotation procedure when a fresh key *is* desired (HEA-745).

- **`validate_token` hot-path: eliminated heap allocation, storage read, and mutex on read path**
  — three concrete violations of the zero-allocation hot-path rules (`CLAUDE.md`) were
  removed (HEA-736):
  - `claims.tid != realm_id.to_string()` → zero-alloc `parse::<RealmId>()` UUID byte comparison.
  - `self.get_realm(realm_id)` storage read → wait-free `ArcSwap<HashMap<RealmId, RealmStatus>>`
    cache populated at startup and updated on every realm CRUD operation.
  - `self.realm_signing_keys.lock()` mutex → `ArcSwap<HashMap<RealmId, Arc<SigningKey>>>` with
    `load()` on the hot path; writers use `rcu()` (clone-and-CAS); zero blocking for readers.

### Changed

- **CodeQL Rust scan quality** — CodeQL's Rust leg now runs an explicit
  `cargo build --workspace --all-targets --all-features --locked` (manual
  build mode) instead of autobuild, and `setup-rust` exports `PROTOC` to
  the GitHub Actions environment. Lifts Code Scanning's
  "calls-with-call-target" metric above its 50 % threshold and reduces
  false negatives from unresolved generated/feature-gated code (HEA-714).

- **CI: bench relative regression check is now informational** — the
  `check-bench-regression.sh` step emits GitHub Actions warning annotations but
  no longer exits non-zero. The authoritative regression blocker is the absolute
  p50/p99 latency gate built into each bench binary's custom `main()` (limits
  from `ARCHITECTURE.md`). Shared GitHub runners vary ±10–15% across Azure
  regions; a hard relative threshold on top of absolute gates produced false
  positives without adding meaningful signal (HEA-711).

- **CI: scoped security scanners to production code** — CodeQL `paths-ignore`,
  Trivy `skip-dirs`, and a new `osv-scanner.toml` exclude test fixtures,
  example apps, fuzz harness code, and the Playwright runner from code
  scanning. Production SDKs (`sdks/*/`), root `Cargo.lock`, `fuzz/Cargo.lock`,
  and `src/**` remain in scope and must stay green. No CVE-id suppressions
  were added — only directories. Existing alerts for excluded paths are
  dismissed via `code-scanning/alerts` after the SARIF re-upload (HEA-690).

### Removed

- **Dead backup file `src/protocol/web/admin.rs.bak` removed from working tree** —
  a 10 005-line editor artifact was present on disk but never committed; deleted
  and the existing `*.bak` `.gitignore` rule confirmed in place (HEA-748).

- **Stale "Snyk is configured" sentence in `docs/guides/security-hardening.md`** —
  Hearth has not used Snyk since the HEA-680 security workflow consolidation. The
  prescriptive line in the Dependency Vulnerability Scanning section is replaced
  with a Dependabot-only statement. Historical changelog entries that reference
  the old Snyk configuration are preserved as release-note history (HEA-717).

### Fixed

- **Stale "Actions workflow is missing" warnings across CodeQL, Trivy,
  osv-scanner, and Snyk Open Source on the Code Scanning Tools page** — a new
  `scripts/cleanup-stale-code-scanning-analyses.sh` walks the
  `confirm_delete_url` / `next_analysis_url` chain via the `gh` CLI and drains
  analyses whose `analysis_key` references workflows that no longer exist on
  `main` (legacy `codeql.yml` / `trivy.yml` / `osv-scanner.yml`,
  GitHub-managed `dynamic/*` default-setup analyses, the empty
  `/language:java-kotlin` and noisy `/language:actions` CodeQL databases), plus
  all Snyk Open Source analyses (Hearth has no Snyk). Defaults to `--dry-run`;
  `--confirm` actually deletes; `--tool <name>` scopes a single tool. Idempotent.
  Uses ambient `GITHUB_TOKEN` via `gh` — no secret handling (HEA-716).

### Security

- **`rsa` crate removed from the dependency graph (RUSTSEC-2023-0071 /
  CVE-2023-49092, Marvin Attack)** — SAML's RSA-2048 keypair + self-signed
  X.509 generation in `src/identity/tokens.rs` now goes through `rcgen` with
  the `aws_lc_rs` backend instead of `rsa@0.9.10`, which has no patched
  release for the Marvin timing side-channel. Hearth never reached the
  vulnerable `Pkcs1v15Decrypt` path (RSA signing uses `ring`, which is
  side-channel-hardened), but dropping the crate eliminates the alert
  entirely. `RsaSigningKey::from_pkcs8_and_cert()` and the `ring`-based
  signing path are unchanged; integration tests that fabricated upstream
  RS256 JWKS now also generate keys via `RsaSigningKey`. Closes Code
  Scanning alerts #221 and #222 (HEA-697).
- **OSV-Scanner: suppress RUSTSEC-2025-0141 (bincode unmaintained)** —
  `bincode@1.3.3` is a transitive dependency of `madsim` (simulation test crate
  only) and is never compiled into the production binary. The advisory has no
  CVE, no CVSS score, and no known exploit. `madsim@0.2.34` (latest) still
  requires it; no upgrade path exists. Suppressed in `osv-scanner.toml` with
  documented rationale. Dismisses Code Scanning alert #223 (HEA-700).
- **CI: scoped `security-events:write` per-job in `security.yml`** — the
  top-level workflow `permissions` block is downgraded to `security-events: read`,
  and `write` is granted only to the three jobs that upload SARIF
  (`codeql`, `trivy`, `osv-scanner`). A supply-chain-compromised action in any
  other job (current or future) can no longer mint Code Scanning findings.
  Closes Code Scanning alert #248 (HEA-696).
- **CI: `required-summary` gate resolves "Waiting for status" on skipped jobs
  (HEA-693)** — a new `required-summary` job in `ci.yml` runs unconditionally
  (`if: always()`), reads every upstream job result, and exits non-zero if any
  dependency failed or was cancelled. Branch protection `main` now requires only
  `CI / required-summary` for the CI workflow instead of listing each conditional
  job individually. Conditional matrix jobs (`sdk-node`) and path-filtered jobs
  (`quality`, `ui`, `sdk-conformance`) no longer leave required checks stuck in
  "Expected — Waiting for status to be reported" when they are legitimately
  skipped by the paths-filter (HEA-693).
- **Go SDK toolchain pinned to 1.26.3** — `sdks/go/go.mod` `go` directive
  raised from `1.24` → `1.26.3` and `toolchain go1.26.3` added, addressing 16
  Go stdlib CVEs (net/mail, net/http, net/url, html/template et al.) fixed in
  Go 1.26.1–1.26.3. Dismissed 22 Code Scanning alerts orphaned by the
  `osv-scanner.yml` → `security.yml` workflow consolidation (category mismatch
  meant new 0-result SARIFs never auto-closed alerts from the old category)
  (HEA-712).
- **CSP hardened** — `Content-Security-Policy` for all `/ui/**` routes now enforces
  `script-src 'self' 'unsafe-eval'` (no `'unsafe-inline'`), `style-src 'self'`,
  `font-src 'self'`, and `base-uri 'self'`. No third-party origins remain in any
  directive (HEA-630).
- **Backup encryption: salt and nonce generation hardened against CodeQL false
  positive** — `encrypt_archive` now calls `ring::rand::generate::<[u8; N]>()`
  directly instead of pre-allocating a zero-filled `[0u8; N]` buffer that was
  then overwritten by `fill()`. CodeQL's `rust/hard-coded-cryptographic-value`
  rule flagged the zero literal as a hard-coded key regardless of the
  subsequent `fill()` — using `generate()` + `.expose()` removes the
  zero-init entirely and keeps the alert closed on main (HEA-712).
- **Backup key-derivation buffer: `[0u8; 32]` replaced with `Default::default()`**
  — `derive_key_with_params` used `[0u8; 32]` as the output buffer passed to
  `argon2::hash_password_into`. CodeQL's `rust/hard-coded-cryptographic-value`
  rule traces zero literals into any crypto call regardless of whether the
  argument is an input or output. Replacing with `let mut key: [u8; 32] =
  Default::default()` removes the literal from CodeQL's taint source while
  producing identical runtime behavior (HEA-712).
- **Examples: `qs` patched to ≥ 6.15.2 in all three TypeScript examples** —
  `examples/federation-flow/client-ts`, `examples/federation-flow/upstream-idp`,
  and `examples/oauth-consent-flow/client-ts` each gained an npm `overrides`
  entry for `qs >= 6.15.2` to close GHSA-q8mj-m7cp-5q26 (DoS via prototype
  poisoning). Lock files regenerated; `npm audit` reports 0 vulnerabilities in
  each directory (HEA-712).
- **Examples: `uuid` bumped to 11.1.1 in oauth-consent-flow example** —
  `examples/oauth-consent-flow/client-ts` direct dependency on `uuid` raised
  from `^10.0.0` → `^11.1.1` to close GHSA-w5hq-g745-h8pq (missing buffer
  bounds check, uuid < 11.1.1) (HEA-712).
- **`deny.toml`: stale RUSTSEC-2023-0071 suppression removed** — the advisory
  ignore entry for the Marvin Attack (`rsa` crate) was left in place after HEA-697
  removed the `rsa` crate entirely. The entry contained misleading documentation
  implying the crate was still present. Removing it keeps the advisory suppress
  list accurate and prevents future confusion about the actual dependency surface
  (HEA-713).

### Changed

- **CI: `main` branch protection required-check migration** — the
  `required_status_checks` list on `main` is rewritten to reference the
  post-consolidation job names emitted by `ci.yml` and `security.yml`. The
  legacy `make check + css-check + proto-check` check is removed and replaced
  by 13 entries: `CI / filter (paths-filter)`,
  `CI / quality (clippy + fmt + nextest + css/proto check)`,
  `CI / ui (Playwright — smoke + regression + accessibility + exploratory)`,
  `CI / sdk-node (18.x|20.x|22.x)`, `CI / sdk-conformance (docs/sdk-spec.md)`,
  `Security / codeql (rust|go|javascript-typescript|python)`, `Security / trivy`,
  and `Security / osv-scanner`. The migration is driven by
  `scripts/ci-required-checks-migrate.sh` (`--dry-run`, `--apply`,
  `--rollback FILE`), which is idempotent and writes a rollback snapshot
  before every `--apply`. Open PRs at the moment of cut-over must push a
  refresh commit so the new check matrix runs against their head SHA
  (HEA-684).

- **CI: mega-consolidation (paths-filter foundation + workflow merges)** —
  the `.github/workflows/` tree shrinks from 12 → 7 files. Three security
  scanners (`codeql.yml`, `trivy.yml`, `osv-scanner.yml`) collapse into a
  single `security.yml` with shared triggers, permissions, and weekly cron;
  each job uploads its own SARIF category so existing alert correlation is
  preserved. Two nightly UI workflows (`ui-tests-cross-browser.yml`,
  `ui-tests-tls-smoke.yml`) collapse into `ui-nightly.yml` with one `build`
  job uploading the `hearth` debug binary as a workflow artifact and four
  parallel `test` matrix legs (`chromium`, `firefox`, `webkit`,
  `https-tls-chromium`) consuming it — eliminates ~4× redundant cargo
  builds per nightly run. `node-sdk-ci.yml` and `sdk-conformance.yml` are
  folded into `ci.yml` as `sdk-node` and `sdk-conformance` jobs. `ci.yml`
  now leads with a `filter` job (`dorny/paths-filter`) whose outputs gate
  every downstream job, so doc-only PRs run only the filter job, Cargo.lock
  bumps skip UI/SDK matrices, and `sdks/node/**`-only PRs skip the Rust
  quality gate. `bench-regression.yml` and `fuzz.yml` triggers now use
  workflow-level `paths:` filters so they no longer fire on doc, template,
  or SDK-only changes. Required-check name changes are not applied in this
  PR — branch-protection rename is sequenced separately (HEA-680).

- **CI: reusable Rust setup action + SHA pin unification** — the Rust toolchain
  / `Swatinem/rust-cache` / `arduino/setup-protoc` / optional `buf` / optional
  Tailwind install sequence is now consolidated into a single composite action
  at `.github/actions/setup-rust`, consumed by every Rust-needing workflow
  (`ci.yml`, `fuzz.yml`, `bench-regression.yml`, `ui-tests-cross-browser.yml`,
  `ui-tests-tls-smoke.yml`, `codeql.yml`'s Rust matrix leg). All
  `actions/checkout` pins normalize to a single SHA (v6.0.2) and all
  `codeql-action/upload-sarif` pins normalize to a single SHA (v4.35.4) across
  the workflow tree, so Dependabot now bumps each from one PR (HEA-672 PR 1 /
  HEA-676). No behavior change to triggers, job graph, or required checks.
- **Security scanners replaced** — Snyk removed; CodeQL (all SDK languages + Rust),
  Trivy (`fs` mode, CRITICAL/HIGH), and OSV-Scanner (all SDK lock files) now run on
  push/PR to `main` and weekly. Results upload as SARIF to GitHub Code Scanning.
  No API token required (HEA-669).
- **Audit log: relative timestamps** — the admin audit table now renders
  timestamps as relative strings (`just now`, `5m ago`, `3h ago`, `May 18`)
  so operators can scan recent activity without mentally converting UTC.
  The absolute UTC timestamp is preserved as a `title=""` tooltip on
  every row, one hover away (HEA-644).
- **Audit log: clickable resource links** — the resource column in the
  admin audit table now wraps the display name in an `<a>` tag pointing
  to the affected user / organization / application / realm / group
  detail page when the resource is still present. Deleted or
  unresolvable resources continue to render as plain text so operators
  don't navigate to a 404. Sessions link to the realm sessions list
  (HEA-645).
- **Audit log: friendly action labels** — the admin audit table now renders
  title-case English phrases ("User Created", "Consent Revoked", "SAML
  Login Failed") in place of raw `snake_case` tags. The raw identifier
  is preserved as a `title=""` tooltip so operators can still correlate
  rows with API filter values, and the Action filter `<select>` shows
  the friendly label as display text while submitting the raw tag
  (HEA-643).
- **Audit log: contextual metadata highlights** — the metadata column
  now lifts the most operationally useful keys inline per action
  instead of taking the first-N alphabetically: `ip`/`user_agent` for
  session creation, `client_id`/`scopes` for OAuth consent grant/revoke,
  `method` for credential changes, and `provider`/`external_id` for
  completed federation logins. The inline pill cap rose from 2 to 3
  and the "+N more" overflow chip only ever hides non-priority keys,
  so the IP behind a new session is visible without expanding the row
  (HEA-646).
- **Audit log: category + severity indicators** — every row in the admin
  audit table now renders a colored category dot before the action label
  (one of Identity / Session / OAuth / Security / Organization / System)
  and a subtle amber left-border on destructive or security-sensitive
  events — deletions, credential changes, consent revocations, role
  revokes, bulk disables, and anything else whose
  `AuditAction::failure_policy()` is `FailOperation`. Routine updates
  (e.g. `UserUpdated`) stay visually quiet while destructive events
  (e.g. `UserDeleted`) stand out, so operators can triage high-impact
  activity at a glance (HEA-647).
- **Self-hosted fonts** — Fraunces, Manrope, and JetBrains Mono `.woff2` files are
  now embedded in the binary and served from `'self'`. The `<link>` to
  `fonts.googleapis.com` has been removed; `@font-face` rules in `app.css` load
  fonts directly from `/ui/static/fonts/` (HEA-630).
- **Alpine.js vendored** — Alpine.js is no longer loaded from `cdn.jsdelivr.net`.
  The file is embedded at compile time and served from `/ui/static/alpine.min.js`
  with an SRI hash, making air-gapped installs work and eliminating the CDN
  supply-chain pivot (HEA-630).

### Added

- **Custom attribute support for users and organizations** — Realms may now declare per-entity
  attribute schemas in YAML under `realms.<name>.attribute_definitions.users` / `.organizations`.
  Each definition specifies `key`, `label`, `type` (`string | number | boolean | enum`), `required`,
  and (for enums) `enum_values`. When definitions are present, unknown keys are rejected with 400
  and required keys are enforced on create. Without definitions, free-form key-value pairs (max
  50 keys, 64-byte keys, 1024-byte values) are accepted. Organization attributes are now fully
  wired through the domain layer, REST admin API, admin UI edit/create/detail forms, gRPC create
  and update RPCs, and SCIM import. The gRPC `UpdateUserRequest` converter no longer drops
  attributes; the proto gains `attributes` + `clear_attributes` on `UpdateUserRequest`,
  `Organization`, `CreateOrganizationRequest`, and `UpdateOrganizationRequest` (HEA-654/655).

- **Skip-to-content link** — all admin pages now include a `<a href="#main">Skip to content</a>` as
  the first focusable element, allowing keyboard and screen-reader users to bypass the sidebar (HEA-633).
- **`.input` utility class** — unified form field style (border, background, placeholder colour,
  ember focus ring) applied across all `/ui/**` text, email, password, search, and textarea inputs;
  eliminates the previous inconsistent ad-hoc class chains (HEA-633).
- **Global focus ring** — every interactive element now shows a visible 2 px ember outline on
  `:focus-visible`, ensuring keyboard navigation is legible on dark backgrounds (HEA-633).
- **Heading colour inheritance** — a `@layer base` rule pins `h1–h6` to `var(--ht-content-primary)`
  (`graphite-50`), preventing UA stylesheets from resetting headings to white on dark surfaces (HEA-633).

### Fixed

- **Realm navigation de-duplicated** — the per-realm tab bar that lived above
  every realm sub-page (Users / Organizations / Groups / Applications / …) has
  been removed; the same links were already in the sidebar's per-realm subtree
  and the duplication caused mismatched active-state and crowded headers. The
  realm overview page now lists every sub-page as a Quick access tile so it
  also works as a navigation hub when the sidebar is collapsed or on mobile
  (HEA-629).
- **Sidebar active-state highlights consistently** — Groups, Organizations,
  Applications detail, Users detail, Identity Providers, Webhooks, and the
  realm Sessions list pages now keep the correct sidebar entry highlighted.
  Previously most of these handlers passed `active: "realm-workspace"` as a
  placeholder (which no sidebar key matched), and the Sessions list still
  passed `active: "users"` (a legacy from when sessions were nested under
  the user-detail page), so the wrong sub-item lit up (HEA-629).
- **Identity Providers and Webhooks reachable from sidebar + overview** —
  added the two missing realm sub-pages to the sidebar's per-realm subtree
  and to the realm overview Quick access tiles. Both were previously
  reachable only via the now-removed topbar tab strip (HEA-629).

- **H1 typography unified across `/ui`** — every admin and pre-login H1 now renders in
  Fraunces (display serif) at one of two canonical sizes (`text-2xl` for the admin
  shell, `text-xl` for compact pre-login modals). Previously the admin list pages
  (Users, Realms, Applications, Webhooks, Organizations, Groups, Sessions, Audit,
  Migration History) and the pre-login pages (login, register, forgot/reset
  password, MFA challenge/recovery/enroll, verify-email, setup, realm-required)
  rendered H1s in Manrope at mixed sizes because they omitted `font-display`. A
  safety-net rule in `@layer base` now also defaults every `h1`–`h6` to Fraunces
  so future undecorated headings cannot regress (HEA-629).

- **New-user form validation** — the admin "Create user" form now shows required-field
  markers and `aria-required` on Email and Initial Password, performs inline email
  regex validation, and displays a real-time 0–4 password strength meter with
  colour-coded bars. The configured password policy appears as helper text below
  the password field (HEA-632).
- **Audit log metadata drawer** — audit event rows now render metadata as compact
  key/value pills (max 2 visible + "+N more") instead of raw JSON. Clicking the
  chevron expands an inline detail panel that pretty-prints the full event JSON
  and shows the SHA-256 hash-chain proof (HEA-632).
- **Config editor SSR fallback** — the admin Config Editor page now renders the raw
  `hearth.yaml` immediately on first paint without JavaScript. When Alpine.js
  attaches the SSR view is replaced by the full interactive tabbed editor; the page
  remains usable (read-only view or direct apply) with JS disabled or CSP-blocked
  (HEA-632).

### Changed

- **Audit filters use HTMX partial swap** — changing actor, action, date range, or
  limit in the audit log no longer triggers a full-page reload. HTMX swaps only
  the `<tbody>` and shows a spinner in the filter bar during the request (HEA-632).
- **Centralised timestamp format** — all admin and account pages render timestamps
  via a single `format_ts()` helper producing `YYYY-MM-DD HH:MM UTC`. Ad-hoc
  `strftime` / `to_rfc3339` calls removed from templates (HEA-632).

- **Persistent dev storage** — `make dev` now uses `./data/dev` as the data directory so
  storage survives restarts. `make dev-reset` wipes `./data/dev` for a clean slate.
  The underlying `HEARTH_DEV_DATA_DIR` env var can override the path when invoking the
  binary directly (HEA-626).

- **Backup HTTP admin endpoints** — two new admin API endpoints for backup and restore without SSH
  access (HEA-623):
  - `POST /admin/backup` — creates a `.hearth-backup` archive and streams it as an
    `application/octet-stream` download. Optional query params: `realm=<slug>` (restrict to one
    realm), `include_audit=true` (embed audit events). No passphrase encryption — TLS provides
    transport security. Emits a `backup_created` audit event.
  - `POST /admin/backup/restore` — accepts a `multipart/form-data` upload with a `file` field
    containing a `.hearth-backup` archive. The archive is streamed to a tempfile before parsing to
    avoid memory pressure. Query params: `mode=skip|overwrite|merge` (default: `skip`),
    `realm=<slug>`, `dry_run=true`. Returns JSON with `realms_restored`, per-realm `counts`, and any
    `errors`. Emits a `backup_restored` audit event. Body size limit is disabled for this endpoint.

- **Backup passphrase encryption** — `encrypt_archive`/`decrypt_archive` in `src/backup/encryption.rs`
  wrap an entire `.hearth-backup` archive in an AES-256-GCM envelope keyed with Argon2id
  (m=65536, t=3, p=4). The binary envelope prepends a `HEARTH-BAK-ENC` magic header, the KDF
  parameters, a random 16-byte salt, and a random 12-byte nonce before the authenticated
  ciphertext. Passphrases are held in `SecretString` (zeroize-on-drop); the derived key is zeroized
  immediately after the AES context consumes it (HEA-621).

- **Backup CLI** — four subcommands under `hearth backup` for offline archive management (HEA-622):
  - `hearth backup create [--output <path>] [--realm <slug>] [--include-audit] [--encrypt] [--data-dir <dir>]` — exports all (or a single filtered) realm to a `.hearth-backup` archive. `--encrypt` prompts interactively for a passphrase and wraps the signing-key DEK with Argon2id + AES-256-GCM so the signing keys cannot be decrypted without the passphrase.
  - `hearth backup restore --input <path> [--realm <slug>] [--mode skip|overwrite|merge] [--dry-run] [--data-dir <dir>]` — restores realms from an archive; exit 0 (success), 1 (partial/conflicts), 2 (fatal).
  - `hearth backup verify --input <path>` — recomputes SHA-256 checksums and compares against `manifest.json`; exit 0 on pass, 3 on integrity failure.
  - `hearth backup inspect --input <path>` — prints manifest metadata and per-realm record counts as a human-readable table without decompressing entity files.

- **Backup restore engine** — `BackupImporter` reads a `.hearth-backup` archive produced by
  `BackupExporter` and drives the existing engine `import_*` methods to restore realms, users,
  credentials, and OAuth clients. Supports `Skip`, `Overwrite`, and `Merge` conflict modes plus
  `dry_run` for validation without writes. Returns a structured `ImportReport` with per-entity-type
  outcome counts and a `Vec<Conflict>` describing any skipped or overwritten records (HEA-620).

- **Backup export engine** — `BackupExporter` serialises all realm entities (users, credentials,
  clients, roles, permissions, groups, scopes, assignments, organizations, audit events) to NDJSON
  streams inside a `.hearth-backup` archive. Realm signing keys are AES-256-GCM encrypted with a
  per-archive DEK stored in `manifest.json`. Usage: construct `BackupExporter::new(identity, audit,
  rbac)`, call `generate_dek()` once per archive, then `export_realm(realm_id, &mut writer, &opts,
  &dek)` per realm (HEA-619).

- **Attribute filtering on admin user list** — `GET /admin/users?attr=key:value` filters results
  to users whose custom attributes contain an exact match for the given key and value. Values may
  contain colons (e.g. ISO timestamps). Malformed `attr` (no colon separator) returns `400` (HEA-578).

- **Audit log retention policy and NDJSON export** — per-realm configurable `retention_days`
  (default 90, `0` = unlimited) with automatic daily pruning of expired events. New REST endpoints:
  `GET/PUT /admin/api/realms/{realm}/audit/config` (read/update retention) and
  `POST /admin/api/realms/{realm}/audit/prune` (manual trigger). The audit export endpoint
  (`GET /admin/realms/{realm}/audit/export`) now returns NDJSON (`application/x-ndjson`, one JSON
  object per line) by default instead of a JSON array, with `?format=csv` unchanged (HEA-590).

- **Raft clustering foundation (Phase 2)** — adds a `cluster:` section to `hearth.yaml` that enables
  multi-node Raft consensus via `openraft`. When configured, Hearth starts a Raft peer gRPC server
  (`peer_address`) secured by mutual TLS. The implementation includes durable log storage (`redb`),
  a CBOR+gzip snapshot format, mTLS peer transport, and a lag-gated read path. Single-node mode is
  unchanged — the cluster layer has zero overhead when `cluster:` is absent. Full write-path
  integration tracked in HEA-616 (HEA-589).

- **Per-IP and per-account rate limiting on auth endpoints** — `POST /token` (password grant),
  `POST /v1/auth/magic-link`, and realm token exchange now enforce a configurable sliding-window
  per-IP limit and a consecutive-failure lockout per account. Blocked callers receive
  `429 Too Many Requests` with a `Retry-After` header. Configure via `security.rate_limiting`
  in `hearth.yaml`; defaults are 10 attempts / 60 s per IP and 5 failures / 5 min lockout per
  account. Trusted-proxy `X-Forwarded-For` handling is used when `server.trusted_proxies` is
  set (HEA-587).

- **Built-in `mailcatcher` email transport** — captures outbound emails in an in-process ring
  buffer (cap 50) and serves them via a password-protected browser UI at `/dev/mail`. Auto-enabled
  when `--dev` is passed and no explicit transport is configured. Startup banner prints the inbox
  URL and a randomly generated 16-character access password. Fatal startup error if
  `email.transport = mailcatcher` is used outside dev mode (HEA-574).
- **`--dev` now overrides SMTP transport → mailcatcher** — previously `--dev` only auto-enabled
  mailcatcher when the transport was the default `log`. Users migrating from Docker-based Mailpit
  setups who had `transport: smtp` in their `hearth.yaml` would still attempt a network SMTP
  connection and see a DNS resolution error. `--dev` now upgrades both `log` and `smtp` to
  mailcatcher; a startup warning advises updating the config explicitly. Production cloud transports
  (`sendgrid`, `postmark`, `mailgun`, `mailtrap`) are kept unchanged (HEA-573).
- **`docs/guides/local-dev.md`** — new developer guide covering the no-Docker local dev setup:
  mailcatcher email capture, transport selection rules table, first-run setup flow, and persistent
  dev storage instructions (HEA-575).

### Removed

- **Docker Compose dev stack removed** — `compose.yaml` (root) and the `docker-up`/`docker-reload`
  Makefile targets are gone. `make dev` (`cargo run -- serve --dev`) replaces Docker entirely for
  local development; the built-in mailcatcher handles email without any external services. The
  production deployment stack in `deploy/docker-compose.yml` is unaffected (HEA-575).

### Security

- **Rate-limiting gaps closed** — per-IP sliding-window enforcement added to `POST /token`
  (password grant) and the new `POST /v1/{realm}/auth/magic-link` endpoint; per-account lockout
  state is now persisted to WAL and restored on startup so active lockouts survive server restarts;
  `security.rate_limiting` YAML section added for configuring IP window and account lockout
  thresholds without recompiling (HEA-592).

- **Mutating operations on Suspended/Archived realms are now rejected** — `create_user`,
  `update_user`, `create_session`, `authorize` (OAuth 2.0 code issuance), `create_organization`,
  `create_invitation`, and `accept_invitation` now return a `RealmSuspended` error when the
  target realm's status is `Suspended` or `Archived`. Previously only `register_user` enforced
  this gate; all other write paths were fully open, allowing data to be written to or new sessions
  created in a decommissioned realm (HEA-552).

### Fixed

- **`onboarding.base_url` fallback is now an absolute URL** — when `onboarding.base_url` is not
  set, the setup URL logged at startup (and the `notification_email` delivery) now uses the bind
  address (`http://{bind_address}:{port}`) instead of a bare relative path (`/ui/setup?token=…`)
  that cannot be navigated to from a remote browser. A startup warning is also emitted advising
  operators to set `onboarding.base_url` for production deployments (HEA-547).
- **`onboarding.notification_email` without `onboarding.base_url` is now a startup error** —
  emailing a setup URL built from the bind address is likely unreachable by the recipient.
  Operators must now set `onboarding.base_url` explicitly when `notification_email` is configured
  (HEA-547).

- **`token.audience` now defaults to `oidc.issuer`** — the previous default `"hearth"` placeholder
  caused OIDC clients that validate `aud` against their `client_id` or resource server URL to
  silently reject all tokens. When `token.audience` is not explicitly set, the server now inherits
  `oidc.issuer` as the audience value. A startup warning is emitted if the audience is still
  `"hearth"` while `oidc.issuer` is configured to a real URL (HEA-551).
- **Global signing key now persists across restarts** — the server-wide fallback signing key was
  previously regenerated on every startup, silently invalidating all tokens that relied on it.
  The key is now stored in the WAL-backed system realm namespace on first startup and reloaded on
  subsequent startups, surviving `kill -9` and WAL replay (HEA-546).
- **`seed_realm` failures are now hard errors** — realm creation via gRPC, HTTP admin bootstrap,
  and web onboarding previously logged a warning and continued when RBAC seeding failed, leaving
  the realm permanently broken with no admin roles. All three paths now return an error to the
  caller. Startup reconciliation (`reconcile_rbac_seeds`) also runs on every `hearth serve` to
  repair any realms whose original seed was lost (HEA-545).

### Security

- **`validate_token` now rejects tokens from Suspended or Archived realms** — suspending or
  archiving a realm immediately blocks all token validation for that realm. Previously, tokens
  remained valid until natural expiry even after a realm was suspended or archived. As a
  belt-and-suspenders measure, `update_realm` also revokes all active sessions in the realm when
  transitioning to Suspended or Archived status (HEA-544).
- **PKCE mandatory for all clients** — confidential clients (those with a `client_secret`) are now
  required to supply `code_challenge`/`code_verifier` in the authorization code flow, matching the
  RFC 9700 §2.1.1 recommendation. Operators who need legacy-client compatibility can set
  `oidc.require_pkce_for_confidential_clients: false` in `hearth.yaml`; doing so emits a startup
  warning (HEA-550).
- **OIDC nonce replay protection** — `enforce_nonces` now defaults to `true`; new deployments reject replayed authorization responses for confidential clients out of the box. Operators who need legacy-client compatibility can set `oidc.enforce_nonces: false` in `hearth.yaml`; doing so emits a startup warning (HEA-548).
- **Go SDK** — minimum Go version bumped from 1.23 to 1.24, clearing `SNYK-GOLANG-STDNETHTTP-16535158` (infinite loop in `std/net/http`) (HEA-515).
- **Admin settings editor** — prototype-pollution guard strengthened in `setVal`: redundant point-of-use check on the final key segment added so static analysis can locally verify safety (HEA-515).
- **Kotlin SDK — nimbus-jose-jwt** upgraded from 9.40 to 9.41.2 (patches JWT library CVEs) (HEA-515).
- **SAML example — xmldom** replaced abandoned `xmldom ^0.6.0` (7 critical CVEs, no upstream fix) with maintained fork `@xmldom/xmldom ^0.9.10` (HEA-515).

### Added

- **Migration history page** — `/admin/migrations` lists all past cross-realm migration runs with
  source realm, destination realm, operation kind (move/copy), user counts, and status badge.
  Orphaned realms without a declared migration destination are shown in an inline recovery panel
  with an HTMX-powered YAML snippet generator to resolve or discard each orphan. The admin
  sidebar and dashboard orphan banner both link to this page (HEA-542).
- **Cross-realm user migration** — declare `migrate_from: <source-realm>` (move semantics) or
  `copy_from: <source-realm>` (copy semantics) on a destination realm's YAML block to atomically
  transfer users, credentials (Argon2id/PBKDF2/bcrypt, TOTP, WebAuthn), and RBAC role assignments
  at server startup. Role names are translated by name across realms; org memberships are matched
  by slug. A `migrate:` sub-block controls `users`, `orgs`, and `on_conflict` (`error` or `skip`).
  Migration is crash-safe: per-user progress markers in the system realm enable idempotent resume
  after an interrupted startup (HEA-541).
- **Signing key rotation** — `POST /admin/realms/{id}/rotate-signing-key` generates a new Ed25519
  key and serves both the new active key and the retiring key in JWKS for a configurable grace
  period (default 24 h), allowing clients to refresh their JWKS cache before the old key expires.
  Configure with `token.signing_key_rotation_grace_period: "24h"` (HEA-539).
- **Declarative rotation trigger** — set `rotate_signing_key: true` under a realm's YAML block to
  trigger rotation on the next server startup via config diff. The flag is auto-cleared from the
  stored snapshot so subsequent restarts do not re-rotate while the YAML still contains the flag
  (HEA-539).
- **Storage engine** — custom embedded WAL + memtable + SST storage engine with tiered hot/cold storage, crash-safe `fsync`-before-ack semantics, per-realm key prefix scoping, and background SST compaction via atomic rename.
- **Hot-path latency targets** — `benches/storage_gate.rs` CI gate enforces p50/p99 read latency; hot-tier auto-sizes from system memory / cgroup limits at startup.
- **Encryption at rest** — all stored realm data encrypted; configurable key material per deployment.
- **Identity layer** — users, hashed credentials (Argon2id), sessions, per-realm signing keys (Ed25519, PKCS#8 persisted), and full cascading delete across 11 key prefixes.
- **Multi-tenancy** — first-class `RealmId` newtype; each realm gets an isolated keyspace, its own signing key, and independent configuration. System realm (`RealmId::nil()`) stores realm metadata.
- **Per-realm branding and config** — stored email template config, locale variables, and web branding wired into login templates.
- **JWT issuance** — Ed25519-signed JWTs with `jti` claim for uniqueness, `iss`/`aud`/`exp` validation per RFC 7519.
- **OIDC Discovery** — `/.well-known/openid-configuration` document; `RS256 + ES256` keys published at `/certs`; document extended with `userinfo_endpoint`, `response_modes_supported`, `claims_supported`, `registration_endpoint`, `device_authorization_endpoint`, `revocation_endpoint`, `introspection_endpoint`, and `grant_types_supported`.
- **OAuth 2.0 complete** — authorization code flow, authorization code with PKCE, client credentials, device authorization (RFC 8628), refresh token rotation with theft detection via grant families, token revocation (RFC 7009), token introspection (RFC 7662). Introspection benchmark: ~1 µs.
- **RFC 8707 resource indicators** — threaded through token issuance and refresh.
- **Dynamic Client Registration** — RFC 7591 register + RFC 7592 read/update at `POST /register`.
- **OIDC Conformance** — Core 1.0 required claims, Discovery 1.0 metadata, UserInfo endpoint with scope-filtered claims, nonce round-trip (stored in auth code → echoed in ID token), and `iss` claim sourced from `config.oidc.issuer` to match discovery document.
- **OIDC RP-initiated logout** — with backchannel and front-channel fan-out to registered clients.
- **TOTP / MFA** — TOTP enrollment and validation (RFC 6238), time-window tolerance, recovery code generation and single-use redemption, brute-force lockout, replay protection. Per-realm `mfa_required` policy enforced at login.
- **WebAuthn / Passkeys** — full Level 2 ceremony: registration, authentication, multi-credential, resident keys, CBOR/authenticator-data parsing, counter-replay protection, RP ID mismatch rejection, and tampered `clientDataJSON` rejection.
- **Magic link / Passwordless** — single-use tokens with configurable TTL, rate limiting, enumeration resistance, and automatic account creation for unknown emails.
- **TLS termination** — PEM loading, live certificate hot-reload without restart, TLS 1.3 enforcement, weak cipher rejection, HTTP → HTTPS redirect, and mutual TLS (mTLS) support.
- **Claims-based RBAC** — replaced Zanzibar with an embedded RBAC engine: roles, groups, and permissions resolved at token issuance and embedded as `roles`/`groups`/`permissions` JWT claims. `GET /v1/me/permissions` effective-permissions endpoint. RBAC cycle detection, reserved namespace guards, and token-size cap. Admin HTTP (`/admin/roles`, `/admin/groups`) and gRPC (`RbacAdminService`) surfaces.
- **Organizations** — B2B customer groups within realms: full CRUD, membership lifecycle (invite → accept → remove), SHA-256 hashed invitation tokens with 7-day expiry, last-owner protection, cascading delete (memberships + invitations + indexes), and slug uniqueness validation.
- **Keycloak migration** — `hearth migrate keycloak --file <export.json>` CLI subcommand. Anti-corruption layer converts Keycloak's nested-JSON credential format to standard PHC strings. Native PBKDF2-SHA256 / PBKDF2-SHA512 verification; upgrades to Argon2id on next password change. `--dry-run` flag. Bypasses HTTP body limits for large exports.
- **Production email service** — five transports: Log (dev), SMTP, SendGrid, Postmark, Mailgun (with EU region). `EmailService` orchestration with per-realm branding override and Askama/Tera HTML + plaintext templates for verification and setup flows.
- **UI theming system** — six named themes: `ember` (dark default), `ocean`, `midnight`, `forest`, `cloud` (light), `slate` (light). Semantic `ht-*` Tailwind tokens backed by CSS custom properties. Global `branding.theme` / `branding.custom_css`; per-realm `web.{theme,custom_css}`. Routes: `GET /ui/static/theme.css` and `GET /ui/static/realm-theme/{id}`.
- **Admin web UI** — server-rendered Axum/Askama templates for users, realms, applications, organizations, groups, roles, permissions, scopes, identity providers, and audit log. Path-based realm scoping. Edit/delete disabled for YAML-managed applications.
- **Admin API** — CRUD endpoints for users, realms, and applications; pagination; bulk operations; full audit trail. `PUT → PATCH` on `/admin/users/{id}`; granular scope decisions; field filters.
- **SCIM provisioning** — user and group sync, service provider config endpoint, realm reconciliation, and per-handler auth enforcement.
- **Signed webhook subscriptions** — HMAC-signed delivery for auth and admin events; subscription management API.
- **Per-realm auth policy enforcement** — `allowed_auth_methods` checked at login; `AuthMethodNotAllowed` error returned when the method is disabled for the realm.
- **Configurable password-reset token TTL** — per-realm override for reset token lifetime.
- **Periodic cleanup** — background task evicts expired OAuth entities (device codes, grant families, revoked JTIs).
- **OpenTelemetry distributed tracing** — trace context propagated through identity and protocol layers.
- **Observability endpoints** — Prometheus `/metrics` (config-gated), `/healthz`, and `/readyz` with fault-injection test coverage.
- **TypeScript SDK** — `createHearth()` factory, `HearthProvider` React context, `useHasPermission` / `useHasRole` / `useInGroup` / `useInOrg` hooks, JWKS validation, and admin CRUD helpers.
- **Go SDK** — auth code flow client, admin CRUD, transparent token refresh, and `HasPermission` / `HasRole` / `InGroup` / `InOrg` / `Permissions` helpers.
- **Kotlin / JVM SDK** — `hearth-core` library for coroutine-based OIDC/JWT verification.
- **Node.js SDK** — unified `HearthClient` entry point (HEA-366).
- **SDK common specification** — `docs/sdk/SPEC.md` documents the cross-language contract; all SDK READMEs link it. CI spec-conformance checks added for TypeScript and Go.
- **Deployment artifacts** — Helm chart templates, `systemd` unit file, and `docker-compose` configuration.
- **Security Phase A** — PKCE mandatory for all public clients, redirect URI exact-match hardening, RFC 9207 `iss` parameter in all authorization responses; fuzz harnesses for token-exchange and redirect-URI validation paths (HEA-501 / HEA-503).
- **SECURITY.md** — vulnerability disclosure policy and reporting contacts.
- **OpenSSF Scorecard** — CI workflow scoring supply-chain hygiene; `CODEOWNERS` enforces review requirements.
- **Dependabot and Snyk** — automated dependency vulnerability scanning for GitHub Actions and Rust crates.
- **`cargo-audit` config** — integrated into `make check`; one known advisory (`RUSTSEC-2023-0071`, RSA, no active decrypt path) documented and ignored.
- **Rust CI quality-gate workflow** — `clippy --all-targets -D warnings`, `rustfmt --check`, `cargo nextest`, and CSS staleness check (`make css-check`) run on every PR.
- **Storage hot-path benchmark CI gate** — enforces `p50 < 50 µs` / `p99 < 200 µs` on `validate_token` / `lookup_session` / `lookup_user`.
- **`make setup`** — installs repo-managed git hooks (`.githooks/`) including pre-commit CSS and proto auto-regeneration.
- **User guides** — `docs/guides/` tree: getting-started, RBAC, SCIM provisioning, webhooks, organizations, and deployment.
- **Operator runbooks** — RBAC operator guide (client-scoped roles via `ClaimProfile`), SCIM provisioning guide, and webhooks guide.

### Changed

- **Authorization engine** — replaced Zanzibar/relationship-tuple engine with claims-based RBAC; permissions are now embedded in JWTs at issuance time rather than checked at request time.
- **License** — Apache-2.0 (`LICENSE`).
- **Admin handler organization** — split `admin.rs` (~10 000 lines) into seven per-entity submodules for maintainability.
- **OIDC `iss` claim source** — now reads from `config.oidc.issuer` (not `config.token.issuer`) so the ID token issuer always matches the discovery document (OIDC Core §2 compliance).
- **Storage `put_batch` API** — all multi-record writes (user import, audit chain) go through a single WAL frame with CRC; a crash mid-batch leaves no partial state on replay.
- **Audit `append`** — refactored to use `put_batch` (primary record + actor index + action index in one WAL record), eliminating dangling index entries on crash.

### Fixed

- Double-slash 404s on Admin Users workspace links (HEA-306).
- `/jwks` endpoint cold-start timeout in CI OIDC HTTP flow test (HEA-276).
- `PUT → PATCH` on `/admin/users/{id}` to conform to RFC 7396 partial-update semantics.
- SCIM `ServiceProviderConfig` endpoint missing auth enforcement.
- Lettre CVE via cargo-audit remediation (HEA-304).
- Stale Tailwind `app.css` CI failure after template changes.
- CodeQL and Scorecard scanning alerts across protocol and identity layers (HEA-294).
- Various `clippy::pedantic` violations gating the new CI quality-gate workflow (HEA-276).

### Security

- **PKCE mandatory** — all public clients must supply a `code_challenge`; server rejects authorization requests without one (Security Phase A).
- **Redirect URI exact-match** — registered redirect URIs compared byte-for-byte; no prefix or wildcard matching (Security Phase A).
- **RFC 9207 `iss` parameter** — returned in every authorization response to prevent mix-up attacks (Security Phase A).
- **Fuzz harnesses** — `cargo-fuzz` targets for token exchange and redirect URI parsing added to `fuzz/` (HEA-503).
- **OIDC nonce replay protection** — TTL-based eviction on the in-memory nonce set prevents unbounded growth while preserving replay resistance.
- **Ed25519-only JWT signing** — `alg:none` and symmetric algorithms (HS256 etc.) rejected at decode time.
- **Argon2id password hashing** — OWASP-recommended parameters; off hot path via `spawn_blocking`.
- **Zeroize-on-drop for secrets** — passwords, tokens, and keys wrapped in `Zeroize`-on-drop types; `Debug`/`Display`/`Serialize` impls intentionally absent.
- **Constant-time comparisons** — all secret-equality checks use `subtle::ConstantTimeEq`.
- **Audience claim validation** — `aud` checked against configured allowed audiences per RFC 7519 §4.1.3 (HEA-239).
- **`exp` and `token_type` enforcement** — `validate_token` rejects expired and mis-typed tokens (HEA-129).
- **HTTP body size limits** — enforced at protocol layer to prevent memory-exhaustion attacks.
- **Error sanitization** — error messages scrubbed of sensitive data before crossing layer boundaries.

### Removed

- **Zanzibar authorization engine** — `src/authz/`, tuple storage, `AuthzCache` in TypeScript and Go SDKs, `POST /v1/authz/check`, `GET /v1/me/capabilities`, and `CapabilityPage` bundles. All authorization now goes through `src/rbac/`.
- **`lazy_static`** — replaced with `std::sync::OnceLock` / `LazyLock` throughout.
### Security

- **WAL rotation must flush memtable before truncating (HEA-1180 / F1)** —
  `Wal::rotate_locked` truncated the WAL file before the in-memory memtable had
  been written to an SST. A `kill -9` between truncation and the next regular
  memtable flush would lose every write since the last SST flush. Fixed: the WAL
  now accepts a pre-rotation callback; `EmbeddedStorageEngine` injects a
  memtable→SST flush so all data is durable before the segment is reused. Regression
  test `wal_rotation_flushes_memtable_to_sst_before_truncating` added.

- **`StorageConfig::production()` always enforces fsync (HEA-1180 / F3)** —
  the constructor accepted a `fsync: bool` parameter that, when `false`, silently
  produced `SyncMode::None` and disabled WAL durability in production. Removed the
  parameter; `production()` now unconditionally uses `SyncMode::EveryWrite`.
  Operators who need fsync off must use `StorageConfig::dev()` or construct
  `WalConfig` directly. A `tracing::warn!` is emitted when a legacy config file
  has `fsync: false` and the production constructor is in use. Regression test
  `production_config_always_fsyncs` added.

### Performance

- **Hot-tier cache hits are now zero-alloc (HEA-1180 / F2)** —
  `HotTier::get` previously made two heap allocations on every cache hit: one to
  build a lookup `CompositeKey` (owned `Vec<u8>`) and one to clone the cached
  `Vec<u8>` value. Both are eliminated: the lookup now uses
  `hashbrown::HashMap::raw_entry` with a computed hash and a borrow-comparison
  closure (no key allocation), and cached values are stored as `Arc<[u8]>` so hits
  return a refcount increment instead of a `memcpy`. Regression test
  `hot_tier_get_returns_shared_arc_no_extra_copy` added.

### Security (continued)

- **gRPC cross-realm BFLA (HEA-799)** — all five realm-management gRPC handlers
  (`list_realms`, `get_realm`, `create_realm`, `update_realm`, `delete_realm`) previously
  discarded the authenticated realm (`_auth`) and operated on any caller-supplied realm ID.
  An admin of realm A could read, modify, or destroy realm B with a valid realm-A token.
  Fixed: each handler now enforces that regular realm admins may only operate on their own
  realm; only system-realm admins may act cross-realm or create new realms. Regression tests
  added in `tests/grpc_cross_realm_bfla.rs` (HEA-799).
