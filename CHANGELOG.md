# Changelog

All notable changes to Hearth will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Argon2id password pepper is now configurable** — set `security.password.pepper`
  (`version` + `key_hex`, plus optional `previous_version`/`previous_key_hex` for
  rotation) in `hearth.yaml` to apply a server-side HMAC-SHA256 pepper before Argon2id
  on all new password hashes. Previously the pepper engine existed but had no YAML
  key, so `CredentialConfig::pepper` was always `None`. Malformed keys (non-hex,
  shorter than 32 bytes, or the all-zero key) are rejected at startup; omitting the
  block preserves the prior no-pepper behaviour (HEA-1838).

### Security
- **SCIM PATCH now enforces the per-request operation cap** — a `PATCH`
  to `/scim/v2/Users/{id}` or `/scim/v2/Groups/{id}` whose `Operations` array
  exceeds `MAX_SCIM_OPERATIONS` (1000) is rejected with `413 Payload Too Large`
  before any operation is applied. The cap constant existed but was never wired
  into the handlers, so a single PATCH could request unbounded per-operation
  work (HEA-1830).

### Changed
- **`make loadtest` now runs against the large corpus by default** — the
  `loadtest` Makefile target boots a demo-seeded, multi-hundred-thousand-user
  Hearth (~1.2M users across the `acme`/`globex`/`initech`/`umbrella` realms,
  from the new `loadtest/loadtest-corpus.yaml`) instead of the prior ~200-user
  REST seed, so the Goose journeys observe tail latency and saturation against a
  realistically-large storage engine. The corpus is seeded in-server by the fast
  batched demo seeder and the pipeline waits for it to finish before load
  starts. New `CORPUS_ACME`/`CORPUS_GLOBEX`/`CORPUS_INITECH`/`CORPUS_UMBRELLA`,
  `LOADTEST_DATA_DIR`, `HOT_TIER_CAPACITY`, and `SEED_WAIT` env knobs tune the
  dataset (shrink the `CORPUS_*` counts for a fast pipeline smoke). This is
  scoped to the `loadtest` target only — the standalone `make seed` / `seed`
  subcommand keep their small explicit defaults (HEA-1787).

### Fixed
- **`hearth-loadtest` HTML report no longer misreads load concurrency as the seeded
  population** — the Goose overview's most-prominent number, `Users: 200`, is the
  load-generator *concurrency* (`--users`), not the seeded corpus, but readers
  repeatedly took it as "only 200 users were seeded." The harness now relabels
  that line to `Load-generator users (concurrency): 200` and, when the resident
  corpus size is known, states it alongside (`resident corpus under test:
  1,200,000 seeded accounts`) — for tier-miss runs the bulk corpus, for
  steady/ramp/soak the `--resident-corpus-size` value (HEA-1788).
- **`hearth-loadtest` HTML report drops uninformative panels** — the report now
  presents only graphs and tables that carry real signal. The dedicated **User
  Metrics** section (a flat active-concurrency line that only ever peaks at
  `--users`) is removed entirely, and the **Scenario Metrics**, **Transaction
  Metrics**, and **Response Time** *time-series graphs* are dropped — the first
  two merely retrace the requests-per-second curve at a constant closed-loop
  rate, and the last is plotted from whole-ms samples so it renders the sub-ms hot
  path as a flat ~1 ms line that contradicts the microsecond percentile table.
  The requests-per-second and errors-per-second graphs and every metrics table
  are kept (HEA-1788).
- **`hearth-loadtest` HTML report shows un-rounded latency in µs resolution** —
  Goose measures every response time in whole milliseconds, so its Request
  Metrics `Min`/`Max` columns and its entire Response Time Metrics percentile
  table rendered Hearth's sub-ms hot path as a flat `1`. The harness now records
  a lock-free per-journey microsecond histogram and post-processes the Goose HTML
  to rewrite both tables — Request `Min`/`Max` and every percentile
  (50/60/70/80/90/95/99/100), per journey and for the aggregate — with the real
  microsecond figures. A prior fix targeted only the `Min`/`Max` cells but scoped
  the rewrite by the first `</div>`, which in real Goose reports closes the nested
  echarts chart before the table, so the rewrite silently no-op'd; scoping is now
  anchored to each metrics `<table>` (HEA-1788).
- **`--dev` now honors `storage.data_dir`** — dev mode previously ignored the
  configured `storage.data_dir` and always used an ephemeral temp directory
  unless `HEARTH_DEV_DATA_DIR` was set, so cold-tier SSTs vanished between runs
  and the tier-miss load profile required an otherwise-redundant env var. A
  `--config` that sets a non-default `storage.data_dir` now persists WAL/SSTs
  there in `--dev`. `HEARTH_DEV_DATA_DIR` still takes precedence, and a bare
  `--dev` run (default `./data`, no env override) keeps the ephemeral-temp
  behavior (HEA-1805).

### Added
- **`hearth-loadtest` server resource sampling (RSS/CPU) in reports** — `run
  --server-pid <pid>` (or `HEARTH_LOADTEST_SERVER_PID`) samples the Hearth
  process's `/proc` stats once a second during the run and folds peak/mean RSS +
  peak/mean CPU% into a new, additive `resources` block in `report.json` (schema
  bumped `2` → `3`) and a **Server Resource Consumption** panel in the HTML
  report. A saturation verdict now means "p99 in budget **and** the server was
  not resource-starved." `make loadtest` passes the pid automatically; the block
  is omitted when no pid is supplied or off Linux. Flush-stall/tier-churn signals
  are out of scope (no server metrics endpoint exposes them yet) (HEA-1811).
- **`hearth-loadtest` tier-miss run mode + per-tier lookup latency reporting** —
  a new `run --mode tier-miss` profile drives the corpus-scale `lookup_user` hot
  path (ROPC `POST /token`) against the bulk demo corpus, splitting every request
  into a resident **hot** working set (`--tier-miss-hot-set-size`) hit repeatedly
  and a uniform **cold** draw across the whole corpus (`--tier-miss-corpus-size`)
  that mostly falls through to the cold/SST read path. `report.json` gains an
  additive, back-compat `tier_miss` block splitting hot-tier-hit from
  cold/SST-miss latency at p50/p95/p99 (`hot_p50_ms`/`cold_p50_ms`,
  `hot_p95_ms`/`cold_p95_ms`, `hot_p99_ms`/`cold_p99_ms`), plus the achieved
  corpus size, hot-tier capacity, and an estimated cold miss rate; the block is
  omitted for every other mode so existing consumers are unaffected. Read the
  storage-tier delta at p50/p95: every request also pays a full ROPC Argon2id
  verify, so at the p99 tail the ordering can invert under Argon2id hot-set
  contention (the default `--tier-miss-hot-set-size` is `10000` to spread that
  load). New `--tier-miss-*` flags (env `HEARTH_LOADTEST_TIER_*`); sweep the
  corpus size (`10k → 100k → 1M`) to prove the per-tier tail stays flat as the
  corpus grows (HEA-1801).
- **`--dev` honors `storage.hot_tier_capacity`** — dev mode previously always
  used the default 100k-entry hot tier and ignored the configured capacity, so
  the whole working set fit in the hot tier and every lookup was a hot-tier hit.
  A `--config` that sets `storage.hot_tier_capacity` now sizes the dev hot tier
  explicitly (logged at startup), letting a corpus-scale load profile size the
  hot tier *below* the working set so a known fraction of lookups fall through to
  the cold/SST tier and the real lookup-cost-vs-`n` curve is measurable. Records
  still read back correctly through a tier miss — it is a latency event, not a
  correctness one. Production continues to size capacity via
  `storage.hot_tier_capacity` / auto-sizing as before (HEA-1800).
- **`hearth-loadtest` report: microsecond min/max latency** — each `report.json`
  journey row now carries `min_us` / `max_us`, the fastest and slowest observed
  request in **microseconds**. The generator times each request itself, so these
  keep the sub-ms precision Goose's whole-ms aggregation rounds away (a 0.1 ms
  request reads `100`, not `0`); the `p50/p95/p99/p999_ms` percentiles remain
  Goose's whole-ms figures. Additive optional fields (omitted when a journey
  recorded no sample); the committed steady baseline gains them on its next
  regeneration (HEA-1796).
- **Runtime-visible signal when rate limiters are disabled** — when
  `security.load_test_unthrottled` resolves to active, the server now exposes a
  `hearth_rate_limiters_disabled{reason="load_test"} 1` Prometheus gauge (absent
  during normal operation) and prints a `RATE LIMITERS DISABLED (load test mode)`
  banner in the startup panel, so operators and dashboards can detect the
  unthrottled state on a live process instead of only from the boot WARN log
  (HEA-1799).
- **`security.load_test_unthrottled` config flag (loopback-gated)** — when `true`
  and the server binds a loopback address, disables all request-rate limiters
  (token endpoint, admin API, export, and the per-IP/per-realm request shaper) so
  a single-node load test can saturate the `validate_token` hot path instead of
  measuring the limiter. **Prod-safe:** it is refused (fail-safe — limiters stay
  on) on any non-loopback bind, logging a loud `WARN` when enabled and an `ERROR`
  when refused. Defaults to `false`. Never enable on a production or
  externally-reachable bind (HEA-1796).
- **`hearth-loadtest` high-concurrency rework** — the `make loadtest` pipeline now
  boots with `load_test_unthrottled` and runs **unthrottled** by default
  (`THROTTLE=0`), with higher default concurrency (`USERS=200`, `HATCH_RATE=50`)
  so `steady` mode at high `--users` drives concurrent fan-out onto the hot path.
  The `report.json` schema bumps to `2`, adding a top-level `summary` block:
  achieved concurrency + RPS, aggregate failure rate, and an explicit **ceiling
  attribution** (`server` / `load_generator_or_headroom` / `generator_saturated`)
  so a reader can tell the single-node ceiling from a load-generator bottleneck.
  README documents the fan-out/ramp invocations and `ulimit -n` /
  `ip_local_port_range` / `TIME_WAIT` generator tuning (HEA-1796).
- **`make loadtest` is now a one-command pipeline** — with no `ARGS` it boots a
  fresh throwaway dev Hearth on loopback, seeds a deterministic corpus, runs the
  Goose journeys, writes `report.json` + HTML, and tears the server down — no
  manual bootstrap/seed/attach steps. Tunable via env vars
  (`MODE`, `USERS`, `RUN_TIME`, `THROTTLE`, `SETTLE`, …; see
  `loadtest/scripts/run-loadtest.sh`). `make loadtest ARGS="…"` still invokes the
  binary directly for advanced/attach usage (HEA-1787).
- **`make loadtest` / `make loadtest-check`** — new load-testing harness crate
  (`hearth-loadtest`, goose-based) for exercising Hearth under concurrent load.
  The crate is excluded from the Cargo workspace so it does not slow the unit
  test gate; run it explicitly via `make loadtest ARGS="…"` (HEA-1788).
- **`hearth-loadtest run` — five closed-loop load journeys with configurable
  weighting** — the harness now drives validate (`POST /introspect`), session
  lookup (`GET /userinfo`), user lookup (`GET /admin/users/{id}`), issuance
  (`POST /token`), and revoke→re-validate (`POST /revoke` then `POST /introspect`
  expecting `active:false`) against a seeded instance. Per-journey weights,
  `--users`, `--run-time`, `--hatch-rate`, and `--throttle` are all CLI/env
  configurable; a weight of `0` drops a journey. Run via
  `make loadtest ARGS="run …"` (HEA-1790).
- **`hearth-loadtest run` — steady/ramp/soak run modes + sourced budgets +
  HTML/JSON reporters** — `--mode` selects `steady` (fixed users), `ramp` (walks
  a user ladder and records the **saturation knee**: the achieved RPS at the
  first step where a journey's p99 breaches its HTTP budget), or `soak` (long
  fixed-user run in buckets, surfacing latency drift). Every mode writes a Goose
  HTML report per sub-run plus a versioned (`"schema": 1`) machine-readable
  `report.json` to `--report-dir` — run metadata (git SHA, timestamp, dataset
  params, mode, host), a per-journey p50/p95/p99/p999 table, the knee RPS, and
  pass/fail against HTTP p99 budgets. Budgets are sourced, not invented: engine
  targets are cited verbatim from `docs/specs/TESTING.md` and the HTTP budgets
  add a CTO-approved loopback envelope. A journey passes only when it is both
  within its latency budget and actually succeeding (failure rate ≤ 5%), so a
  fast-but-erroring run never reads as a pass (HEA-1791).
- **`hearth-loadtest seed --admin-token` / `HEARTH_LOADTEST_ADMIN_TOKEN`** — the
  seed step can now attach to an **already-bootstrapped** dev instance by
  supplying the admin bearer token from the first bootstrap, instead of failing
  the anonymous re-bootstrap with `401 missing authorization header`. When the
  token is omitted and that 401 occurs, the seed now prints an actionable hint
  naming the flag/env var and alternatives (`make loadtest` boots its own fresh
  instance) (HEA-1787).

### Changed
- **Expired-session eviction moved off the token-validation read path** — the
  `validate_token` hot path previously performed a storage write (persist-revoke
  + audit + session-version bump) when it encountered an idle/absolute-timeout
  (A-18) session, violating the "no read-path syscall" hot-path rule. Such
  sessions are still rejected fail-closed on read, but the eviction write is now
  deferred to the periodic background cleanup sweep (`sweep_expired_sessions`,
  driven by the existing cleanup task). This also wires the previously-unwired
  session reaper into the cleanup loop; its count is reported as
  `sessions_evicted` in the `Cleanup` audit event (HEA-1774).
- **`hearth app create` now requires an admin `--token`** — client registration
  via `POST /clients` was gated behind admin authorization in HEA-1750, so the
  CLI's `app create` command now takes a mandatory `--token` flag carrying an
  admin bearer token (`hearth.clients.admin` or `hearth.admin`; obtain one via
  `POST /admin/bootstrap` in dev mode). Requests without it are rejected `401`.
  The target realm is derived from the token (HEA-1749).

### Fixed
- **Realm-scoped and admin MFA login: TOTP submit no longer 404s** — the inline
  two-factor form rendered on `/ui/realms/{realm}/login` and `/ui/admin/login`
  posted to `{prefix}/mfa-challenge` (e.g. `/ui/realms/acme/mfa-challenge`), a
  route that is not registered, so submitting a valid TOTP code returned
  `404 Not Found`. Both the TOTP form action and the "use a recovery code" link
  now target the global `/ui/mfa-challenge` / `/ui/mfa-recovery` routes (the
  MFA-pending cookie already carries realm scope), matching the standalone
  challenge page. This also made the HEA-1752 required-action gate reachable on
  the scoped and admin login surfaces (HEA-1763).

### Security
- **`hearth-loadtest seed` params redact the admin token in `Debug` output** —
  `SeedParams` now hand-implements `Debug` so a panic or error-context print can
  never spill a `--admin-token` / `HEARTH_LOADTEST_ADMIN_TOKEN` bearer token into
  logs; the README's attach flow now leads with the env var because `make`
  echoes expanded `ARGS` (flag form lands in terminal/CI logs and `ps`)
  (HEA-1795).
- **Single-node `put_if_absent` is now atomic, closing the capability-JTI TOCTOU
  window** — the `StorageEngine::put_if_absent` trait default is a non-atomic
  get-then-put, and `EmbeddedStorageEngine` did not override it, so the
  capability-token single-use JTI guard (HEA-1757 G2) still had a narrow race
  under concurrent Tokio tasks on a multi-threaded executor in single-node mode:
  two requests bearing the same capability token in a sub-millisecond window
  could both observe the JTI as absent and both spend it. `EmbeddedStorageEngine`
  now overrides `put_if_absent` to hold a write lock across the existence check
  and the write, so exactly one concurrent writer wins per key. Cluster mode was
  already atomic via Raft and is unaffected (HEA-1767).
- **Webhook egress SSRF guard extended to connect-time DNS resolution** — the
  pre-flight `check_webhook_url` guard validated the destination, but `ureq`
  then performed its own DNS lookup before `connect()`, leaving a DNS-rebinding
  TOCTOU: a hostname resolving to a public IP during the guard could be re-bound
  to an internal/link-local address (IMDS `169.254.169.254`, RFC 1918) before
  the connect. All four webhook egress paths (dispatcher, approval notifier,
  pre-token webhook, and the admin webhook test-ping) now build their `ureq`
  agent with an SSRF-validating resolver that rejects private/reserved addresses
  on the *exact* lookup that feeds `connect()`, collapsing the two lookups into
  one. The admin test-ping additionally now pins `max_redirects(0)` so a `3xx`
  can no longer chase an internal target, matching the other paths (HEA-1762).
- **gRPC audit reads require `hearth.realm.admin`; OIDC nonce replay scoped;
  CSP tightened** — a batch of function-level authz and defense-in-depth fixes
  (HEA-1757). (Z1) `AuditService.list_events` and `verify_integrity` on the gRPC
  surface authenticated the admin token but never asserted a permission, so any
  authenticated sub-admin (e.g. a users-only admin) could read the audit log —
  both RPCs now require `hearth.realm.admin`, matching the REST surface. (O3)
  the OIDC nonce replay-protection set was keyed on the raw nonce value globally,
  so an identical nonce independently chosen by clients in different realms could
  spuriously reject one as a replay; the set is now keyed by realm + client. (M1)
  the `/ui/**` Content-Security-Policy now pins `object-src 'none'` and
  `form-action 'self'`, and the capability-token single-use JTI guard now uses an
  atomic `put_if_absent` (closing a check-then-set TOCTOU double-spend window).
- **Audit hash-chain hardened against false alarms, prune breakage, and tail
  truncation** — three integrity gaps in the tamper-evident audit log are
  closed (HEA-1756). (1) Events sharing the same microsecond timestamp were
  stored under UUID-suffixed keys, so the storage scan order could diverge from
  append order and `verify_integrity` raised a false tamper alarm; the primary
  key now embeds a per-realm monotonic sequence so scan order always equals
  append order. (2) Retention pruning (`prune_before` / `max_rows` backstop)
  permanently invalidated the chain because the surviving events chained from a
  now-deleted event; pruning now re-anchors the chain to the last-pruned event's
  hash so the retained window still verifies. (3) A new per-realm HMAC-signed
  chain head (last hash + live-event count) is persisted atomically with each
  append and prune, so deleting the newest events (tail truncation) is now
  detected by `verify_integrity` instead of passing silently (U1/U2/U3).
- **Token endpoint enforces confidential-client authentication** — the
  `authorization_code` exchange never verified `client_secret`, so a
  confidential client's code could be redeemed by anyone who intercepted it, and
  the `refresh_token` grant had no client authentication or token↔client
  binding. The token endpoint (`POST /token` and `/realms/{realm}/token`, plus
  the gRPC `TokenExchange` RPC) now requires a valid `client_secret` (HTTP Basic
  Auth or body parameter) for confidential clients on code exchange, and
  `rotate_grant_family` binds each refresh grant to the confidential client it
  was issued to — a refresh token minted for one confidential client can no
  longer be redeemed unauthenticated or by a different client. Public (PKCE)
  clients are unaffected (O1+O2, HEA-1755).
- **Webhook egress no longer follows HTTP redirects** — the SSRF guard
  (`check_webhook_url`) only validated a webhook's initial destination, so a
  `3xx` response could bounce the request to an internal/link-local address
  (IMDS `169.254.169.254`, RFC 1918) that was never checked. All three egress
  paths (event dispatcher, approval notifier, pre-token webhook) now pin
  `max_redirects` to `0` and require `https_only`, refusing any redirect. DNS
  rebinding TOCTOU remains a separate residual risk (W1, HEA-1754).
- **Delegation consent revocation now invalidates session-bound OBO tokens** —
  revoking a delegation grant projected the token's `jti` into the revocation
  cache, but `validate_token` only consulted that cache on the sessionless
  (client_credentials) path. A session-bound on-behalf-of token therefore stayed
  valid until natural expiry after its consent was revoked; the session path now
  checks the revocation cache too (G1, HEA-1753).
- **Capability-token JTI is spent only after all authorization checks pass** —
  the single-use JTI for an approval capability token was recorded before the M5
  caller-binding check, so an unauthorized caller could grief the legitimate
  holder by replaying the token once (burning the JTI) and causing the rightful
  caller's use to be rejected as already-spent. The JTI is now recorded only
  after caller binding and all other checks succeed (G2, HEA-1753).
- **Token exchange rejects a revoked agent anywhere in the delegation chain** —
  a revoked agent previously resolved to the loosest global delegation-depth
  ceiling (fail-open) and was not blocked as an actor. RFC 8693 token exchange
  now rejects the request when the actor or any entry in the subject's `act`
  chain resolves to a `Revoked` agent (G3, HEA-1753).
- **MFA completion no longer bypasses pending required actions** — the browser
  MFA challenge (`POST /ui/mfa-challenge`) and forced-enrollment
  (`POST /ui/mfa-enroll-required/activate`) handlers now run the required-action
  gate before issuing a session, matching the direct-login and OIDC
  interceptors. A user with a pending required action (forced password change,
  email verification, forced enrollment) is redirected into the required-action
  flow instead of receiving a session (D1, HEA-1752).
- **MFA pending-cookie nonce redemption is now atomic** — the single-use nonce
  check-and-burn is serialized under a per-nonce lock, so two concurrent MFA
  challenge submissions replaying the same pending cookie can no longer both
  succeed (M1a, HEA-1752).
- **SAML IdP SSO endpoints now require an authenticated session** — `GET`/`POST`
  `/ui/realms/{realm}/saml/sso` and `GET /ui/realms/{realm}/saml/sso/init` previously minted a
  signed SAML assertion for any anonymous caller (a signing oracle) using a fixed placeholder
  subject. Both now require a valid Hearth UI session in the same realm and derive the assertion
  `NameID` from the authenticated user; unauthenticated callers are redirected to login (S1,
  HEA-1751).
- **SAML HTTP-Redirect binding caps DEFLATE inflation** — inbound `SAMLRequest`/`SAMLResponse`
  payloads are now bounded to 1 MiB of decompressed output, rejecting DEFLATE decompression bombs
  before they can exhaust memory (S2, HEA-1751).
- **SAML audience/destination no longer sourced from the `Host` header** — when
  `onboarding.base_url` is configured, SAML assertion audience/destination validation uses that
  trusted origin instead of the attacker-controllable request `Host`, closing a spoofing bypass
  (S3, HEA-1751).
- **SAML assertions without `Conditions/NotOnOrAfter` are rejected** — an assertion carrying no
  expiry upper bound was previously accepted and would never age out, making it replayable
  indefinitely; a missing `NotOnOrAfter` is now rejected (S4, HEA-1751).
- **SAML SP `want_assertions_signed` is now enforced per connector** — the
  federation connector's `want_assertions_signed` YAML flag was parsed but
  silently dropped during reconcile, so the SP ACS always fell back to accepting
  a Response-level signature regardless of configuration. The flag now flows
  through to the ACS: when set to `true`, an inbound assertion that is not
  individually signed is rejected instead of accepted (S4 Part A, HEA-1759).
- **GitHub federation no longer trusts the public profile email as verified** — the
  `/user.email` field is accepted as verified only when it also appears as a verified row in
  `/user/emails`; unverified addresses are neither surfaced nor marked verified, preventing
  auto-link account takeover (S5, HEA-1751).
- **OAuth client registration now requires admin authorization** — `POST /clients` (REST) and
  `OAuthService.register_client` (gRPC) previously skipped every authorization gate, letting any
  unauthenticated caller mint OAuth clients (bypassing the realm's `dcr_policy` that guards
  `POST /register`). Both now require an admin bearer token carrying `hearth.clients.admin` (or
  `hearth.admin`), matching the `/admin/clients` and `ApplicationAdminService.create_application`
  gates. Unauthenticated dynamic registration remains available via `POST /register` under
  `dcr_policy`. Proto-registered clients now default to `ThirdParty` trust, so they present the
  consent screen instead of silently skipping it (HEA-1750).
- **Delegated (`act`) token RBAC permissions now attenuated** — token exchange previously copied
  the subject's full `permissions` claim verbatim into the delegated token, allowing any actor
  (regardless of its own RBAC grants) to acquire admin-level access by exchanging an admin's
  token. Effective permissions on `act`-bearing tokens are now the intersection of the subject's
  and actor's own permission sets. `roles` and `groups` are cleared on delegated tokens. Decision
  documented in `AUTHORIZATION.md § 16` (HEA-1726).
- **Privilege-ceiling enforced on `create_role` and `update_role`** — a sub-admin holding
  `hearth.realm.admin` could previously create a role with arbitrary permissions (including
  `hearth.admin`) or update an existing role to include permissions the caller does not hold.
  Both gRPC handlers now reject any permission set where the caller does not already hold each
  listed permission, unless the caller has `hearth.admin`. Prevents role-definition poisoning
  and the direct self-escalation path (update own assigned role → receive `hearth.admin` on
  next token issuance) (HEA-1734).
- **Privilege-assignment ceiling enforced on `GrantUserPermission` and `AddAdditionalRole`** —
  a sub-admin holding `hearth.realm.admin` could previously call the gRPC `GrantUserPermission`
  RPC or `AddAdditionalRole` to grant themselves or any user the `hearth.admin` permission (or a
  role carrying it), escalating to full realm superuser. Both RPCs now reject any grant where the
  assigner does not already hold the permission (or every permission in the target role) unless the
  caller has `hearth.admin`. The fix mirrors the existing ceiling already enforced on the role
  assignment path (HEA-1722).
- **Unauthenticated `POST /authorize` now rejected** — the machine-API authorization endpoint
  previously accepted a caller-supplied `user_id` with no authentication, allowing any party who
  knew a valid `client_id`, `redirect_uri`, and `user_id` (all non-secret) to mint an OAuth
  authorization code for an arbitrary account — a pre-authentication account takeover. The
  endpoint now requires a valid Bearer token; the token's `sub` is used as the authoritative
  user identity and any body-supplied `user_id` is ignored. The same fix applies to
  `POST /realms/{realm}/authorize` and the gRPC `Authorize` RPC (HEA-1721).
- **Tool-gate H2: realm tool-group map now loaded from config; fail-closed on error** — `POST /v1/tools/invoke`
  previously built an empty `ToolGroupMap` on every request, so `toolgroup.{g}.deny` permissions
  could never fire and the `Allow` outcome was always returned for group-member tools. The handler
  now loads the realm's `tool_registry.groups` map from stored config; if the realm cannot be
  loaded the request is rejected with 500 (fail-closed) rather than silently bypassing group denies
  (HEA-1723).
- **Tool-gate M4: DPoP proof now enforced when token carries `cnf.jkt`** — a stolen DPoP-bound
  access token could previously be replayed as a plain bearer against `POST /v1/tools/invoke`
  because the endpoint never checked for a matching DPoP proof. The handler now requires a valid
  DPoP proof (signature, `htu`, `htm`, nonce, JTI replay, jkt thumbprint binding) when the token
  has a `cnf.jkt` claim; missing or mismatched proofs return 401 with a `DPoP-Nonce` header
  (HEA-1723).
- **Tool-gate M5: capability token caller binding enforced** — `validate_capability_token_inner`
  previously validated a capability token's signature, expiry, tool/action, and single-use JTI
  without checking that the presenting agent is the one the approval was minted for. Agent A could
  consume an approval minted for Agent B (confused-deputy attack). The engine now requires
  `capability.sub == caller_sub` (the `sub` from the caller's bearer token), rejecting cross-agent
  capability token presentation (HEA-1723).
- **Tool-gate M6: `Allow`-path invocations now emit `AgentToolInvocation` audit records** — only
  the capability-token (approval) path previously emitted an audit event; a plain `Allow` returned
  200 with no record, creating a blind spot for all non-approval tool invocations. The `Allow` arm
  now writes an `AgentToolInvocation` audit event before returning (HEA-1723).
- **WebAuthn discoverable-login userHandle spoofing fixed** — in the discoverable passkey flow,
  the server now rejects any assertion where the client-supplied `userHandle` does not match the
  credential owner resolved from the server-side discoverable index. Previously, an attacker with
  a valid discoverable credential in the target realm could substitute an arbitrary victim UUID
  into `userHandle` (which is not covered by the WebAuthn signature) and receive a valid session
  for the victim account — a pre-authentication account takeover (CWE-287 / CWE-639). The
  discoverable index is now authoritative; `userHandle` is validated, not trusted (HEA-1720).
- **JSON embedded in `<script>` tags now HTML-escaped (M10)** — the admin config editor and roles
  tab rendered `serde_json` output verbatim inside `<script type="application/json">` elements;
  a stored config value containing `</script>` would prematurely close the tag, creating a latent
  stored-XSS vector. JSON is now `</` → `<\/` escaped before template injection (HEA-1728).
- **Refresh tokens now DPoP sender-constrained (M1 — RFC 9449 §5)** — refresh tokens were
  minted with no `cnf` claim and the refresh path never verified DPoP key binding, so a stolen
  refresh token was usable by any holder regardless of key possession. The grant family now records
  the `bound_jkt` (JWK thumbprint) from the DPoP proof presented at authorization-code exchange;
  the refresh token carries the matching `cnf.jkt` claim; and subsequent refresh calls are rejected
  with `invalid_token` if the caller presents a different or absent JKT. Non-DPoP flows are
  unaffected (HEA-1725).
- **Token-exchange grant now requires client authentication (M2 — RFC 8693 §2.1)** — the
  `urn:ietf:params:oauth:grant-type:token-exchange` handler previously accepted an
  unauthenticated `client_id` body parameter and derived the `act.sub` claim and
  `AgentDelegation` audit actor from it, allowing any caller to forge the acting-party identity
  by supplying an arbitrary UUID. The handler now calls the standard client authentication path
  (`verify_endpoint_client`); confidential clients must present a matching secret (via body
  parameter or HTTP Basic Auth); `act.sub` is derived from the verified identity (HEA-1725).
- **Email-verify token now protected by per-token redemption lock (L6)** — the email-verification
  token lacked the TOCTOU guard already present on password-reset and magic-link redemption. Two
  concurrent requests with the same token could both pass the used-check. A per-hash mutex
  (`token_redemption_lock`) is now acquired before any read-modify-write (HEA-1728).
- **Token introspection scoped to intended audience (L7)** — any authenticated realm client could
  previously introspect any token regardless of whether the token was issued to it. The endpoint
  now enforces per-token-class audience restriction (RFC 7662 §2): (1) tokens carrying an `azp`
  claim may only be introspected by the `azp` client or a member of the token's `aud`; (2)
  M2M/`client_credentials` tokens (no `azp`, `sid == "none"`) may only be introspected by the
  issuing client (`sub == client_id`) or an explicit `aud` member; (3) user-session tokens with
  no `azp` may be introspected by any authenticated realm client. All other cases return
  `{ "active": false }` (HEA-1728, HEA-1729).
- **`Cache-Control: no-store` added to all authenticated HTML responses (L8)** — the
  `SecurityHeadersLayer` now emits `Cache-Control: no-store` on any `text/html` response,
  preventing sensitive admin and account pages from being retained by shared or private caches.
  Static assets (CSS, JS, fonts) are unaffected (HEA-1728).
- **MFA at-rest DEK decoupled from signing key (H3)** — TOTP secrets and recovery-code blobs were
  previously encrypted with an HKDF-derived DEK keyed from the realm's Ed25519 signing key.
  Rotating the signing key (an advertised operator feature) silently changed the DEK, making every
  TOTP verification fail immediately after rotation and locking all MFA-enrolled users out of their
  accounts. Each realm now receives a dedicated 32-byte random MFA DEK stored separately (like the
  audit HMAC key), KEK-wrapped when `security.key_encryption_key` is configured. Signing-key
  rotation no longer touches MFA data. Any blobs still encrypted under the old signing-key-derived
  DEK are re-encrypted atomically during the next rotation call (HEA-1724).
- **Pre-token and approval webhooks now routed through SSRF guard (M7)** — webhook delivery
  previously bypassed the `check_webhook_url` SSRF check, allowing a configured webhook URL to
  target RFC 1918 / loopback / link-local / ULA addresses (cloud-metadata SSRF). Both the
  pre-token enrichment webhook and the approval-notification webhook are now checked at
  registration time (https:// scheme required; http:// rejected) and at delivery time (DNS
  resolution blocks private ranges). Tests updated to use https:// URLs (HEA-1727).
- **Client IP extraction now trusted-proxy-aware (M8)** — `register_client_ip` and
  `captcha_client_ip` previously trusted the leftmost `X-Forwarded-For` header value, allowing a
  remote attacker to spoof their source IP by prepending an arbitrary address to XFF. Both
  extraction sites now use `extract_client_ip(headers, fallback_peer, trusted_proxies)`, which
  walks XFF right-to-left and stops at the first non-trusted hop — returning the true client IP
  regardless of attacker-controlled XFF values (HEA-1727).
- **`SessionCreated` and `TokenIssued` audit events now include client IP and user-agent (M9)**
  — success-path authentication events previously emitted no metadata, making IP- or UA-based
  forensics impossible after a breach. `SessionContext` IP and UA are now threaded into
  `AuditContext.metadata` (`client_ip`, `user_agent`) for `SessionCreated` and `TokenIssued`
  audit events (HEA-1727).
- **HIBP breach check now enabled by default** — `BreachCheckConfig::default()` previously
  had `enabled: false` (safe migration default for existing deployments). The default is now
  `enabled: true` so new realms get breach checking out of the box without explicit
  configuration. Existing configs that explicitly set `enabled: false` are unaffected.
  Integration tests inject a no-network stub transport to avoid HIBP API calls in CI
  (HEA-1727).
- **WebAuthn RP ID derived from `oidc.issuer` config, not `Host` header (L5)** — the
  relying-party origin used during passkey registration and authentication was previously derived
  from the request's `Host` header. An attacker who could manipulate the `Host` header during a
  WebAuthn ceremony could redirect the server to validate assertions against a different origin
  than the one the credential was bound to. `resolve_public_origin` now unconditionally prefers
  `config.oidc.issuer` as the RP origin; the `Host` header is used only as a fallback when no
  issuer is configured (HEA-1729).
- **SCIM JWT-fallback path now rejects cross-realm JWTs** — when a SCIM endpoint received no
  per-realm bearer token and fell back to validating a JWT in the `Authorization` header, the
  server previously accepted any valid admin JWT regardless of which realm it was issued for. An
  admin of realm A could present their JWT against realm B's SCIM endpoints (identified via
  `X-Realm-ID`) and gain cross-realm user-provisioning access. The fallback path now asserts
  `jwt.realm_id == X-Realm-ID`; a mismatch returns `403 Forbidden` with `"realm mismatch"` (HEA-1738).

### Changed
- **Password minimum length floor raised from 8 to 12 characters (NIST SP 800-63B §5.1.1.1)**
  — the unconditional hard floor for all password-setting and self-registration call sites has
  been raised from 8 to 12 characters. Realm `password_policy.min_length` may still raise this
  higher but cannot lower it below 12. Deployments where users have passwords shorter than 12
  characters are unaffected at login (existing hashes remain valid); the floor applies at the
  next password change (HEA-1727).

### Fixed
- **Dev-mode `oidc.issuer` defaults to actual server URL** — when running `hearth serve --dev`
  without an explicit `oidc.issuer` config, the server now uses `http://127.0.0.1:{port}` as the
  issuer base instead of the placeholder `https://hearth.local`. Token `iss` claims are now
  reachable, allowing JWKS-verifying clients to derive the per-realm JWKS URL directly from
  the `iss` claim without a hostname mismatch (HEA-1716).
- **CI quality job no longer masks nextest on advisory failure** — removed the redundant
  `cargo deny check` step from the `quality` job (already covered by the dedicated
  `cargo-deny` job); added `continue-on-error: true` to `cargo audit` so advisory hits
  never suppress test results. Both checks still fail the build via their own named CI jobs
  (HEA-1714).
- **Session access/refresh tokens now verify** — `issue_tokens` signs session-originated
  tokens with the realm's per-realm signing key instead of the global key. HEA-SEC-18
  removed the global-key fallback from signature verification (fail-closed), so
  session tokens signed with the global key were rejected by `validate_token`,
  `refresh_tokens`, and introspection with `InvalidToken`. Restores password/session
  login, `/admin/bootstrap`, and admin/tenant sessions (HEA-1712).
- **Per-realm token issuer accepted at validation** — `validate_token` now accepts an
  `iss` that matches the configured `token.issuer` or is issued under the `oidc.issuer`
  base (`{base}` or `{base}/realms/{name}`), matching what issuance produces. The prior
  exact-match against `token.issuer` rejected every real token (HEA-1712).

### Security
- **RUSTSEC-2026-0204 (crossbeam-epoch)** — bumped `crossbeam-epoch` 0.9.18 → 0.9.20 to
  remediate an invalid pointer dereference advisory flagged by `cargo deny` (HEA-1712).

### Added
- **Auth-discard CI lint** — `scripts/check-auth-discard.sh` and `make auth-discard-check`
  fail on any occurrence of `let _auth`, `let _ = extract_admin_auth(...)`, or an unbound
  `authenticate_admin()` call in `src/protocol/http/admin.rs` and `src/protocol/grpc/*.rs`.
  Wired into the `filter` CI job (runs on every PR, no Rust build required) and
  `make ci-local-fast`. Prevents recurrence of the cross-realm BOLA class found in
  HEA-1629 (HEA-1657).
- **Auth-boundary PR review checklist** — `docs/guides/security-hardening.md` now
  documents the automated CI backstops, a five-point manual review checklist, and the
  `// auth-discard-lint-allow` suppression escape hatch for auth-boundary PRs (HEA-1657).

### Added
- **TLS 1.3-only mode** — `security.tls.min_version: "1.3"` config option restricts the server
  to TLS 1.3 only, rejecting TLS 1.2 clients at the handshake level. Default `"1.2"` preserves
  existing TLS 1.2+1.3 behaviour. Recommended for high-security deployments (HEA-SEC-33).

### Security
- **HSS-010 (Argon2 parallelism rehash)** — `argon2_params_need_rehash` now includes
  the `p` (parallelism) parameter; a stale value triggers rehash on next login (HEA-SEC-34).
- **WEB-005 (Captcha site_key XSS)** — Turnstile `site_key` is HTML-attribute-escaped
  before insertion into widget HTML (HEA-SEC-34).
- **OAUTH-04 (Redirect URI schemes)** — Non-reverse-DNS custom URI schemes emit a
  `tracing::warn` at client registration; advises RFC 8252 §7.1 format (HEA-SEC-34).
- **HSEC-008 (Device code TTL)** — Device code lifetime is now configurable per realm
  via `auth.token.device_code_ttl`; hard-capped at 30 minutes (HEA-SEC-34).
- **HSS-008 (Magic link invalidation)** — Requesting a new magic link invalidates all
  existing unexpired tokens for the same email (HEA-SEC-34).
- **WEB-009 (gRPC reflection auth)** — Reflection service now requires
  `Authorization: Bearer <token>`; unauthenticated callers get `UNAUTHENTICATED` (HEA-SEC-34).
- **Minimal security headers on all REST API responses** — `X-Content-Type-Options: nosniff`
  and `Referrer-Policy: no-referrer` are now applied to every HTTP response from the REST API,
  not only the web UI. Prevents MIME-type sniffing and referrer leakage (HEA-SEC-33).
- **Rust SDK: PKCE and OAuth state use OS entropy** — `rand::thread_rng()` (userspace CSPRNG)
  replaced with `ring::rand::SystemRandom` (direct OS entropy, consistent with server-side)
  in PKCE verifier generation and OAuth state token generation. The `rand` crate dependency
  has been removed from the SDK (HEA-SEC-32).
- **Nonce replay protection is now unconditional** — `oidc.enforce_nonces` opt-out config key
  has been removed. Duplicate nonces are always rejected per OIDC Core §3.1.2.1. Setting
  `enforce_nonces: false` in `hearth.yaml` is a hard startup error (HEA-SEC-29).
- **PKCE required for all clients** — `oidc.require_pkce_for_confidential_clients` opt-out
  config key has been removed. All authorization code flows, including confidential clients,
  must supply `code_challenge` (S256). Setting `require_pkce_for_confidential_clients: false`
  is a hard startup error (HEA-SEC-29).
- **Authorization code TTL reduced to 60 seconds** — default `oidc.authorization_code_ttl`
  is now 60 s (down from 600 s). Reduces exploitation window for intercepted auth codes.
  Operators may configure a longer TTL via `oidc.authorization_code_ttl` (HEA-SEC-29).
- **JWKS endpoint hardened** — Three improvements (HEA-SEC-28): (1) `GET /jwks` (and
  aliases `/certs`, `/.well-known/jwks.json`) now returns `Cache-Control: max-age=3600,
  must-revalidate` so clients know when to re-fetch and avoid serving stale keys after
  rotation (JWT-015). (2) Each JWK object carries a non-standard `x-key-role` annotation
  (`"access-token-signing"`, `"saml-signing"`, or `"ecdsa-compat"`) to disambiguate key
  purpose for external relying parties (JWT-006). (3) The `OPTIONS /token` preflight
  handler now returns the same 204 response structure regardless of whether the requesting
  origin is registered, closing a CORS-oracle information-disclosure that allowed origin
  enumeration by observing which preflights received CORS headers (OAUTH-10).
- **Host key file integrity framing** — `hearth.host_key` is now written and verified with
  a magic header (`HRTHHKY1`) and an HMAC-SHA256 integrity tag covering the magic and key
  bytes. A file that is the correct length but has corrupt content (or is a random 32-byte
  blob left by another tool) is now rejected at startup with a clear error. A startup
  warning is also emitted on non-Unix platforms where OS file ACLs cannot be enforced,
  directing operators to use `HEARTH_MASTER_KEY` instead (STOR-003 / HEA-SEC-26).
- **CRC-corrupt KEK entries block startup** — A CRC mismatch in a `hearth.keys` entry now
  returns `StorageError::CorruptedKeks` and blocks startup rather than silently skipping the
  entry and leaving the realm's SSTs silently unreadable. The error names all affected realm
  IDs so operators know exactly which data requires restore from backup
  (STOR-004 / HEA-SEC-26).
- **`nbf` claim validation enforced** — `validate_token_with_time` now rejects tokens whose
  `nbf` (not-before) claim is in the future, with a configurable 60-second clock-skew
  tolerance per RFC 7519 §4.1.5. Previously, a future-dated token would be accepted
  immediately after issuance (HEA-SEC-27).
- **JTI assigned to all access tokens** — `issue_token_pair` now generates a UUID JTI for
  every issued access token. Previously, session-bound tokens had `jti: None`, causing
  JTI-based revocation checks to silently skip them (HEA-SEC-27).
- **Hard TTL caps on access and refresh tokens** — Config validation now enforces a hard
  cap of 1 hour on `token.access_token_ttl` (global and per-realm) and 30 days on
  `token.refresh_token_ttl`, regardless of `allow_unsafe_ttl`. Operator warnings are
  emitted at startup when TTLs exceed 15 minutes (access) or 24 hours (refresh)
  (HEA-SEC-27). The `nbf` field is also now surfaced in introspection responses
  (RFC 7662 §2.2).
- **Password minimum length enforced unconditionally** — A hard floor of 8 characters is
  now applied at every password-setting and self-registration call site regardless of
  whether a realm `password_policy` is configured. Previously, an absent policy allowed
  any password including empty strings. The floor cannot be overridden downward by
  per-realm operator configuration; a higher `min_length` in the policy is still respected.
  A production startup warning is emitted when the system realm has no explicit
  `password_policy` configured (HSEC-003 / HEA-SEC-23).
- **System realm MFA enforcement is opt-in; explicit disable is blocked** — MFA defaults
  to not required for all realms including the system realm, preserving bootstrappability on
  a fresh install (HSEC-004 revised — prior default-on broke bootstrap). Operators who want
  second-factor enforcement on the admin control plane should enroll MFA for all admin
  accounts and then set `mfa_required: true` in `hearth.yaml`. A production startup warning
  is emitted when the system realm has no explicit `mfa_required` setting. Explicitly setting
  `mfa_required: false` on the system realm remains a hard startup error (HSEC-004 / HEA-SEC-23).
- **Token substitution rejected at introspection** — `POST /introspect` now returns
  `{"active": false}` for any token whose `token_type` claim is not `"access"`. Previously
  a valid ID token or refresh token could be presented to the introspection endpoint and
  return `active: true`, allowing a confused-deputy attack against resource servers that
  use introspection for authorization (OAUTH-08 / HEA-SEC-22).
- **Authorization code TOCTOU closed** — The auth-code exchange now holds a per-code
  advisory mutex across the load → delete → issue window. Previously two concurrent
  requests with the same code could both load the code before either deleted it, producing
  two valid token sets from one authorization grant (OAUTH-06 / HEA-SEC-22).
- **Audit log integrity hardened** — three STOR-class fixes (HEA-SEC-21):
  (1) Administrative prune operations are now recorded as `AuditLogPruned` events in the
  audit log *before* deletion, so a crash-interrupted prune always leaves a trace.
  (2) Per-event deletion in `prune_before` / `prune_oldest` is now atomic via `write_batch`,
  eliminating orphaned actor and action index entries on crash.
  (3) The hash chain is upgraded from unkeyed SHA-256 to HMAC-SHA256 with a per-realm key
  stored at rest (KEK-wrapped when a key-encryption key is configured), preventing a
  storage-layer attacker from recomputing a valid chain after deleting events.
- **JWT issuer validation** — `validate_token` now enforces RFC 7519 §4.1.1: the `iss`
  claim must exactly match the configured `token.issuer` value. Previously this claim was
  never verified, allowing tokens from foreign Hearth instances to pass validation when
  they carried a valid signature and correct realm binding (HEA-SEC-18).
- **Global signing-key fallback removed** — `verify_token_signature_for_realm` is now
  fail-closed: signature verification uses only the realm's own per-realm key. The legacy
  global-key fallback — which could accept global-key-signed tokens for any realm — has
  been removed. Every realm has a dedicated key provisioned at creation time (HEA-SEC-18).
- **HTTP rate limiting wired to REST router** — `RequestShaper` (per-IP + per-realm
  sliding-window, 100 rps/IP default) is now applied as an axum Tower middleware on all
  matched HTTP routes. The same `Arc<RequestShaper>` is shared with the gRPC server so
  per-IP counters accumulate across protocols and callers cannot evade the limit by
  switching from REST to gRPC. The limit is configurable via `security.request_shaper`
  in `hearth.yaml` (HEA-SEC-17).
- **DPoP nonce enforcement** — `POST /token` and `POST /realms/{name}/token` now require
  a valid server-issued nonce in every DPoP proof. Proofs that omit or supply an expired
  nonce are rejected with HTTP 401 `use_dpop_nonce`; the response includes a fresh
  `DPoP-Nonce` header so clients can retry. Without this enforcement, a stolen DPoP
  proof JWT was replayable within its 120-second `iat` window (HEA-SEC-17).
- **Host header allowlist enforcement** — `security.allowed_hosts` in `hearth.yaml` is
  now enforced by an outermost Tower middleware. Requests whose `Host` header is not in
  the allowlist are rejected with HTTP 400 before any route dispatch. An empty list
  (the default) preserves fail-open behavior for existing deployments (HEA-SEC-16).
- **At-rest encryption for signing keys and DPoP secrets** — Per-realm Ed25519
  signing keys, the global signing key, the OIDC RSA key, SAML RSA keys, and
  DPoP nonce secrets are now wrapped with AES-256-GCM before being written to
  the WAL when `security.key_encryption_key` (or the `HEARTH_KEK` env var) is
  set. Existing plaintext entries in legacy WALs continue to load transparently
  and are re-encrypted on the next key rotation. A `realm:key:*`,
  `sys:global:key`, `sys:oidc:rsa:*`, and `agt:dpop:nonce-secret` prefix guard
  (`is_key_material`) is added to identify key-material entries that must be
  excluded from admin export and storage scan paths (HEA-SEC-09).
- **Privilege-ceiling enforcement on role assignment** — `POST /admin/users/:id/roles`
  and the gRPC `AssignUserRole`/`AssignGroupRole` RPCs now enforce that a sub-admin
  may only assign roles whose effective (transitive) permission set is a subset of
  their own. Previously a `hearth.realm.admin` caller could assign the `realm.admin`
  role (which carries `hearth.admin`) to any user, achieving full privilege escalation.
  `hearth.admin` callers bypass the ceiling check and may assign any role. A new
  `RbacEngine::resolve_role_permissions` method expands the role's parent chain to
  compute the transitive set used for the check. Blocked attempts are logged at WARN.
  Regression tests in `tests/admin_rbac_auth.rs` (HEA-SEC-13).
- **Pre-token webhook HMAC secret enforced** — `update_realm` and `create_realm`
  now reject any `pre_token_webhook` configuration that omits or supplies an empty
  `hmac_secret`. An unsigned webhook endpoint allows any caller reachable from the
  webhook URL to forge enrichment responses and inject arbitrary JWT claims into
  issued tokens. Operators must supply a non-empty `hmac_secret` for webhook
  configurations to be accepted (HEA-SEC-20).
- **Dev mode fail-closed defaults** — Server refuses to start with `--dev` when
  `server.bind_address` is non-loopback (blocks network exposure of weak Argon2,
  CSRF bypass, and plaintext token logging). `WebState::new()` now defaults
  `dev_mode = false`; tests requiring the CSRF bypass must call
  `.with_dev_mode(true)` explicitly. Setup token is truncated to an 8-char
  prefix in dev-mode startup logs; full token remains readable from the
  `.setup_token` file. ERROR-level startup log lists all active security
  reductions when `dev_mode = true` (HEA-1678).
- **Bootstrap admin password is now randomly generated** — `POST /admin/bootstrap` generates
  a cryptographically random 32-character password via `ring::rand::SystemRandom` on first
  call and returns it once in `admin_password`. Re-bootstrap no longer resets the existing
  password (previously reset to the hardcoded `HearthTest123!` on every call, allowing
  credential recovery by anyone who could trigger bootstrap). Re-bootstrap now requires a
  valid Bearer token from the initial call (HEA-1670).
- **Per-operation gRPC permission checks** — `RbacAdminService`, `IdentityAdminService`, and
  `ApplicationAdminService` now enforce the same per-operation sub-permission that the HTTP
  surface does. Previously the outer gate admitted any sub-admin token and no handler-level
  check narrowed it, allowing `hearth.users.admin` to invoke `create_role` / `delete_realm`
  and similarly for all other sub-admin/operation mismatches. `grpc_require_permission()`
  mirrors `require_admin_permission()` on the HTTP path; `hearth.admin` still bypasses all
  per-handler checks. `hearth.agents.admin` is now accepted at the gRPC outer gate, the HTTP
  outer gate, and a new seeded role and permission record. 17 regression tests added in
  `tests/grpc_sub_admin_bfla.rs` (HEA-SEC-04).
- **CORS allowed-origins decoupled from redirect URIs** — `OAuthClient` gains an
  explicit `cors_origins` field distinct from `redirect_uris`. The token endpoint
  now only reflects `Access-Control-Allow-Origin` for origins listed in `cors_origins`;
  a redirect URI no longer implicitly grants cross-origin token access. The
  `Access-Control-Allow-Credentials: true` header is removed from the token endpoint
  entirely — PKCE flows use authorization codes, not cookies. DCR accepts an optional
  `cors_origins` array; the admin REST API and gRPC surface expose the field for
  update (HEA-1674).
- **DCR `Authenticated` policy (RFC 7591 §3.1)** — `DcrPolicy` gains an
  `Authenticated` variant requiring a valid realm bearer token before any client
  may self-register via `POST /register`. The prior `Open` policy accepted
  anonymous callers; it still works but now emits a tracing warn. Configurable as
  `dcr.mode: authenticated` in `hearth.yaml` (HEA-1671).
- **ROPC gated per-client via `grant_types`** — `POST /token` with
  `grant_type=password` now returns `400 unauthorized_client` if the presented
  `client_id` belongs to a client whose registered `grant_types` do not include
  `"password"`. Prevents any client from being silently usable for ROPC (HEA-1671).
- **Rate-limit counters persisted to WAL** — five secondary rate-limit trackers
  (`ip_login`, `mfa`, `magic_link`, `password_reset`, `registration_email`) were
  previously in-memory only and reset to zero on every process restart, allowing
  an attacker to bypass brute-force and abuse-rate limits with a simple server
  restart or rolling-restart deploy. All five now write increments to the WAL and
  are restored on startup; the sweep also prunes stale WAL entries to bound storage
  growth. The per-user password-failure tracker (`attempt_trackers`) was already
  WAL-persisted and is unaffected (HEA-1669).
- **Pre-token webhook HMAC signing implemented** — `hmac_secret` now produces a real
  `X-Hearth-Signature-256: sha256=<hex>` header over the serialized request body; the
  prior stub silently ignored the secret, allowing claim injection by any party able to
  reach the endpoint (HEA-1661/HEA-1662).
- **Pre-token webhook timeout enforced** — the configured `timeout_ms` is now wired through
  `ureq::config::Config::timeout_global`; previously the timeout was a no-op, allowing a
  slow webhook to stall the token endpoint indefinitely (HEA-1661/HEA-1663).
- **Session revocation on user disable** — `update_user()` now calls
  `revoke_all_user_sessions` when the status transitions to `Disabled`, preventing
  previously-issued access tokens from remaining valid for up to the token TTL after an
  administrator disables the account (HEA-1661/HEA-1664).
- **HSTS `preload` directive added** — the `Strict-Transport-Security` header now includes
  `; preload`, enabling HSTS preload-list submission so browsers never attempt an initial
  plaintext connection to a Hearth deployment (HEA-1661).
- **`quick-xml` upgraded 0.36 → 0.41 (RUSTSEC advisories)** — remediates two advisories in
  the SAML XML parser: quadratic runtime on duplicate-attribute checks and an unbounded
  namespace-declaration allocation enabling memory-exhaustion DoS on crafted XML. The SAML
  reader now resolves quick-xml 0.41's standalone entity-reference events (numeric and the
  five predefined entities) and rejects any DTD-defined general entity, preserving the
  existing anti-XXE posture and canonicalization/signature-validation behavior (HEA-1629).
- **MFA-pending cookie is now single-use** — a random 128-bit nonce is embedded in
  the cookie and burned server-side on first successful MFA completion. A captured
  pending cookie can no longer be replayed after the session has been established (HEA-1656).
- **`azp` (Authorized Party) claim added to OIDC ID tokens** — ID tokens issued via
  the authorization-code and device flows now include `azp: <client_id>` per OIDC Core §2,
  satisfying FAPI 2.0 requirements (HEA-1656).
- **RP-initiated logout no longer open-redirects on unknown sessions** — `GET /end_session`
  with a `post_logout_redirect_uri` but no resolvable client now returns 200 JSON instead of
  redirecting to the caller-supplied URI. The engine also rejects unregistered
  `post_logout_redirect_uri` values when no `client_id` is provided (HEA-1656).
- **Federation account-link enumeration resistance** — `POST /ui/federation/confirm-link`
  on password failure now redirects to `/ui/login` instead of back to the confirm-link
  page with the ticket in the URL, preventing attackers from distinguishing
  "valid ticket + wrong password" from "invalid ticket" (HEA-1656).
- **MFA enroll/disable/regenerate now require step-up credential verification** — `POST /ui/account/totp/activate`
  requires the user's current password before activating MFA; `POST /ui/account/totp/disable` and
  `POST /ui/account/totp/regenerate-codes` require a fresh TOTP code before proceeding. A stolen
  session cookie can no longer silently strip or replace a user's second factor (HEA-1659).
- **OIDC RSA signing key now persisted across restarts** — the server-wide RS256 keypair (`kid`)
  is stored in the system realm under `sys:oidc:rsa:key` (WAL-synced) so previously-issued ID tokens
  remain verifiable after a restart. JWKS includes retiring keys during the configured grace window
  so tokens signed before an explicit key rotation continue to validate (HEA-1655).
- **TOTP secrets and recovery codes encrypted at rest** — `StoredMfaState.secret_base32` and
  pending recovery codes are now AES-256-GCM encrypted before being written to the WAL. The
  encryption key is a per-realm DEK derived via HKDF-SHA256 from the realm's Ed25519 signing key
  with domain label `hearth-totp-at-rest-v1`, providing cryptographic isolation between realms.
  Recovery code entropy increased from 40 bits (8 chars) to 80 bits (16 chars) of the same
  32-symbol unambiguous alphabet. Legacy plaintext records are transparently migrated on first
  write (HEA-1675).
- **Backup restore now requires `hearth.export` capability** — `POST /admin/backup/restore`
  previously admitted any sub-admin token; it now enforces `check_export_capability` and
  `check_export_rate_limit` (same gates as `POST /admin/backup`) immediately after auth.
  A `BackupRestored` audit event is emitted before the destructive import begins so the
  attempt is recorded even if the server is killed mid-stream (HEA-1682).
- **Cross-realm BOLA hardening in REST admin handlers** — introduced `scoped_realm(auth, path_realm_id)`
  accessor that enforces `auth.realm_id == path_realm_id` (system realm bypasses as superuser) for
  every endpoint that carries a `{realm_id}` path parameter. Fixes 10 handlers previously vulnerable
  to Broken Object-Level Authorization: `GET/DELETE /admin/realms/{id}`, `GET/PATCH /admin/realms/{id}/branding`,
  `GET/PUT/DELETE /admin/realms/{id}/email-templates/{k}`, `POST /admin/realms/{id}/rotate-signing-key`,
  `POST /admin/realms/{id}/sv-bump-all`. Adds missing `hearth.realm.admin` permission gate to
  `POST /admin/sessions/{id}/sv-bump`. Audit events for cross-realm mutations now log under the
  target realm rather than the auth realm (HEA-1649).

### Added
- **Users table search grammar + column sort** — the admin users list now supports
  exact (`"alice@acme.com"`), glob (`*@acme.com`, `alice?`), and substring search
  via the `q` param, plus 4-column ascending/descending sort (`sort=email|name|status|created`
  + `dir=asc|desc`). Sort is applied to the full filtered set before the page slice
  so pagination totals are always exact. Sort and search params survive page / page-size
  navigation via `preserved_params` (HEA-1633).
- **Search + column sort rolled out to every admin table** — realms, organizations,
  groups, sessions, webhooks, and identity providers now share the same search
  grammar (substring / quoted-exact `"…"` / glob `*`,`?`) and clickable `sort`/`dir`
  column headers as the users list, via the shared `_sortable_th` header macro.
  Realms and webhooks gain a `q` search bar; sessions sort by created/expires
  (default newest-first), webhooks search URL + events and sort by URL, and
  identity providers sort by name/kind. `aria-sort` is exposed on every sortable
  header and stays accurate after HTMX partial swaps (HEA-1634, HEA-1635, HEA-1636,
  HEA-1637, HEA-1638).
- **Per-SST Bloom filters (SST V2 format)** — each newly written SST file now
  embeds a Bloom filter (k = 7, ~1% FPR, ~10 bits/entry). A cold point lookup
  probes the filter in O(k) constant time (~70 ns/SST) before performing a binary
  search, so absent-key reads skip the binary search on ~99% of SSTs. At 500 k
  users (~35 SSTs), this cuts a cold miss from O(35 · log n) to approximately
  35 × 70 ns + 1 µs binary search for the single matching SST. V2 SST files carry
  magic bytes `HSS2`; the engine remains fully backward-compatible with V1 files
  (`HSST` magic), which load without a filter and pass all membership tests (HEA-1626).
- **Large-scale demo seeder (`make seed-large`)** — a new top-level `demo:` config
  block (`demo.enabled`, `demo.password`) plus a per-realm `seeding:` block
  (`users`, `email_domain`, `display_name_prefix`, `email_verified`) stand up a
  fully fleshed-out, multi-million-user instance for local scale testing. When
  `demo.enabled: true`, each realm's `seeding.users` count is bulk-inserted as
  synthetic accounts (`user0000001@<domain>`, …) that all share `demo.password`
  — hashed once and reused, so seeding 1M+ users costs one Argon2id hash, not a
  million. Seeding runs in the **background after the server is listening**, so
  the instance is reachable within ~1 s and usable while it fills (watch the
  per-100k progress logs). It is additive, synthetic-only, idempotent, and
  resumable via a per-realm sentinel; it is never reached without `demo.enabled`
  (the production guard). `make seed-large` boots
  `examples/large-scale-demo/hearth.yaml` into `./data/demo`; `make
  seed-large-reset` wipes it.

### Security
- **gRPC RBAC admin: cross-realm BOLA closed across all 30 methods (HEA-1650)** — all
  `RbacAdminService` handlers previously discarded the authenticated realm from the
  `x-realm-id` header and sourced the target realm from the request body's `realm_id`
  field instead. A realm-A admin could write groups, roles, and assignments into
  realm-B by setting `realm_id: <realm-B-uuid>` in the body. All 30 methods now
  assert that the body `realm_id` matches the authenticated realm and return
  `PERMISSION_DENIED` on mismatch; the authenticated realm is always authoritative.
- **Webhook SSRF guard at registration and delivery (HEA-1651)** — webhook URLs are now
  validated for SSRF safety (RFC 1918, loopback, link-local, ULA, cloud-metadata ranges
  blocked) at registration time via `POST /admin/webhooks` and `PUT /admin/webhooks/{id}`,
  and again immediately before each delivery attempt to defend against DNS rebinding.

### Fixed
- **Admin tables: search, sort, and pagination now interact consistently.** Sorting
  or searching only swapped the table rows, leaving the pagination bar stale — so
  sorting on page 3 showed page 1's rows under a "page 3" widget, clearing the
  search box didn't reset paging, and paging afterward re-applied the cleared query.
  Every in-place interaction now swaps a single `#…-table-region` (table + pagination)
  as one unit, and pagination links carry the full `q`+`sort`+`dir` (and session
  `status`) state, so the three controls always agree. Applies to users, realms,
  groups, organizations, webhooks, sessions, and identity providers (HEA-1615).
- **Admin tables: sorting no longer 400s when a search term is active.** Clicking a
  sort header while the search box was populated sent the `q` parameter several times
  (htmx `hx-include` repeats it), which the stock query-string parser rejected with
  `400 Bad Request` — so the sort silently did nothing. Admin list endpoints now
  tolerate duplicated query keys (keeping the last value), so sort, search, and
  pagination compose in any order (HEA-1615).
- **Performance: point lookups no longer scan the whole realm.** `StorageEngine::get`
  fell through to an `iter_realm` linear scan of the active memtable, cloning and
  scanning every entry in the realm on each key lookup. On a freshly-seeded
  500k-user realm this made a single user-detail page load O(N) — 1–2 s per lookup.
  It now uses the memtable's O(log n) `BTreeMap` lookup (new tombstone-aware
  `get_entry`), so point reads stay near-instant regardless of realm size (HEA-1614).
- **Performance: admin list page loads no longer scan and allocate the full realm prefix.** `count_prefix` and `scan_prefix_paged` previously called `scan()` on the entire prefix — materialising key + value bytes for every entry (e.g. 500 k users × ~500 B/entry ≈ 250 MB per page load). A new two-phase approach is used: a key-only scan (`scan_keys`) builds the total count without allocating any value bytes, then a bounded value scan covering only the requested page window (O(limit) instead of O(N)) returns the entries with their values. A new `StorageEngine::scan_keys` method and corresponding efficient `EmbeddedStorageEngine` override (using `range_scan_keys`/`iter_realm_range_keys` on SST and memtable layers) underpin the change (HEA-1622).
- **Pagination: admin list totals are no longer capped at 10,000.** Admin list and
  dashboard counts were truncated to a 10,000-per-prefix ceiling, so a realm with
  500,000 users reported "10,000" and the dashboard summed a wrong global total
  (4 realms → "40,000"); worse, the pager's `total_pages` was computed from the
  capped total, making every record past the first 10,000 unreachable. The storage
  count primitives (`count_prefix`, `scan_prefix_paged`) now treat `cap == 0` as
  "no ceiling" and every admin list path reports the exact count, so pagination
  spans the full result set (HEA-1614).
- **Pagination: disabled prev/next controls now use `<button disabled>` instead of
  `<span aria-disabled="true">`.** `aria-disabled` is invalid on non-interactive elements;
  the native `disabled` attribute on a `<button>` is the correct, axe-core-passing pattern
  (HEA-1621).
- **Pagination: per-page `<select>` no longer uses an inline `onchange=` handler.**
  The handler was blocked by `Content-Security-Policy: script-src 'self'`, making the
  per-page dropdown a no-op. The logic is now wired in `admin.js` via an external event
  listener (HEA-1621).
- **Storage: concurrent writes are no longer lost during a memtable flush.** The
  flush snapshotted the memtable lock-free and cleared it under the lock as two
  separate steps; a write landing in that window was silently dropped. Under a
  multithreaded server this could lose acknowledged writes (e.g. an admin created
  via the setup wizard while background work flushed, making the account
  un-loginable and invisible to password reset). The flush now snapshots, writes
  the SST, and resets the memtable atomically under a single write-lock hold, so
  a concurrent write is always either captured in the SST or kept in the live map.
- **Emailed links (verification, password reset) now include the server port.**
  When `onboarding.base_url` was unset, links fell back to a bare
  `http://localhost` with no port. The fallback now uses the server's own
  bind `host:port`; set `onboarding.base_url` to override.
- **Bulk writes (`put_batch`/`write_batch`) no longer clone the memtable per
  entry.** The storage engine applied each entry of a batch with its own
  copy-on-write of the entire memtable `BTreeMap`, making a batch of N entries
  O(N²). Batches now apply in a single clone-mutate-swap cycle — both on the write
  path and during crash-recovery WAL replay — so bulk loads (the demo seeder,
  audit appends, migrations, imports) and reopening a large data directory scale
  linearly instead of quadratically.
- **Rust SDK Actix-web middleware adapter (HEA-1602)** — `hearth-sdk` gains an optional
  `actix-middleware` feature that provides `HearthActixMiddleware` (implements Actix-web 4's
  `Transform`/`Service` traits), the `RequirePermission` extractor (reads verified `Claims` from
  request extensions), and `HearthActixError` (implements `actix_web::ResponseError` for idiomatic
  `?`-operator error propagation). Supports all three authorization modes (`Embedded`,
  `Introspection`, `Decision`) with fail-closed semantics matching the Tower middleware.
  Enable with `hearth-sdk = { features = ["actix-middleware"] }` (HEA-1602).
- **Python SDK Django middleware adapter (HEA-1600)** — `hearth.django` provides
  `HearthDjangoMiddleware` for installation via Django's `MIDDLEWARE` setting (new-style
  `__init__(get_response)` / `__call__(request)` class interface). The middleware extracts the
  Bearer token from every request and sets `request.hearth_token` for downstream views. A global
  permission gate can be configured via `HEARTH_PERMISSION`. Also provides `@require_permission`
  as a per-view decorator supporting all three modes (`embedded`, `introspection`, `decision`).
  Django is an optional dependency: `pip install hearth-sdk[django]` (HEA-1600).
- **Node SDK Next.js adapter (HEA-1598)** — `@hearth-auth/node/nextjs` provides
  `withHearthAuth(handler, options)` for Pages Router API routes (attaches `req.hearthToken`) and
  `getHearthToken(req, config)` for App Router Route Handlers (returns `VerifiedToken | null`).
  `@hearth-auth/node/nextjs/edge` provides `hearthEdgeMiddleware(options)` — an Edge Runtime-safe
  middleware factory that uses Web Crypto (`crypto.subtle` via `jose`) instead of `node:crypto`, safe
  for Next.js `middleware.ts` running in the V8 Isolate Edge Runtime. `requirePermission(perm)` is a
  composable predicate guard compatible with both `EdgeToken` and `VerifiedToken`. Next.js is an
  optional peer dependency.
- **Kotlin SDK Spring Security adapter (HEA-1597)** — new `hearth-spring` Gradle subproject provides
  `HearthJwtAuthenticationFilter` (extends `OncePerRequestFilter`), `HearthAuthentication` (implements
  `Authentication`), `HearthSecurityAutoConfiguration` (`@AutoConfiguration`) and
  `HearthSecurityProperties` (`@ConfigurationProperties("hearth")`). Auto-configures from
  `hearth.issuer-url` with no `@Import` required. Access verified claims in controllers via
  `@AuthenticationPrincipal HearthAuthentication auth`. Roles map to `ROLE_<role>` authorities;
  permissions are granted verbatim for `hasAuthority()` guards.
- **Go SDK Echo middleware adapter (HEA-1599)** — `hearth/echo` package (`package hearthecho`) provides
  `HearthMiddleware(client, opts...)` that extracts the bearer token and stores it in the Echo context,
  `GetToken(c)` for downstream handlers, and `RequirePermission("perm")` for group-level permission
  guards via `e.Use()` or `g.Use()`. Supports `WithTokenExtractor` and `WithOnUnauthorized` customisation hooks.
  Install: `go get github.com/hearth-auth/hearth/sdks/go/hearth/echo`.
- **Go SDK Gin middleware adapter (HEA-1595)** — `hearth/gin` package (`package hearthgin`) provides
  `HearthMiddleware(client, opts...)` that extracts the bearer token and stores it in the Gin context,
  `GetToken(c)` for downstream handlers, and `RequirePermission("perm")` for group-level permission
  guards via `router.Use()`. Supports `WithTokenExtractor` and `WithOnUnauthorized` customisation hooks.
  Install: `go get github.com/hearth-auth/hearth/sdks/go/hearth/gin`.
- **Python SDK FastAPI adapter (HEA-1596)** — `hearth.fastapi` module provides `HearthFastAPIDep`
  (a `Depends()`-compatible callable that verifies a Bearer JWT and returns `VerifiedClaims`),
  `require_permission("docs.write", dep=auth)` shorthand returning `Annotated[VerifiedClaims, Depends(...)]`
  for per-route permission gating, and optional `HearthSettings` for `pydantic-settings`/env-var
  configuration (`HEARTH_BASE_URL`, `HEARTH_REALM_ID`, `HEARTH_CLIENT_ID`). Installs via
  `pip install hearth-sdk[fastapi]`.
- **Stateless `beginLogin`/`completeLogin` helpers across all 6 server SDKs (HEA-1592)** — collapses
  the ~5-step authorization-code ceremony into 2 SDK calls + 1 developer-owned session-persist line:
  `beginLogin(redirectUri, scopes?)` generates PKCE, builds the authorization URL, and returns
  `{ authorizationUrl, state, codeVerifier }` (language-idiomatic casing);
  `completeLogin(code, codeVerifier, redirectUri)` wraps `exchangeCode`. Uniform shape across
  **Node** (`OAuthFlowsClient` + `HearthClient`), **Go** (`BeginLogin`/`CompleteLogin`),
  **Rust** (`begin_login`/`complete_login`), **Python** (`begin_login`/`complete_login`),
  **PHP** (`beginLogin`/`completeLogin`), and **Kotlin** (`beginLogin`/`completeLogin`).
  The TypeScript browser SDK retains its existing stateful `createHearthAuth` facade.
- **SDK parity — residual gaps closed (HEA-1552)** — final cells in the cross-SDK capability
  matrix (`docs/specs/SDK_SURFACE.md` §7) filled:
  - **Node `refreshTokens()`** — `OAuthFlowsClient.refreshTokens(refreshToken, scope?)` and
    `HearthClient.refreshTokens()` perform the RFC 6749 §6 refresh-token grant (credentials in
    body, honors rotated `refresh_token` in the response). Closes the C-09 gap where Node could
    exchange an auth code but not refresh.
  - **TypeScript WebAuthn helpers** — `HearthApiClient` gains `startWebAuthnRegistration()`,
    `finishWebAuthnRegistration()`, `startWebAuthnAuthentication()`, and
    `finishWebAuthnAuthentication()` (C-21), with the `WebAuthn*` request/response types. The
    browser SDK is the natural home for `navigator.credentials` ceremonies.
  - **Node managed `SessionVersionCache`** — `start()`/`stop()`/`validateSv()`/`age()` background-poll
    facade plus `SessionVersionConfig`, `SessionVersionRevokedError`, and
    `SessionVersionCacheStaleError` (C-20, RFC HEA-930), bringing Node to parity with TS/Go/Kotlin
    for zero-network session-revocation checks in middleware.
  - **Magic-link send + exchange in every SDK (C-12)** — the canonical surface now requires *both*
    halves of the passwordless flow. Added the **exchange** step to the six SDKs that only had *send*:
    `exchangeMagicLink(token)` (TS browser `HearthClient`, Node `HearthClient`/`OAuthFlowsClient`,
    PHP), `ExchangeMagicLink(ctx, token)` (Go), `exchange_magic_link(token[, client_id])`
    (Python, Rust) — each posts `grant_type=urn:hearth:grant-type:magic-link` and returns the token
    response. Added the **send** step `requestMagicLink(email)` to the Kotlin SDK (which previously
    had only exchange). All 7 SDKs now expose the full send→exchange magic-link flow.
- **TypeScript SDK C2 surface** — `@hearth-auth/sdk` now exposes the full canonical SDK surface (HEA-1557):
  `verifyToken()` (full EdDSA/Ed25519 JWKS-backed local signature verification, all five spec §2 steps);
  `clientCredentials()` (RFC 6749 §4.4 M2M grant, credentials in body);
  `startDeviceFlow()` / `pollDeviceToken()` (RFC 8628, transparent `authorization_pending`,
  `slow_down` back-off, `TokenExpiredError` on expiry);
  `requestMagicLink()` (enumeration-resistant, 429 → `OAuthFlowError`).
  Admin CRUD extended with Clients, Roles, Groups, and Org member management.
  New error `OAuthFlowError` with `statusCode`/`errorCode` for token-endpoint failures.
  New type `DeviceAuthorizationResponse`. `JwksClient.verify()` uses
  `fetchKeys()` + `createLocalJWKSet` so JWKS fetches go through global `fetch`
  (mockable in tests).
- **Node SDK C3 surface** — `HearthClient` now exposes the full canonical SDK surface (HEA-1558):
  `exchangeCode()` (authorization code → tokens, PKCE verifier support);
  `clientCredentials()` (RFC 6749 §4.4 M2M token grant, credentials in body never URL);
  `startDeviceFlow()` / `pollDeviceToken()` (RFC 8628, `authorization_pending` transparent,
  `slow_down` increases interval by 5 s per occurrence, `expired_token` raises `TokenExpiredError`);
  `requestMagicLink()` (enumeration-resistant passwordless initiation, 429 → `OAuthFlowError`);
  `userinfo()` (OIDC userinfo endpoint, endpoint discovered); `mePermissions()` (`GET /v1/me/permissions`,
  live RBAC state); `svSnapshot()` / `svDelta()` (session-version feed HEA-930).
  New standalone `generatePkce()` helper (`PkcePair` with verifier/challenge/method, RFC 7636 S256).
  New error: `OAuthFlowError` with `statusCode` for OAuth endpoint HTTP errors.
  New types: `TokenResponse`, `DeviceAuthorizationResponse`, `UserInfoResponse`,
  `MePermissionsResponse`, `SvDeltaEntry`, `SvDeltaResponse`, `SvSnapshotResponse`, `ExchangeCodeOptions`.
  `OAuthFlowsClient` is exported as a standalone class for composition.
  `verifyToken()` already supported full Ed25519/EdDSA via `jose` (EdDSA in algorithm list since initial ship).
- **Rust SDK C7 surface** — `HearthClient` now exposes the full canonical SDK surface (HEA-1562):
  `verify_token()` (full Ed25519/EdDSA local signature verification via JWKS cache with TTL,
  all five spec §2 validation steps, typed `HearthError` variants per §5);
  `client_credentials()` (RFC 6749 §4.4 form-encoded, no refresh token);
  `start_device_flow()` / `poll_device_token()` (RFC 8628 with `authorization_pending`
  and `slow_down` handling); `initiate_magic_link()` (passwordless initiation);
  `session_version_snapshot()` / `session_version_delta()` (session-version polling);
  `HearthClientBuilder` (spec §1 config table: `issuer_url`, `client_id`, `client_secret`,
  `jwks_ttl`, `http_timeout`); `JwksCache` (standalone TTL cache, Cache-Control-aware,
  24h max, kid-indexed, keys never evicted). New module `hearth_sdk::pkce` exposes
  `PkcePair` + `generate_pkce_pair()` (RFC 7636 S256). `TokenResponse.refresh_token`
  is now `Option<String>` (absent on client_credentials responses). New types:
  `DeviceAuthorizationResponse`, `SvDeltaEntry`, `SvDeltaResponse`, `SvSnapshotResponse`.
  `authorize()` gains optional `code_challenge` / `code_challenge_method` PKCE parameters.
  `Claims` now implements `Debug` (redacts payload, exposes only `sub`+`iss`).
- **Go SDK C4 surface** — `Client` now exposes the full canonical SDK surface (HEA-1559):
  `VerifyToken()` (full Ed25519/EdDSA local signature verification via JWKS cache),
  `ClientCredentials()` (RFC 6749 §4.4 client credentials grant, form-encoded),
  `StartDeviceFlow()` / `PollDeviceToken()` (RFC 8628 device authorization, with
  `authorization_pending` and `slow_down` handling),
  `RequestMagicLink()` (enumeration-resistant magic-link initiation),
  `StartWebAuthnRegistration()` / `FinishWebAuthnRegistration()` /
  `StartWebAuthnAuthentication()` / `FinishWebAuthnAuthentication()` (WebAuthn passkey ceremonies).
  New types: `DeviceAuthorizationResponse`, `WebAuthnRegistrationBeginResponse`,
  `WebAuthnRegistrationCompleteRequest`, `WebAuthnRegistrationCompleteResponse`,
  `WebAuthnAuthenticationBeginResponse`, `WebAuthnAuthenticationCompleteRequest`,
  `WebAuthnAllowCredential`. New options: `WithClientCredentials()`, `WithJWKSTTL()`.
  `TokenResponse` gains a `Scope` field.
- **PHP SDK C5 surface** — `HearthClient` now exposes the full canonical SDK surface (HEA-1560):
  `generatePkce()`, `buildAuthorizeUrl()`, `refreshToken()`, `clientCredentials()`,
  `startDeviceFlow()` / `pollDeviceToken()` (with `slow_down` + `authorization_pending` handling),
  `requestMagicLink()`, `registerClient()`, `getMyPermissions()`, `checkDecision()`,
  `startWebAuthnRegistration()` / `finishWebAuthnRegistration()` / `startWebAuthnAuthentication()` / `finishWebAuthnAuthentication()`,
  `getSessionVersion()`, and `bootstrap()`. New types: `PkceChallenge`, `DeviceAuthorizationResponse`,
  `PermissionsResponse`, `ClientRegistrationResponse`, `WebAuthnOptions`, `BootstrapResponse`,
  `RateLimitException`.
- **Continuous deployment via semantic-release** — merging a `fix:` or `feat:` PR to `main`
  now automatically computes the next semver version, updates CHANGELOGs, bumps version files,
  pushes a git tag, and fires the downstream publish workflows (binaries, Helm, SDKs). Each
  package in the monorepo is independently versioned with its own tag format (`v*`, `sdk-node-v*`,
  `sdks/go/v*`, etc.). Maintenance branches (`1.x`, `2.x`) enable security backports without
  shipping from `main`. See `docs/release-runbook.md` for setup and operational procedures
  (HEA-1496).
- **PR-title Conventional Commit lint** — the `commit-lint.yml` workflow rejects non-conforming
  PR titles using `amannn/action-semantic-pull-request`; the PR title serves as the
  squash-merge commit message that semantic-release reads for its version bump calculation
  (HEA-1496).
- **Windows release binary** — `hearth-windows-amd64.exe` (`x86_64-pc-windows-msvc`) is now
  included in every tagged release alongside the Linux and macOS binaries (HEA-1494).
- **`SHA256SUMS` in release artifacts** — every tagged release includes a `SHA256SUMS` manifest
  covering all binaries and the SBOM; verify locally with `sha256sum -c SHA256SUMS` (HEA-1494).
- **Release version stamped in binary** — `hearth --version` now reports the release tag version
  (e.g. `1.2.3`) rather than the Cargo.toml placeholder `0.1.0`; set at build time via
  `HEARTH_RELEASE_VERSION` in `build.rs` (HEA-1494).
- **`@hearth-auth/sdk` npm package is now publishable** — the TypeScript browser/React SDK
  (`sdks/typescript/`) is publish-ready: `private` flag removed, `exports` and `types` fields
  point to compiled `dist/` output, and a `files: ["dist"]` constraint ensures only built
  artifacts are included in the tarball. Publish via the new `sdk-ts-v*` tag trigger (HEA-1488).
- **npm publish workflows for `@hearth-auth/node` and `@hearth-auth/sdk`** — pushing a
  `sdk-node-v*` or `sdk-ts-v*` git tag now triggers a live `npm publish --provenance` run via
  GitHub's OIDC trusted-publisher binding; PRs and branch pushes continue to run dry-run gates
  (HEA-1488).
- **Multi-arch container image published to GHCR** — release tags now build `linux/amd64` + `linux/arm64`
  images via `docker buildx` and push to `ghcr.io/hearth-auth/hearth`. Each image is tagged
  `vX.Y.Z`, `sha-<rev>`, and `latest` (non-prerelease only). The pushed digest is cosign-signed
  (keyless OIDC) and a CycloneDX SBOM attestation is attached via `cosign attest` (HEA-1481).
- **Helm chart published to GHCR as a signed OCI artifact** — release tags now package and push
  the chart to `oci://ghcr.io/hearth-auth/charts/hearth`; the pushed digest is cosign-signed
  (keyless OIDC). Install with:
  `helm pull oci://ghcr.io/hearth-auth/charts/hearth --version <tag>` (HEA-1482).
- **Go SDK PKCE support** — `hearth.GeneratePKCE()` returns a verifier/challenge pair, and
  `AuthorizeRequest` (`CodeChallenge`/`CodeChallengeMethod`) and `TokenRequest` (`CodeVerifier`)
  now carry PKCE parameters. Required to complete the authorization-code flow, which the server
  mandates for public clients (RFC 9700 §2.1.1).

### Fixed
- **`sms` now accepted as a valid `mfa_methods` value** — `hearth config validate` previously
  rejected `sms` with "unknown MFA method sms; valid methods are: totp, webauthn". Added `sms`
  to the allowlist and added a cross-validation error when `sms` appears in `mfa_methods` but
  `sms.transport` is `log` (which cannot deliver real OTPs). Also, `config validate` now checks
  `HEARTH_SMS_OTP_HMAC_KEY` for non-log transports so misconfigured deployments are caught at
  validate time rather than startup (HEA-1542).
- **Deploy assets corrected to canonical `hearth-auth` GitHub org** — `deploy/helm/hearth/values.yaml`,
  `values-prod.yaml`, `Chart.yaml`, Helm test fixtures, `deploy/docker-compose.yml`,
  `deploy/systemd/hearth.service`, and `deploy/README.md` all referenced `ghcr.io/hearth-rs/hearth`
  and `github.com/hearth-rs/hearth`; corrected to `hearth-auth`, which is the org the Docker
  publishing workflow actually pushes to (HEA-1537).
- **SDK manifest versions bumped to `1.0.0`** — `sdks/typescript/package.json` (was `0.0.1`),
  `sdks/python/pyproject.toml` (was `0.1.0`), and `sdks/rust/Cargo.toml` (was `0.2.0`) now
  reflect the `1.0.0` tags that have been released (HEA-1537).

### Security

- **`jsonwebtoken` bumped to 10.4.0 in Rust SDK (type-confusion advisory)** — `jsonwebtoken@9.3.1`
  in `sdks/rust/` was flagged by GitHub Advanced Security / Trivy for a type-confusion
  vulnerability that could enable authorization bypass on the JWT verify path. Upgraded to
  `jsonwebtoken = "10"` (resolves to 10.4.0) with the `rust_crypto` feature selected explicitly,
  as v10 decoupled crypto backends from the default feature set. The EdDSA/Ed25519 verify path
  is source-compatible; all 41 SDK unit tests remain green (HEA-1589).
- **`quinn-proto` bumped to 0.11.15 (RUSTSEC-2026-0185)** — `quinn-proto@0.11.14` carried a
  high-severity advisory (CVSS 7.5). Bumped to 0.11.15 across `Cargo.lock`, `fuzz/Cargo.lock`,
  and `sdks/rust/Cargo.lock` via `cargo update -p quinn-proto` (HEA-1510).
- **`memmap2` bumped to 0.9.11 (RUSTSEC-2026-0186)** — `memmap2@0.9.10` was flagged by an
  upstream security advisory. Hearth's storage engine uses memmap2 for SST/hot-tier reads.
  Bumped to 0.9.11 in `Cargo.lock` and `fuzz/Cargo.lock` (HEA-1510).
- **Go SDK toolchain pinned to 1.26.3** — `sdks/go/go.mod` `go` directive raised from
  `1.26.2` → `1.26.3` with an explicit `toolchain go1.26.3` line, addressing Go stdlib CVEs
  (net/mail, net/http, net/url, html/template et al.) fixed in Go 1.26.3 (HEA-1511).

### Fixed
- **Go SDK module path corrected** — `go.mod` now declares `module github.com/hearth-auth/hearth/sdks/go`,
  matching the published repository URL. The previous path (`github.com/anthropics/hearth/sdks/go`)
  caused `go get` to fail with a 404 (HEA-1479).

### Security
- **`memmap2` bumped to 0.9.11** — resolves RUSTSEC-2026-0186 (unsound pointer offset in
  `[unchecked_]advise_range()` and `flush[_async]_range()`); 0.9.11 adds bounds validation
  before the `madvise`/`msync` syscalls, eliminating the UB path (HEA-1520).

## [1.0.0] — 2026-06-21

### Security

- **Agent REST endpoints now require admin auth — BFLA remediation (HEA-1412)** — All 8 agent
  management endpoints (`GET/POST /v1/agents`, `GET/PATCH/DELETE /v1/agents/{id}`,
  `POST /v1/agents/{id}/credentials/keys`, `GET /v1/agents/{id}/credentials`,
  `DELETE /v1/agents/{id}/credentials/{cred_id}`) previously accepted unauthenticated requests.
  Every handler now calls `extract_admin_auth` + `require_admin_permission("hearth.agents.admin")`.
  A fail-closed `route_layer` guard is also applied at the router level so future handlers in this
  router return `401` by default even if per-handler auth is accidentally omitted. Regression tests
  assert `401` for all endpoints without a token (HEA-1412).
- **Agent API key entropy zeroed after use (HEA-1412)** — `create_agent_api_key` now calls
  `raw.zeroize()` on the 32-byte entropy buffer after the SHA-256 hash is computed, preventing
  key material from lingering on the stack (HEA-1412).
- **actor_token signature verified and sub-bound to client_id (HEA-1466 F3)** — RFC 8693 token
  exchange now verifies the `actor_token` Ed25519 signature against the realm key before reading
  any claims. Previously, `actor_token` was only base64-decoded without signature verification;
  a fresh forged JWT with an arbitrary `sub` claim bypassed the JTI replay guard and allowed
  impersonation of any agent in the `act` delegation chain (confused-deputy). The exchange also
  now asserts `actor_token.sub == client_id` — a token belonging to principal A cannot be used
  to impersonate principal B. Rejects with `invalid_grant` (HEA-1466).
- **AAT audience claim validated at parse time (HEA-1469 F6)** — `parse_and_validate_aat` (and
  the public `validate_aat` trait method) now accept an `expected_aud: Option<&str>` parameter.
  When supplied, the `aud` JWT claim must exactly match; otherwise `AatAudienceMismatch`
  (`HEARTH_AAT_AUDIENCE_MISMATCH`) is returned. Previously a token issued for `service-A` was
  silently accepted by `service-B`. The `/v1/aats/validate` HTTP endpoint accepts the new
  optional `expected_aud` body field (HEA-1469).
- **AAT string constraint widening blocked (HEA-1468 F5)** — `validate_tools_subset` now enforces
  equality for non-numeric constraint values (strings, booleans, nested objects). Previously a child
  AAT could set an arbitrary string for any constraint key the parent held (e.g. swapping
  `allowed_domain` from `safe.example.com` to `attacker.example.com`) without triggering
  `AatScopeEscalation`. Numeric constraints (≤ parent) are unchanged (HEA-1468).
- **Cross-realm token exchange rejection (HEA-1467 F4)** — RFC 8693 token exchange now rejects
  subject tokens whose `tid` claim does not match the serving realm, preventing identity laundering
  across realm trust boundaries. The issued token's `iss` and `tid` are always pinned to the
  serving realm's configured issuer URL and realm ID, regardless of what the subject token carried.
  Rejects with `invalid_grant` (HEA-1467).
- **DPoP JKT thumbprint blocklist (§10.4)** — operators can block a DPoP JWK thumbprint via the
  admin API (`POST /v1/dpop/block-jkt`). Blocked thumbprints are maintained in an in-memory
  projection loaded at startup and updated on each block/unblock call. Tokens whose `cnf.jkt`
  matches a blocked entry are rejected at `validate_token` time with `HEARTH_DPOP_JKT_BLOCKED`
  without any storage syscall on the hot path. New engine methods: `block_dpop_jkt`,
  `unblock_dpop_jkt`, `is_dpop_jkt_blocked`. New error variant: `DPopJktBlocked`. (HEA-1408 §10.4)
- **Hot-path JTI revocation projection (§10.5)** — sessionless token revocation now populates an
  `ArcSwap`-backed in-memory map (`revoked_jti_cache`) at startup and on each revoke call.
  `validate_token`, introspection, and `decide_permission` check this map atomically instead of
  hitting storage; each `rcu()` sweep evicts expired entries. Revocation survives restarts and is
  consistent across Raft nodes via WAL replay. (HEA-1408 §10.5)

- **SPIFFE SVID validation hardened** — `extract_spiffe_id_from_der` now uses `x509-parser` to
  extract the SPIFFE identity exclusively from the URI-type SubjectAlternativeName extension;
  a `spiffe://` string in Subject CN, Issuer, or any non-SAN field is no longer accepted as a
  valid identity. `check_cert_not_expired` validates the `notAfter` field and returns the new
  `SpiffeCertExpired` error variant (wire code `HEARTH_SPIFFE_CERT_EXPIRED`) instead of silently
  accepting expired SVIDs (HEA-1444).

- **DPoP binding enforced at resource endpoints (RFC 9449 §7.2)** — `extract_user_auth` now
  calls `enforce_dpop_binding` for tokens carrying a `cnf.jkt` claim. The DPoP proof presented
  in the `DPoP` header is validated against the token's bound key thumbprint, the `htm` HTTP
  method, and the `htu` URI (issuer + request path). A DPoP-bound access token presented as a
  plain Bearer token (no `DPoP` header) is rejected with `invalid_token`. JTI replay prevention
  applies via `check_and_record_dpop_jti`. Callers on MFA and OAuth resource endpoints
  automatically supply `method` and `uri` for `htm`/`htu` computation. (HEA-1409 M5)

- **Per-agent request rate monitor with fail-closed auto-suspend (D.6)** — Hearth now maintains
  a per-agent in-memory rolling-window rate counter (`AgentRateMonitor`). The default threshold
  is 1 000 requests per 60-second window. When an agent exceeds its threshold, `verify_agent_api_key`
  auto-suspends the agent (status → `Suspended`), emits an audit event, and returns
  `AgentRateLimitExceeded` (HTTP 429 / gRPC `RESOURCE_EXHAUSTED`, wire code
  `HEARTH_AGENT_RATE_LIMIT_EXCEEDED`). Counters reset on server restart; the threshold is not
  yet configurable via `hearth.yaml`. (HEA-1409 M5 D.6)

### Fixed

- **Transaction token double-consumption** — `consume_transaction_token` now holds the
  per-`txn_id` advisory lock across the consumed-key check and write, closing a TOCTOU
  window where two concurrent callers presenting the same token could both pass the
  `get(consumed_key)` guard before either wrote the consumed marker (HEA-1445).

### Changed

- **A-36 startup guardrail removed** — the startup check that rejected
  `agent_auth.capabilities.approval = true` without `identity = true`, and
  `agent_auth.capabilities.advanced = true` without `identity = true`, has been removed.
  All agent-auth capability phases (M1–M4) are fully implemented; the prerequisite-ordering
  enforcement is no longer needed. Operators can now enable any combination of capability
  flags without a startup error. (HEA-1409)

- **`--dev` auto-enables all agent-auth capabilities** — running `hearth serve --dev` now
  unconditionally enables `agent_auth.capabilities.{identity,approval,advanced}`, so Phase D
  routes (AATs, transaction tokens, SPIFFE, cross-realm) are available out of the box in
  development without requiring `hearth.yaml` edits. Production deployments (without `--dev`)
  are unaffected: capabilities remain `false` unless explicitly set. (HEA-1408)

- **Admin UI full pagination** — all admin list pages (users, realms, audit, groups,
  organisations, applications, sessions, roles) now display complete pagination controls:
  total record count, "Page X of Y", numbered page links, and prev/next buttons.
  Pages accept `?page=` and `?per_page=` query parameters; `per_page` is selectable from a
  dropdown (5 / 10 / 25 / 50 / 100, default 25). An active `?q=` search filter is preserved
  when changing pages or page size; changing page size always resets to page 1 (HEA-1614).

- **`?cursor=` removed from admin UI list routes (breaking, admin UI only)** — the former
  cursor-based pagination parameter is no longer accepted on any `/ui/admin/…` list URL.
  REST (`/v1/…`) and gRPC list endpoints are unaffected (HEA-1614).

### Added

- **Agent Auth end-to-end smoke example** — `examples/agent-auth-smoke/smoke.sh` demonstrates
  the full M5 surface against a live `hearth --dev` server: DPoP-bound token issuance (RFC 9449,
  Node.js native crypto), RFC 8693 token exchange with `act` chain and `on_behalf_of`, AAT
  issuance + child derivation, and transaction token lifecycle including replay prevention.
  Runs as part of `make sdk-smoke-local`. (HEA-1463)

- **Agent auth surface documented in all 7 SDK READMEs** — TypeScript and Go READMEs include
  full DPoP proof construction, RFC 8693 exchange, AAT, and transaction token code samples. Rust,
  Python, PHP, and Kotlin READMEs include language-specific idioms and cross-references.
  `docs/specs/SDK.md` gains Section 13 (agent-auth SDK contract) and a conformance checklist item.
  Draft-tracking owner: CTO (@therecluse26). (HEA-1463)

- **`agent_auth.capabilities.advanced` flag** — enables Phase D agent features: Attenuating
  Authorization Tokens (AATs), transaction tokens, cross-realm trust policies, and SPIFFE/mTLS
  workload identity. Requires `agent_auth.capabilities.identity = true`. (HEA-1425)
- **Agent-Auth M5 close-out** — all five implementation milestones complete. AGENT_AUTH.md
  banner updated to final status; end-to-end conformance tests pass for M1–M4. (HEA-1425)

- **Attenuating Authorization Tokens (AATs) — Phase D.1** — agents can request root AATs
  (signed with the realm's Ed25519 key, `typ: "aat+jwt"`) and derive child AATs that narrow
  permissions offline. Derivation enforces strict subset invariants: child scope ⊆ parent scope,
  child tools ⊆ parent tools, child constraints ≤ parent constraints, child exp ≤ parent exp.
  Revocation of any ancestor invalidates all descendants. Adversarial crafted-AAT escalation
  is rejected at the chain validation step. New engine methods: `issue_aat`, `derive_aat`,
  `validate_aat`, `revoke_aat`. (HEA-1424 Phase D.1)
- **Transaction tokens — Phase D.3** — single-use, 60-second transaction tokens bind two agents
  to a specific operation. The `txn` claim (caller-supplied UUID) is written atomically at
  issuance for replay prevention; a second issuance or consumption of the same `txn_id` returns
  `TransactionTokenReplayed`. New engine methods: `issue_transaction_token`,
  `consume_transaction_token`. (HEA-1424 Phase D.3)
- **Cross-realm trust policies — Phase D.4** — realm admins can declare explicit trust policies
  allowing agents from a source realm to present tokens to resources in the target realm,
  restricted to a declared set of capabilities. No implicit trust: a missing policy always
  returns `false`. New engine methods: `create_cross_realm_policy`, `get_cross_realm_policy`,
  `list_cross_realm_policies`, `delete_cross_realm_policy`, `check_cross_realm_policy`.
  Audit actions: `CrossRealmTrustCreated`, `CrossRealmTrustRevoked`. (HEA-1424 Phase D.4)
- **SPIFFE / workload identity — Phase D.7** — agents can be registered with a SPIFFE ID
  (`spiffe://{trust_domain}/agent/{uuid}`) for mTLS workload authentication. The TLS
  termination layer maps the SVID's URI SAN to an `AgentId` via the SPIFFE mapping registry.
  Invalid SPIFFE ID format and duplicate mappings are rejected. New engine methods:
  `register_spiffe_mapping`, `lookup_agent_by_spiffe_id`, `delete_spiffe_mapping`,
  `validate_spiffe_svid`. Audit actions: `SpiffeIdMapped`, `SpiffeAuthSuccess`. (HEA-1424 Phase D.7)
- **Phase D proto backfill** — `AuditAction` proto enum gains 6 Phase D variants
  (110–115: `AatIssued`, `AatRevoked`, `TransactionTokenIssued`, `CrossRealmTokenIssued`,
  `SpiffeIdMapped`, `SpiffeAuthSuccess`). (HEA-1424)
- **Phase D HTTP REST API** — `POST /v1/aats`, `POST /v1/aats/derive`, `POST /v1/aats/validate`,
  `DELETE /v1/aats/{jti}`, `POST /v1/transaction-tokens`, `POST /v1/transaction-tokens/consume`,
  `POST /v1/spiffe-mappings`, `GET|DELETE /v1/spiffe-mappings/{agent_id}`,
  `POST|GET /v1/cross-realm-policies`, `GET|DELETE /v1/cross-realm-policies/{id}`.
  All gated by `agent_auth.capabilities.advanced = true`. (HEA-1408)
- **Prometheus metrics for agent operations** — five new counters:
  `hearth_agent_delegation_total` (realm, outcome), `hearth_agent_approval_total` (realm, transition),
  `hearth_agent_aat_issued_total` (realm, kind), `hearth_agent_aat_revoked_total` (realm),
  `hearth_agent_txn_token_total` (realm, op). (HEA-1408)
- **AAT fuzz target** — `fuzz/fuzz_targets/aat_parse.rs` exercises `decode_claims_unverified`
  and `verify_token_signature` on arbitrary byte sequences covering AAT, agentic-JWT, and
  actor-token parsing paths. (HEA-1408)
- **`AuditQuery` agent/chain/tool filters (§12.4 MUST)** — `AuditQuery` gains `agent_id` and
  `tool` optional fields that match against `metadata.agent_id` and `metadata.tool` in the
  stored event JSON, enabling per-agent and per-tool audit query scoping. (HEA-1408)

### Fixed

- **RFC 8693 actor scope: absent claim treated as unconstrained** — an actor token with no
  `scope` claim (field absent) no longer produces `EmptyScopeIntersection`; only an explicit
  `"scope": ""` (zero permissions) is rejected. Actors that omit the claim are treated as not
  imposing an additional scope ceiling beyond the subject token. (HEA-1424)

### Security

- **RFC 8693 actor scope enforcement** — token exchange now enforces RFC 8693 §4.4:
  `effective_scope ⊆ actor_scope ∩ subject_scope`. Previously, `actor_scope` defaulted to
  `subject_scope`, allowing a zero-permission actor to obtain the subject's full privilege set
  via a delegated token. The actor's scope ceiling is now taken from the `scope` claim in the
  actor's JWT; actors with no scope claim or empty scope produce an `EmptyScopeIntersection`
  rejection. (HEA-1429 / HEA-1427 F-2)

### Added

- **Tool-level permission grammar (agent-auth Phase C)** — RBAC roles can now include
  `tool.{name}.invoke`, `tool.{name}.invoke_with_approval`, and `tool.{name}.deny` permission
  strings to govern per-tool agent access. Tool groups are supported via `toolgroup.{group}.{action}`
  permissions, with group-to-tool membership declared in realm config. **Deny wins:** a `deny`
  permission always overrides any co-present `invoke` grant. Scope intersection at delegation
  narrows the effective scope to the triple intersection of user-granted, agent-permitted, and
  requested scopes. (HEA-1423)
- **Human-in-the-loop approval request lifecycle (agent-auth Phase C)** — agents holding
  `tool.{name}.invoke_with_approval` can submit approval requests via the identity engine.
  Approvers transition requests from `Pending → Approved` (issuing a time-boxed capability
  token scoped to the approved tool, default TTL 5 min, max 1 h) or `Pending → Denied`.
  Transitions from non-`Pending` states are rejected. Requests expire after a configurable
  window (default 1 hour); expired requests are treated as denied. (HEA-1423)
- **Approval webhook notifications (agent-auth Phase C.5)** — realms can configure
  `approval_webhook.url` (plus optional `secret` and `timeout_ms`) to receive durable
  at-least-once HTTP POST notifications when an approval request is created. The payload
  carries `request_id`, `agent_id`, `tool`, `delegation_chain`, `approve_url`, and `deny_url`.
  Delivery is HMAC-SHA256 signed when a secret is configured (same `X-Hearth-Signature-256`
  convention as the audit webhook engine). The outbox record is written to WAL atomically with
  the approval record, guaranteeing delivery survives server crashes. (HEA-1407)
- **Approval REST API (agent-auth Phase C)** — `POST /v1/approval-requests`,
  `GET /v1/approval-requests`, `GET /v1/approval-requests/{id}`,
  `POST /v1/approval-requests/{id}/approve`, `POST /v1/approval-requests/{id}/deny`.
  Gated by `agent_auth.capabilities.approval = true`. (HEA-1407)
- **`agent_auth.capabilities.approval` flag** — enables Phase C approval routes and webhook
  delivery. Requires `agent_auth.capabilities.identity = true`. (HEA-1407)

- **Consent UI: agent delegation view/revoke** — users can list and revoke active RFC 8693
  agent delegations at `GET /ui/consent/delegations`. Revoking immediately invalidates the
  bound access token via the JTI blocklist. Delegation grants are persisted on every
  successful token exchange and indexed by user subject. (HEA-1418)
- **gRPC `AuditAction` enum fully synced** — the proto enum now covers all 109 domain variants
  (previously 59 variants mapped to `UNSPECIFIED`, losing information on the wire). Includes
  RBAC group events, login/lockout events, backup/export watermarking, required-action lifecycle,
  SMS MFA, adaptive step-up, device fingerprints, email-change, agent lifecycle, and M2
  delegation/MCP events (`AgentDelegation` through `ProtectedResourceDeleted`). Go and TypeScript
  SDK types regenerated; reverse mapping (`proto → domain`) added for gRPC filter queries. (HEA-1417)
- **RFC 8693 token exchange** (`urn:ietf:params:oauth:grant-type:token-exchange`) — agents
  can exchange a user's access token for a delegated token via `POST /token` with the new
  grant type. Resulting tokens carry an `act` (actor) claim per RFC 8693 §4.1. The exchange
  enforces scope intersection (`subject ∩ actor_permitted ∩ requested`), lifetime ≤ subject
  remaining, per-agent `max_delegation_depth` cap, and actor-token JTI replay prevention
  (5-minute window, persisted). (HEA-1406)
- **Protected resource registration** — realms can register MCP tool servers as protected
  resources via `POST /v1/resource-servers`. Resources have a canonical `resource_uri`, scope
  list, and required-claims list. URI uniqueness is enforced per realm. (HEA-1406)
- **Protected Resource Metadata endpoint** (RFC 9728) — `GET /.well-known/oauth-protected-resource`
  returns Hearth's PRM document advertising itself as an OAuth AS, its JWKS URI, and supported
  MCP scopes. (HEA-1406)
- **MCP scope strings** (§2.6) — Hearth accepts and validates `{namespace}:{category}:{action}`
  scope format. Standard scopes: `mcp:tools:invoke`, `mcp:tools:list`, `mcp:resources:read`,
  `mcp:resources:write`, `mcp:prompts:read`. (HEA-1406)
- **`act` chain on `TokenClaims`** — all issued JWTs now include an optional `act` field
  (RFC 8693 §4.1) encoding the full delegation chain. Existing non-delegated tokens omit it
  (`skip_serializing_if = None`). (HEA-1406)
- **`ResourceServerId` newtype** (prefix `rs_`) added to `hearth::core`. (HEA-1406)
- **Delegation audit actions** — `AuditAction` extended with `AgentDelegation`,
  `AgentToolInvocation`, `ApprovalRequested`, `ApprovalGranted`, `ApprovalDenied`,
  `AgentTokenRevoked`, `CrossRealmTrustCreated`, `CrossRealmTrustRevoked`,
  `ProtectedResourceRegistered`, `ProtectedResourceUpdated`, `ProtectedResourceDeleted`. (HEA-1406)
- **Actor JTI cleanup sweeper** — `sweep_actor_jtis` evicts expired actor-token JTI entries
  during the periodic cleanup sweep. (HEA-1406)

### Changed

- **`MAX_ACT_CHAIN_DEPTH` raised 3 → 10** (A-38 global ceiling, `src/abuse/mod.rs`). The
  per-agent `max_delegation_depth` field (1–10) gates individual agents; the global constant
  is the hard ceiling when validating inbound tokens from external parties. (HEA-1406)
- **`resource_indicators_supported` set to `true`** in both the test `OidcDiscoveryDocument`
  default and the live discovery document. RFC 8707 `resource` parameter support was already
  implemented; the discovery field now reflects reality. (HEA-1406)
- **`grant_types_supported`** in the OIDC discovery document now includes
  `urn:ietf:params:oauth:grant-type:token-exchange`. (HEA-1406)

### Security

- **Agent endpoint authentication (HEA-1414)** — all 9 `/v1/agents` HTTP handlers
  now require a valid Bearer token with `hearth.admin` permission; unauthenticated
  requests return `401 Unauthorized`. Cross-realm BOLA is blocked at the
  token-validation layer (per-realm Ed25519 signing keys).
- **DPoP `ath` claim validation (HEA-1414)** — `validate_dpop_proof` now accepts
  an `access_token` parameter; when provided, the proof's `ath` claim is required
  and validated with constant-time comparison (`subtle::ConstantTimeEq`).
- **Capability string bounds (HEA-1414)** — `create_agent` and `update_agent`
  reject requests with more than 50 capability URIs or any URI exceeding 256
  characters.
- **Agent credential quota (HEA-1414)** — `create_agent_api_key` enforces a
  per-agent cap of 25 active (non-revoked) credentials; further attempts return
  `QuotaExceeded { resource: "agent_credentials" }`.
- **Audit actor attribution (HEA-1414)** — all 8 agent-mutating engine methods now
  accept `caller: Option<&UserId>`; HTTP and gRPC handlers pass the authenticated
  user so audit events record who performed the action.
- **Credential audit events (HEA-1416)** — `create_agent_api_key` and
  `revoke_agent_credential` now emit `AgentCredentialCreated` / `AgentCredentialRevoked`
  audit events with the caller's `UserId` as actor; previously these two operations
  emitted no audit event and the `_caller` parameter was unused.

### Added

- **DPoP storage infrastructure (HEA-1410)** — lays the persistence foundation for M2
  DPoP-bound agent tokens:
  - Per-realm DPoP nonce HMAC secret generated once and persisted under
    `agt:dpop:nonce-secret`; reloaded on restart so nonces survive server restarts.
    Previously a global ephemeral key caused all nonces to expire on every restart.
  - DPoP proof JTI replay cache persisted to storage under `agt:dpop:jti:{jti}` with
    8-byte little-endian i64 TTL expiry; survives restarts and is consistent across
    Raft nodes. Previously an in-memory `HashMap` was bypassed on restart.
  - Background cleanup sweeper extended to evict expired `agt:dpop:jti:*` entries
    on every tick (same pattern as JAR JTI and fingerprint sweepers).
  - New `IdentityEngine` methods: `check_and_record_dpop_jti` and
    `get_realm_dpop_nonce_secret`.

- **Agent identity (M1, HEA-1405)** — Phase A of `AGENT_AUTH.md` is now reachable:
  - `POST /v1/agents` — register an agent; owner (user or organization) FK-checked;
    realm `max_agents` quota enforced when configured.
  - `GET /v1/agents`, `GET /v1/agents/{id}`, `PATCH /v1/agents/{id}`,
    `DELETE /v1/agents/{id}` — full CRUD with credential cascade on delete.
  - `POST /v1/agents/{id}/credentials/keys` — issue a 256-bit API key (show-once;
    SHA-256 hash stored, plaintext never persisted); constant-time verification.
  - `GET /v1/agents/{id}/credentials` — list credentials (active and revoked).
  - `DELETE /v1/agents/{id}/credentials/{cred_id}` — revoke a credential.
  - `GET /.well-known/agent.json?agent_id={id}` — Agent Card per A2A protocol.
  - All routes absent from the router unless `agent_auth.capabilities.identity: true`.

- **`agent_auth.capabilities.identity` config flag** — replaces the old A-36 binary
  guardrail (`agent_auth.enabled`). Setting `capabilities.identity: true` activates M1
  agent routes. Future phases add their own capability flags.

- **`RealmQuotaConfig.max_agents`** — per-realm limit on registered agents;
  mirrors `max_clients` / `max_users`.

- **`GET /admin/users/{id}/sessions`** — lists active (non-revoked) sessions for a user.
  Returns a paginated `{"items": [...], "next_cursor": "..."}` response with session ID,
  timestamps, IP address, and device label. Requires `hearth.users.admin`.

- **`DELETE /admin/sessions/{id}`** — hard-revokes a session by ID, marking the session
  record as revoked and cascading to any grant families issued under it. Returns `204 No
  Content`. The existing `sv-bump` endpoint performs a soft-invalidate; this endpoint is a
  full termination. Emits a `session_revoked` audit event with `via: "admin_api"`. Requires
  `hearth.users.admin`.

### Security

- **CSRF check on device-approval form (F5, HEA-1367)** — `POST /ui/device` now verifies
  the `csrf_token` field against the session's CSRF cookie before calling `approve_device`.
  The field was already present in the form but silently discarded; a missing or mismatched
  token now returns 403, preventing an attacker from CSRFing a logged-in victim into
  approving the attacker's device.

- **CSRF fail-closed on login/register/MFA challenge (F6, HEA-1367)** — pre-auth form
  handlers (`/ui/login`, `/ui/register`, `/ui/mfa-challenge`) now require the
  `hearth_ui_csrf` cookie to be **present** in production mode (`dev_mode = false`); a
  missing cookie returns 422 "Invalid security token" instead of bypassing the check. The
  bypass is preserved under `--dev` for direct-POST tooling.

- **CSRF protection added to `/ui/register` form (HEA-1367)** — the registration form
  now issues and embeds a `hearth_ui_csrf` double-submit token (previously missing
  entirely); `POST /ui/register` verifies it against the cookie.

- **Backup archives now encrypt all sections; DEK wrapping is mandatory (HEA-1366)** — previously
  only `signing_key.json` was AES-256-GCM encrypted; credentials and all other sections were
  plaintext NDJSON with the DEK optionally stored as plain base64. Now all sections are encrypted
  under a single DEK that is always Argon2id-wrapped before persisting to the manifest
  (`wrapped_dek_b64` + `dek_wrapping_params`). The `hearth backup create` CLI requires `--encrypt`
  or `HEARTH_MASTER_KEY`; the HTTP export endpoint requires `HEARTH_MASTER_KEY`. Archive format
  version bumped to 2.

- **CSRF protection on TOTP/MFA challenge forms** — the inline TOTP form in
  `login.html` and the standalone `mfa_challenge.html` form now include a
  `_csrf` hidden field and the submit handler verifies it against the
  `hearth_ui_csrf` cookie, closing a CSRF gap on `/ui/mfa-challenge` (HEA-1348).

### Fixed

- **TOTP input placeholder** — corrected `placeholder="000 000"` →
  `placeholder="000000"` in the login and MFA-challenge forms; the space was
  causing pattern-validation failures on mobile keyboards with
  `inputmode="numeric"` and `pattern="[0-9]{6}"` (HEA-1348).

- **Eliminated `ring 0.16.20` (CVE-2025-4432, MEDIUM) and `rustls-webpki 0.101.7`
  (GHSA-82j2-j2ch-gfr8, HIGH)** — upgraded `ldap3` from 0.11 to 0.12.
  The new release uses `ring 0.17` and `rustls 0.23`, removing the only transitive
  paths to both vulnerable packages. The `tls-rustls-ring` feature flag was adopted
  to satisfy ldap3 0.12's mandatory Rustls crypto-provider selection (HEA-1344).

### Added

- **Email OTP MFA factor** — `email_otp` is now a distinct, configurable MFA method.
  Users can enroll via the `ENROLL_EMAIL_OTP` required-action flow, which sends a
  6-digit CSPRNG code to their registered email address (via the existing `EmailService`).
  Enrollment sets `email_otp_enabled` on the user record. Per-realm expiry and maximum
  attempt count are configurable via `email_otp_expiry_seconds` / `email_otp_max_attempts`
  in realm config; defaults match the SMS OTP module (10-minute TTL, 5 attempts). The
  `mfa_methods: ["email_otp"]` realm setting auto-injects the enrollment required action
  for users who have not yet enrolled (HEA-1329).

- **Conditional MFA enforcement** — `mfa_required: true` on a client registration
  forces users accessing that client to enroll an MFA factor (TOTP or passkey)
  before an authorization code is issued. `mfa_required_roles: [...]` on realm config
  enforces MFA for users assigned any of the named roles, regardless of which client
  they are authenticating against. Both gates inject the `EnrollMfa` required action
  which redirects to a dedicated enrollment page (`/required-action/enroll-mfa`) within
  the existing required-action flow (HEA-1330).

- **Granular admin sub-permissions** — `hearth.admin` is now complemented by three
  fine-grained sub-permissions that enable Keycloak-style sub-admin delegation without
  granting full superuser access (HEA-1328):
  - `hearth.users.admin` — user CRUD, sessions, credentials, consents, effective-permissions
  - `hearth.clients.admin` — OAuth client/application registration and management
  - `hearth.realm.admin` — realm settings, roles, groups, assignments, webhooks, audit logs

  Three matching seed roles (`hearth.users.admin`, `hearth.clients.admin`,
  `hearth.realm.admin`) are now seeded alongside `realm.admin` on every new realm,
  ready to assign to service accounts or restricted operators. The `realm.admin` role
  is unchanged and still carries all three sub-permissions plus `hearth.admin`.
  The `hearth.admin` permission continues to grant unrestricted access to all admin
  endpoints. Existing integrations require no changes.

- **`hearth migrate auth0` command** — imports an Auth0 Management API export bundle
  (`hearth migrate auth0 --file export.json --data-dir /var/lib/hearth`). The operator
  assembles the bundle from Auth0's Management API (users, clients, organizations, roles)
  using the reference bundler at `examples/auth0-migration-bundler/`. Supported credential
  formats: bcrypt (`$2a$`/`$2b$`/`$2y$`), Argon2, PBKDF2-SHA256, PHC-scrypt.
  Unsupported algorithms (MD5, SHA-1) surface a per-user warning and import the user
  without a credential. `--dry-run` validates without writing. `--realm <uuid>` pins
  the destination realm ID (HEA-1327).

- **Apple Sign In connector** (`type: apple`) — native Sign In with Apple support
  via `private_key_jwt` client authentication (ES256-signed per-request JWT),
  `response_mode=form_post` callback handling, and first-login-only name extraction
  from the `user` form field. Cannot be covered by the generic OIDC connector.
  Configure via `realms.<name>.federation` with `type: apple`, `team_id`, `key_id`,
  and `private_key_pem` (HEA-1326).

- **Pre-token enrichment webhook** (`realms.<name>.pre_token_webhook`) — before
  issuing an access token, Hearth POSTs a JSON context payload (user ID, client
  ID, grant type, scope, resolved roles/groups/permissions) to a configured URL.
  The endpoint may return `extra_claims` that are merged into the token's
  top-level claims. Reserved JWT claims (`sub`, `iss`, `exp`, etc.) cannot be
  overridden. Supports `on_error: fail_open` (default — token issued without
  extra claims on failure) or `fail_closed` (token rejected). Optional
  `hmac_secret` for `X-Hearth-Signature-256` request signing. Covers Gap C-3
  from the 1.0 Readiness Audit — minimal Auth0 "Actions" / Keycloak protocol
  mapper escape hatch (HEA-1324).

- **F10–F17 batched auth/crypto/logging hardening (HEA-1371)**

  - **F10 Magic-link and password-reset tokens are now single-use under concurrent requests** — a per-token mutex eliminates the TOCTOU race between the `get` (reads `used=false`) and `put` (writes `used=true`), matching the existing `jti_locks` pattern.
  - **F11 TOTP code comparison now constant-time** — `validate_totp` switched from `==` to `subtle::ConstantTimeEq` to eliminate timing side-channels during HMAC-TOTP verification.
  - **F12 Hardcoded dev OTP HMAC fallback key removed** — the literal `hearth-dev-sms-otp-key-not-for-production` string was replaced with a zeroed 32-byte key in dev/log mode. Startup now also validates that any provided `HEARTH_SMS_OTP_HMAC_KEY` is ≥ 32 bytes.
  - **F13 `Secure` cookie attribute added to three flow cookies** — `hearth_fed_bind`, `hearth_ui_fed_confirm`, and `hearth_ui_oauth_ticket` now include `; Secure` when the request is served over HTTPS (determined via `is_secure_request`).
  - **F14 gRPC consent handlers no longer leak internal error text** — `revoke_consent` and `list_consents_by_user` now route errors through `identity_to_status` (opaque error-id mapper) instead of forwarding `e.to_string()` to the caller.
  - **F15 Browser-login timing parity for nonexistent users** — when `get_user_by_email` returns `None`, the handler now runs a dummy Argon2id hash via `dummy_verify_password` before returning, making the response timing indistinguishable from a real user with the wrong password.
  - **F16 Setup token and mailcatcher password now gated on `dev_mode`** — the startup panel previously printed these to stdout whenever `log_format != json`; they are now redacted in production mode.
  - **F17 Unsafe mmap (`OfflineBreachCorpus`) relocated from identity to storage layer** — moved `src/identity/breach_corpus.rs` → `src/storage/breach_corpus.rs`, bringing it into the layer where `unsafe` I/O is permitted.

- **Auto-generated master key now written `0o600`; production refuses auto-gen
  (HEA-1368)** — when `HEARTH_MASTER_KEY` is unset, the auto-generated
  `hearth.host_key` file was previously created via `std::fs::write` honoring
  the process umask (commonly `0o644`), making the key world-readable. The file
  is now created with mode `0o600` via `OpenOptions` + `create_new`. Startup
  also emits a `WARN` when auto-generating in dev mode and fails closed in
  production, requiring `HEARTH_MASTER_KEY` to be set explicitly.

- **JSON parse-bomb guard now active on all JSON routes (HEA-1369)** —
  `POST`/`PUT`/`PATCH` requests with `Content-Type: application/json` are now
  validated for nesting depth (≤ 128 levels) and array length (< 65 536 items)
  before reaching any handler. Requests exceeding either limit are rejected with
  HTTP 400. The guard logic already existed in `src/abuse/guards.rs` but had no
  callers; it is now wired as a global axum route middleware. `Content-Encoding:
  gzip` decompression (A-22) remains N/A — Hearth does not install an inbound
  decompressor.

- **Parser/validation fail-closed hardening (HEA-1372)** — three low-severity
  findings from the HEA-1363 audit closed:
  - **F18 WAL batch decode allocation now capped** — `decode_batch_payload` now
    bounds `Vec::with_capacity` to `min(count, remaining_bytes / 9)` before
    the sub-entry loop, preventing a corrupted `count` field from triggering an
    unbounded allocation. Reachable only after AES-GCM authentication, so no
    remote exploit path existed.
  - **F19a SAML `DocType` uniformly rejected** — `parse_response`,
    `parse_authn_request`, `parse_idp_metadata`, `parse_logout_request`, and
    `parse_logout_response` now explicitly return an error on `Event::DocType`,
    matching the existing reject in `xml.rs` and `c14n.rs`.
  - **F19b Email addresses containing `:` are now rejected** — `validate_email`
    rejects any address containing the storage key delimiter `:`; the impact is
    negligible (`:` is not a valid RFC 5321 local-part character) but closes a
    theoretical key-injection avenue in realm-scoped key lookups.

- **Dependency-hygiene triage: SDK and CI lockfile updates (HEA-1389)** —
  full audit of all shipped SDK and CI lockfiles; real vulnerabilities fixed,
  dev-only findings justified-accepted with documented rationale:
  - **`sdks/node`**: bumped `vitest@3.2.4 → 3.2.6` (GHSA-5xrq-8626-4rwp, critical
    arbitrary file exec), `vite@7.3.3 → 7.3.5` (GHSA-fx2h-pf6j-xcff high path
    bypass + GHSA-v6wh-96g9-6wx3 NTLM hash disclosure). Residual: `esbuild@0.27.7`
    (low, Windows-only dev server, constrained by vite peer-dep) — justified-accept
    added to `osv-scanner.toml`.
  - **`sdks/typescript`**: bumped `vitest`, `vite`, and `form-data` (GHSA-hmw2-7cc7-3qxx
    CRLF injection) to patched versions — now clean.
  - **`sdks/php`**: bumped `guzzlehttp/guzzle 7.10.5 → 7.12.1`
    (CVE-2026-55767 cookie domain confusion, CVE-2026-55568 silent HTTPS
    proxy downgrade), `guzzlehttp/psr7 2.10.3 → 2.12.1` (CVE-2026-55766
    CRLF injection), `orchestra/testbench v9 → v10`,
    `laravel/framework v11.54 → v12.62.0` (CVE-2026-48019 CRLF injection in
    email rule, GHSA-crmm-hgp2-wgrp Signed URL confusion),
    `phpunit v10.5 → v11.5`. All 77 SDK tests pass.
  - **`examples/grpc-admin-flow`**: bumped `@grpc/grpc-js → 1.14.4`
    (GHSA-5375-pq7m-f5r2, GHSA-99f4-grh7-6pcq: malformed request crash) and
    `protobufjs` (GHSA-wcpc-wj8m-hjx6 DoS). Examples are excluded from
    osv-scanner scope; fixed as good hygiene.
  - **CI**: replaced unpinned `pip3 install pyyaml` with
    `apt-get install python3-yaml` to eliminate the Scorecard
    pinned-dependencies finding.

- **Upgraded `maxminddb` to 0.27.3 (RUSTSEC-2025-0132)** — `maxminddb` 0.24
  contained a soundness bug where `Reader::open_mmap` unsoundly treated a
  `memmap2` operation as safe, enabling potential undefined behaviour if the
  backing file was modified after being mapped. Hearth never called
  `open_mmap` (only `open_readfile`), so no exploit path existed; the
  upgrade closes the advisory and removes the suppression in `deny.toml`.
  A `cargo audit --deny warnings` gate has been added to the CI quality
  job to catch future RustSec advisories at PR time (HEA-1370).

### Fixed

- **Realm OIDC discovery now includes `end_session_endpoint`** — the realm-scoped
  `/.well-known/openid-configuration` handler was serializing through the protobuf
  path which lacks the field, so SPA clients never saw the logout endpoint and
  fell back to a no-op URL leaving the Hearth session alive (HEA-1294).

- **`delete_realm` now purges `email:reserved:` tombstones** — the 90-day
  A-20 email-reservation records (plaintext email addresses) were previously
  absent from both the sync and background cascade prefix lists, leaving them
  as residual PII after realm deletion.  `dfp:user:` (device fingerprint
  HMAC hashes) and `slug:org:` (org-slug cooldown tombstones) are also now
  included in the unconditional idempotency sweep.  The `estimate_cascade_count`
  array is updated in step to prevent background/sync path skew (HEA-1270).

### Changed

- **Identity-provider admin pages are now read-only when managed via `hearth.yaml`** — when a
  federation connector is declared under `federation.<name>` in `hearth.yaml`, the admin UI
  identity-provider detail and list pages suppress edit controls; management is exclusively via
  config file + reconciler restart. This matches the existing behavior for YAML-managed
  OAuth applications and prevents config drift between the UI and `hearth.yaml`.

### Added

- **Full-stack demo Phase 4 — integration, smoke test & docs polish**
  (`examples/full-stack-demo/`) — wires Phase 2 (React/PKCE frontend) and Phase 3
  (Go + Gin backend) together into a runnable end-to-end demo. Includes: inline
  security-rationale comments in `pkce.ts` and `backend/middleware/auth.go`,
  README final pass (prerequisites table, production deployment callout comparing
  this demo's Bearer-token approach to the recommended HttpOnly-cookie BFF pattern,
  curl-based role-enforcement verification examples, token-refresh walkthrough),
  and `examples/full-stack-demo/backend` wired into `make sdk-smoke-local` CI
  smoke suite (HEA-1276).

- **Full-stack demo Phase 3 — Go + Gin backend** (`examples/full-stack-demo/backend/`) — runnable Go API
  server demonstrating `hearth-go` SDK integration: JWKS auto-discovery with key-rotation re-fetch,
  `RequirePermission` / `RequireRole` Gin middleware, notes CRUD with per-route `content.*` enforcement,
  admin user list via `client.Admin(token).ListUsers()`, thread-safe in-memory store, explicit-origin
  CORS, and table-driven handler tests (HEA-1275).

- **Third-party license attribution** — `THIRD_PARTY_LICENSES` now contains full
  license texts for all transitive crates compiled into Hearth, generated by
  `cargo-about`. `NOTICE` is updated with first-party copyright and cryptographic
  dependency provenance (ring/aws-lc-rs/rustls). `make notice` regenerates both
  files on dependency updates; `make notice-check` (wired into CI) fails if
  `THIRD_PARTY_LICENSES` is stale relative to `Cargo.lock` (HEA-1268).

- **Full-stack demo scaffold** — `examples/full-stack-demo/` provides Phase 1 core infrastructure:
  `hearth.yaml` with a `demo` realm + `hearth-hub` PKCE public client, `demo.sh` bootstrap/start
  script (idempotent, seeds viewer/editor/admin users), and `frontend/` + `backend/` placeholder
  directories for Phase 2/3 scaffolding (HEA-1273).

- **Migration runnable examples** — `examples/keycloak-migration/` and `examples/auth0-migration/` provide
  self-contained end-to-end examples (sample fixture → `hearth migrate` → `hearth serve --dev` → verify).
  A **Migration provider checklist** in `examples/README.md` codifies the requirement for every future
  importer (HEA-1179).

- **P-1 Cloudflare Turnstile CAPTCHA adapter** — new `TurnstileCaptchaProvider` in
  `src/abuse/captcha/` implements the `CaptchaProvider` trait with Cloudflare's
  siteverify API.  Widget HTML is injected at the `<!-- captcha-widget-slot -->`
  marker in the register and forgot-password UI forms.  Server-side verification
  runs via `spawn_blocking`.  Fail-open on transport errors per §6.1.  Configure
  via `security.captcha.provider: turnstile` in `hearth.yaml`; defaults to
  `NoopCaptchaProvider` (no CAPTCHA shown) when absent (HEA-1202).
- **A-30 Backup/export hardening** — export operations now require a separate
  `hearth.export` permission in addition to `hearth.admin` (granted to the
  `realm.admin` role by default). A per-user rate limit of 10 exports per hour
  caps blast radius from a compromised credential. Every backup, user-export, and
  audit-export call emits a `RealmExportWatermarked` audit event with a unique
  `export_id` UUID, `export_type`, and actor (HEA-1206).

- **A-30 Restore archive signature verification** — `BackupManifest` gains a
  `detached_signature_b64` field (base64url Ed25519). When
  `security.backup.verify_key` is configured (raw Ed25519 public key, base64url),
  the restore handler verifies the detached signature over `canonical_bytes()`
  before importing any data. Fail-closed: archives without a valid signature are
  rejected with `400 missing_manifest_signature` (HEA-1206).

- **A-5 Reserved realm/org slug names** — `security.reserved_slugs` in `hearth.yaml`
  lets operators declare a list of names that cannot be used as realm names or
  organization slugs (e.g. `["support", "www", "mail"]`).  Built-in URL-routing
  keywords remain reserved as before (HEA-1212).

- **A-5 Post-delete slug cooldown** — when a realm or organization is deleted its name
  enters a 30-day cooldown window.  Attempts to create a new realm or org with the
  same name during the window are rejected with `HEARTH_SLUG_IN_COOLDOWN` (HEA-1212).

- **A-6 Bootstrap endpoint production guard** — `POST /admin/bootstrap` is now absent
  from the route table in production by default (the route is not registered, preventing
  fingerprinting).  Pass `--allow-bootstrap-in-prod` to enable it for initial
  provisioning of a fresh deployment; a startup warning is emitted (HEA-1212).

- **A-10 Per-IP JWKS / OIDC discovery rate cap** — JWKS and OpenID discovery endpoints
  are now capped at 60 requests per second per source IP (`JwksRateLimiter`).  Exceeding
  the limit returns `429 Too Many Requests` (HEA-1212).  Dev mode (`--dev`) disables the
  cap so local SDK smoke tests and CLI integration tests do not race the limiter.

### Fixed

- **`$2y$` bcrypt prefix now verifies correctly** — `verify_hash` previously only dispatched
  `$2a$`/`$2b$` prefixes to `bcrypt::verify`; `$2y$` hashes (produced by PHP-backed tenants and
  accepted by the Auth0 migration importer) fell through to `PasswordHash::new`, which cannot
  parse the non-PHC bcrypt format and returned an `unsupported algorithm` error on every login
  attempt. Users migrated from Auth0 with `$2y$` hashes can now authenticate (HEA-1225).

- **A-33 `update_realm` vs delete cascade race** — `delete_realm` releases the realm
  ops lock after stamping `DeletingInProgress` so the (potentially long) cascade does
  not block other realms.  Without a status check on `update_realm`, a concurrent
  rename could re-put the realm record between the cascade's record-delete and
  signing-key-delete, leaving `record=Some / key=None`.  `update_realm` now refuses
  updates against a realm whose cascade has started.

- **A-13 WebAuthn attestation policy** — per-realm configuration (`realms.<name>.auth.webauthn_attestation`)
  controls: `allow_none` (whether the `"none"` attestation format is accepted),
  `aaguid_allowlist` (allowlist of authenticator AAGUIDs in UUID format), and
  `require_prf` / `require_large_blob` flags.  Absent = fail-open (HEA-1212).

- **A-14 Per-realm TTL hard caps** — `to_realm_config` rejects realm configs where
  `auth.token.password_reset_token_ttl` exceeds 1 hour or `auth.token.magic_link_ttl`
  exceeds 30 minutes unless `auth.token.allow_unsafe_ttl: true` is also set.  Operators
  accept the wider token-theft window by explicitly setting the flag (HEA-1212).

- **P-8 Pluggable `SecretsBackend` trait** — `src/abuse/secrets_backend/` provides
  a `dyn SecretsBackend` abstraction for signing keys (PKCS#8 DER), encryption-at-rest
  keys (32 bytes), and Argon2 pepper (32 bytes). Adapters: `StorageSecretsBackend`
  (default, today's WAL storage layout), `FileSecretsBackend` (reads from a
  directory), and stubs `KmsSecretsBackend` / `HsmSecretsBackend` for future
  HSM/KMS integration (HEA-1206).

- **`hearth.export` permission** — seeded in all realms and included in the
  `realm.admin` role. Service accounts can be granted `hearth.export` without
  full `hearth.admin` for dedicated DR pipelines (HEA-1206).

- **A-31 Per-realm JWT leeway (federation)** — `federation.<idp>.leeway_seconds`
  replaces the hardcoded 60-second clock-skew allowance on OIDC ID-token `exp` and
  `nbf` checks. Defaults to 60 s; capped at 300 s. Raises are only necessary for
  enterprise IdPs with known clock drift (HEA-1213).

- **A-32 `trusted_proxies` startup validator** — Hearth now refuses to start when
  `server.trusted_proxies` contains `0.0.0.0/0`, `::/0`, `0.0.0.0`, or `::` (catch-all
  entries that would trust every IP as a reverse proxy). Loopback addresses
  (127.x.x.x, ::1) are also rejected when the listener is bound to a public address
  (HEA-1213).

- **A-34 Consent page clickjacking protection** — `GET /ui/oauth/consent` and
  `POST /ui/oauth/consent` now emit `Content-Security-Policy: frame-ancestors 'none'`
  to prevent UI-redressing attacks on the approve/deny buttons. The consent ticket
  also embeds the issuing realm's ID; submitting a ticket from realm A into realm B's
  consent flow is now rejected (HEA-1213).

- **A-36 `agent_auth` feature guardrail** — Setting `agent_auth.enabled: true` in
  `hearth.yaml` now produces a startup error. The Agent entity, delegation chains,
  MCP/A2A surfaces, and Agent Authorization Tokens (AATs) described in
  `docs/specs/AGENT_AUTH.md` are not yet fully implemented; the guardrail prevents
  silent misconfiguration until the feature ships (HEA-1213).

- **A-24 Per-realm resource quotas** — `RealmConfig.quotas` (`RealmQuotaConfig`)
  adds optional per-realm caps for users, orgs, OAuth clients, total sessions,
  and audit rows. Create operations are rejected with HTTP 429 /
  `HEARTH_QUOTA_EXCEEDED` once the current count reaches the limit. All limits
  default to `None` (unlimited). Disk-usage soft-warning (`max_disk_bytes`) is
  checked by the daily background pruner (HEA-1195).

- **A-25 Audit auto-retention: `max_rows` backstop** — `AuditRetentionConfig`
  gains an optional `max_rows: u64` field.  The background daily pruner now
  enforces it after the time-based `retention_days` sweep: if the event count
  still exceeds `max_rows`, the oldest events are trimmed until the count is
  within the limit.  Two new `AuditEngine` trait methods: `count_events` and
  `prune_oldest` (HEA-1195).

### Changed

- **Atomic org-slug reservation and invitation acceptance** — concurrent requests can no
  longer both win the same organization slug or double-spend an invitation token; a
  per-engine mutex serializes the check-then-write sequence and `put_batch` makes the
  primary record + index land atomically (A-28, HEA-1207).
- **RBAC assignment deduplication** — concurrent role assignments for the same
  (subject, role, scope) tuple are now idempotent; the second caller receives the
  existing assignment record (A-28, HEA-1207).
- **Bounded realm deletion cascade** — `delete_realm` marks the realm
  `DeletingInProgress` before cascading, preventing new auth ops; the cascade is
  chunked (default 200 keys/chunk) and backgrounded for realms exceeding 1 000 items,
  preventing write storms that would degrade all tenants (A-33, HEA-1207).

- **Reserved slug registry and cooldown** — YAML-driven list of reserved names (admin, api,
  www, …) cannot be used as org or realm slugs; deleted slugs enter a 30-day cooldown before
  reuse (A-5, HEA-1212).
- **Bootstrap production guard** — `/admin/bootstrap` requires `--allow-bootstrap-in-prod`
  when running outside `--dev`; a loud warning is logged when the flag is active (A-6, HEA-1212).
- **JWKS/discovery per-IP rate cap** — JWKS and discovery endpoints capped at 60 req/s per
  source IP (configurable via `security.jwks_rps_limit`); responses served from pre-serialized
  `Arc<Bytes>` (A-10, HEA-1212).
- **WebAuthn attestation policy** — per-realm AAGUID allowlist, configurable rejection of
  "none" attestation, and optional PRF/large-blob requirement (A-13, HEA-1212).
- **TTL hard caps** — per-realm password-reset tokens capped at 1 h and magic-link tokens
  at 30 min; `allow_unsafe_ttl: true` in realm config bypasses the cap with a warning
  (A-14, HEA-1212).

### Security

- **A-43 gRPC reflection production-disable** — `security.grpc.reflection_enabled`
  (default `false`; `true` in `--dev`) gates the `grpc.reflection.v1.ServerReflection`
  service. Hearth refuses to start with reflection enabled in production mode unless
  `--allow-reflection-in-prod` is explicitly passed on the command line (HEA-1209).

- **A-44 TLS 0-RTT off + mTLS CRL revocation** — `rustls` `max_early_data_size` is
  asserted `= 0` at startup so a future library upgrade cannot silently re-enable
  replay-vulnerable early data. Optional `security.tls.crl_paths` accepts a list of
  PEM-encoded CRL files; when configured, mTLS client certificates are checked against
  every CRL on each handshake and revoked certificates are rejected (HEA-1209).

- **P-2 IP reputation: Spamhaus DROP + MaxMind ASN/GeoIP2** — New pluggable
  `IpReputationProvider` trait (`src/abuse/ip_reputation/`).  Two reference
  adapters ship: (1) `SpamhausDropProvider` — checks source IPs against the
  Spamhaus DROP (IPv4) and EDROP (IPv6) blocklists, refreshed daily in a
  background Tokio task via an Arc-swapped `CidrFilter` (lock-free, zero-alloc
  on the read path); (2) `MaxMindAsnProvider` — looks up the ASN for a source
  IP from a local MaxMind GeoLite2-ASN or GeoIP2-ASN MMDB file (operator
  provides the database; absent = fail-open noop).  Both adapters are
  fail-open.  Per-realm enable/action policy configured under
  `security.ip_reputation` in `hearth.yaml`.  (HEA-1203)

- **A-50 Cross-realm SMS / email aggregation cap** — Closes §3.53: a global
  (cluster-wide) counter keyed by recipient hash (email or E.164 phone number)
  now tracks how many distinct realms have sent to each address in a rolling
  window.  Three escalating outcomes fire as the distinct-realm count rises:
  `MultiRealmAlert` (emit A-7 operator webhook; send still allowed),
  `SoftCap` (CAPTCHA / queue required), and `HardCap` (send rejected with
  HTTP 429).  This closes the bypass where an attacker splits sends across N
  realms to slip past A-4's per-realm cap.  Fail-open on lock poisoning.  New
  config section `security.cross_realm_aggregation_cap` in `hearth.yaml`.
  New types: `CrossRealmAggCapConfig`, `CrossRealmOutcome`,
  `CrossRealmAggregationCap` in `src/abuse/detector`.  (HEA-1201)

- **P-4 `RiskScorer` pluggable trait + rule-based reference engine** — The A-11
  step-up MFA risk scorer is now exposed as a public pluggable trait
  (`src/abuse/risk_scorer`).  Operators can replace the built-in
  `RuleBasedRiskScorer` with any vendor risk engine or custom HTTP adapter by
  implementing `RiskScorer: Send + Sync`.  The built-in engine aggregates five
  configurable signals (`NewDevice`, `NewCountry`, `PasswordAge`,
  `BreachCorpusHit`, `RefreshContextDelta`) with per-weight YAML config under
  `security.risk_scorer`.  Fail-open: `enabled: false` (the default) and
  `NoopRiskScorer` both always return score `0.0`.  New type: `NoopRiskScorer`.
  Renamed public type: `RuleBasedRiskScorer` (was `DefaultRiskScorer` — alias
  preserved for existing call sites).  (HEA-1205)

- **A-46 Argon2 pepper rotation policy** — `CredentialConfig` gains an optional
  `PepperConfig` that applies `HMAC-SHA256(key=pepper, msg=password)` before
  Argon2id hashing. The pepper version is stored in `StoredCredential::pepper_version`
  (`serde(default)` for backward compatibility). On login, the engine tries the
  active pepper first; if the credential carries the previous pepper version
  (grace window open in config), it is also accepted and the credential is lazily
  re-hashed with the active pepper. Credentials without a pepper version (pre-upgrade)
  are also lazily upgraded. A new `hearth migrate rotate-pepper --data-dir <path>`
  CLI subcommand reports how many credentials in each realm still lack a pepper version.
  Fail-choice: fail-open (no pepper = still logs in) until operator installs pepper.
  New types: `PepperKey`, `PepperConfig`. New functions: `hash_password`,
  `verify_password_with_pepper` (both public for migration tooling). (HEA-1210)

- **A-3 Distributed-attack detector** — `DistributedAttackDetector` in
  `src/abuse/detector` tracks two cardinality dimensions per realm using a
  two-bucket rotating `DistinctWindow`: (1) distinct usernames tried per
  source IP and (2) distinct source IPs targeting one username.  When either
  count exceeds the configured threshold in the rolling window, `check()`
  returns `DetectorOutcome::Challenge` with a reason string for logging.
  Callers must emit `AuditAction::AbuseDetected` and apply A-16 / A-17.
  Fail-open on lock poisoning; `disabled()` constructor for opt-out.
  Config: `security.distributed_attack_detector` (`window`, per-dimension
  thresholds).  No new dependencies (HEA-1189).

- **A-4 Outbound email/SMS volume shield** — `OutboundVolumeShield` in
  `src/abuse/detector` enforces per-realm rolling-window distinct-recipient
  caps for outbound email (and SMS when that module ships).  Two thresholds:
  `SoftCap` for operator-review alerting (A-7 webhook / A-8 dashboard) and
  `HardCap` for mandatory send rejection (HTTP 429).  Recipients are stored
  as `SipHash-1-3` hashes — PII never written to memory.  Fail-open on lock
  poisoning; `disabled()` constructor for opt-out.  Config:
  `security.outbound_volume_shield` (`window`, `email_soft_cap`,
  `email_hard_cap`, `sms_soft_cap`, `sms_hard_cap`) (HEA-1189).

- **A-9 Tenant-managed CIDR allow/deny lists** — `CidrFilter` in `src/abuse/cidr`
  provides per-realm IPv4/IPv6 CIDR allow and deny lists evaluated in `AbuseGuard`.
  Stored under the `abuse:{realm}:cidr:*` key prefix.  Evaluation order: allow list
  overrides deny list (explicit trust); non-empty allow list enables strict whitelist
  mode; empty filter is fail-open per §6.1 (HEA-1191).

- **A-12 Adaptive exponential lockout backoff** — `AdaptiveBackoffStore` in
  `src/abuse/backoff` escalates per-key lockout durations across repeat offenses:
  **1 min → 5 min → 30 min → 24 h** (configurable).  The offense counter resets after
  a configurable cooldown period following the end of the most recent lockout.
  Disabled (fail-open) by default; enable via `security.adaptive_backoff` (HEA-1191).

- **A-17 Login-event tarpit** — `TarpitStore` in `src/abuse/tarpit` injects a
  deterministic delay (default 200 ms, configurable 100–500 ms) into auth `POST`
  requests once a source IP exceeds the failure threshold.  The delay is applied
  off the hot path by the caller (`tokio::time::sleep`); the `check()` method is
  allocation-free and meets the ≤5 µs p99 hot-path budget.  Disabled (fail-open)
  by default; enable via `security.tarpit` (HEA-1191).

- **P-3 BotSignal provider** — `BotSignalProvider` trait and reference
  `HeuristicBotSignalProvider` adapter in `src/abuse/bot_signal`.  The adapter
  applies three layers: JA3/JA4 hash blocklist (proxy-injected headers), `woothee`
  crawler-category detection, and scripting-client / headless-browser UA substring
  matching.  Default: fail-open; `NoopBotSignalProvider` ships as the default so
  no request is blocked until an adapter is configured.  External adapters
  (Cloudflare Bot Management, Datadome, Kasada, Akamai) implement the trait
  and plug in via `security.providers.bot_signal` (HEA-1204).

- **P-5 EmailReputation provider** — `EmailReputation` trait and reference
  `BuiltinEmailReputation` adapter in `src/abuse/email_reputation`.  The adapter
  checks the email domain against a bundled ~400-entry disposable-domain list and
  flags well-known role addresses (`noreply@`, `postmaster@`, `admin@`, etc.).
  DNS MX validity is stubbed (always passes); the upgrade path to
  `hickory-resolver` is documented in the module.  Default: fail-open;
  `NoopEmailReputation` ships as the default.  External adapters (Kickbox,
  ZeroBounce, NeverBounce) implement the trait and plug in via
  `security.providers.email_reputation` (HEA-1204).

- **A-48 Federation state↔session binding** — at `begin`, Hearth now plants a
  short-lived `hearth_fed_bind` cookie containing `HMAC-SHA256(cookie_secret,
  state_token)`. At `callback`, the server rejects requests that lack the
  cookie or whose MAC does not match — preventing cross-browser callback
  injection (IdP callback hijacking). Fail-closed (HEA-1200).

- **A-49 Refresh-token UA/ASN context binding** — grant families now record
  the SHA-256 hash of the `User-Agent` at grant creation time. On each refresh
  exchange, the engine computes a `RefreshContextDelta` risk signal when the
  UA hash changes. The signal is fed to the `DefaultRiskScorer`; when
  `security.risk_scorer.enabled = true` and the combined score exceeds
  `step_up_threshold`, the engine returns `StepUpChallengeRequired` so the
  caller must force re-authentication. Fail-open by default (HEA-1200).

- **A-26 `/metrics` authentication + `Server:` header suppression** — the
  Prometheus scrape endpoint now enforces `Authorization: Bearer <token>`
  (constant-time comparison) when `metrics.bearer_token` is set in
  `hearth.yaml`; unauthenticated requests receive HTTP 401 with
  `WWW-Authenticate: Bearer`. All responses no longer include a `Server:`
  header, preventing runtime/version fingerprinting (HEA-1196).

- **A-27 Tracing PII / token redaction** — a `Redact<T>` newtype in
  `src/protocol/redact.rs` wraps sensitive values so both `Display` and
  `Debug` emit `[REDACTED]`; the first usage guards the password-reset URL
  logged when no email transport is configured (`reset_url` span field in
  `protocol/web/handlers.rs`). Default-redacted fields: `reset_url`,
  `magic_link_url`, `password`, `token`, `cookie`, raw email (HEA-1196).

- **A-19 Email-change re-verification** — changing a user's email address now
  requires the new address to be verified via a separate 32-byte random token
  (SHA-256 stored, 24-hour TTL, single-use) before the swap is committed.
  Two new identity-engine methods are exposed: `initiate_email_change` (issues
  token, caller delivers to new address) and `confirm_email_change` (validates
  token, swaps indexes, revokes all sessions, caller notifies old address).
  New `EmailChangeInitiated` and `EmailChangeConfirmed` audit actions; new
  `EmailChangeTokenInvalid` error code `HEARTH_EMAIL_CHANGE_TOKEN_INVALID`
  (HEA-1194).

- **A-20 Deleted-account email reservation** — `delete_user` now writes a
  90-day tombstone under `email:reserved:{normalized_email}`. While the
  tombstone is live, `create_user` and `initiate_email_change` for that address
  return `EmailReserved` (same wire code as `DuplicateEmail` —
  `HEARTH_DUPLICATE_EMAIL` — for enumeration resistance). The tombstone is
  automatically cleaned up when it expires. (HEA-1194).

- **A-37 `prompt=none` silent-auth probe rate limit** — the OIDC
  `GET /ui/oauth/authorize` handler now tracks every `prompt=none` request per
  (realm, subject) in a 1-hour sliding window (cap: 50 probes/hour). Probes
  over the limit receive `error=login_required`. An `OidcSilentAuthProbed`
  audit event is emitted on every probe with `outcome` and `probe_count`
  metadata; new error code `HEARTH_SILENT_AUTH_RATE_LIMITED` (HEA-1194).

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

- **A-7 Security webhook channel** — operators can now subscribe webhooks to the
  `security.*` event family: `security.login_failed`, `security.account_locked`,
  `security.abuse_detected`, `security.password_compromised`, and
  `security.rate_limit_exceeded`. The webhook admin create/edit form lists these
  five event types with descriptions so they can be wired to a SIEM, Slack, or
  custom WAF without polling the audit log (HEA-1190).

- **A-8 Abuse monitor dashboard** — new admin page
  `/ui/admin/realms/{realm}/abuse` shows security event counters (login
  failures, locked accounts, rate-limit hits, compromised-password rejections,
  and abuse detections) over a rolling 24-hour window, plus a top-10 failing
  IPs table and a 50-event security timeline. ASN view, geo heat-map, and
  one-click block/unblock are placeholders pending the A-9 CIDR allow/deny
  lists and P-2 IP-reputation integration (HEA-1190).

- **`AuditAction::AbuseDetected`** — new `abuse_detected` wire-format audit
  action for the A-3 distributed-attack detector. Fail-open (`LogOnly`);
  included in `AuditAction::all()` for the audit-log filter UI (HEA-1190).

- **A-18 Session lifecycle policy + P-7 `SessionStore` trait** — per-realm
  `idle_timeout_secs` and `absolute_timeout_secs` on `RealmConfig` (also in
  `hearth.yaml` under `auth:` and per-realm). Sessions are evicted lazily on
  `get_session` / `refresh_session` and proactively by a background reaper task
  that runs alongside the existing OAuth cleanup sweep. A new `SessionEvicted`
  audit event (distinct from `SessionRevoked`) is emitted on every policy
  eviction. `SessionStore` pluggable trait (`src/identity/sessions.rs`) defines
  the persistence interface for multi-node deployments; `EmbeddedSessionStore`
  is the reference adapter backed by the WAL storage engine (HEA-1193).

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

- **§3.41 adversarial test-quality gate** — a new CI job (`abuse-coverage`) and
  `make abuse-check` target enforce that every A-N row in
  `docs/plans/HEA-1114-abuse-prevention.md` has at least one adversarial
  negative-scenario test in `tests/abuse_*.rs`. The gate is grep-only (no Rust
  build required) and completes in under two seconds. PRs that add a new plan row
  without a corresponding test now fail CI with a clear message listing the
  uncovered identifiers. Rollback: set `SKIP_ABUSE_COVERAGE_CHECK=1`; see the
  rollback procedure in `docs/plans/HEA-1114-abuse-prevention.md`. (HEA-1214)

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

- **Node SDK spec conformance (HEA-959)** — `@hearth-auth/node` now fully implements the
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
