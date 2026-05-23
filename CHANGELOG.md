# Changelog

All notable changes to Hearth will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Hearth has not yet cut a versioned release; all shipped work appears under `[Unreleased]`.

## [Unreleased]

### Changed

- **CI: scoped security scanners to production code** — CodeQL `paths-ignore`,
  Trivy `skip-dirs`, and a new `osv-scanner.toml` exclude test fixtures,
  example apps, fuzz harness code, and the Playwright runner from code
  scanning. Production SDKs (`sdks/*/`), root `Cargo.lock`, `fuzz/Cargo.lock`,
  and `src/**` remain in scope and must stay green. No CVE-id suppressions
  were added — only directories. Existing alerts for excluded paths are
  dismissed via `code-scanning/alerts` after the SARIF re-upload (HEA-690).

### Security

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
- **Go SDK toolchain bumped to 1.26** — `sdks/go/go.mod` `go` directive raised
  from `1.24` → `1.26` so OSV-Scanner resolves the bundled `stdlib` against
  patched releases. Closes CVE-2026-39820 (`net/mail` quadratic concatenation
  DoS) and CVE-2026-39823 (`html/template` XSS bypass) — Code Scanning alerts
  #219 and #220. No SDK code changes; `go mod tidy` regenerated `go.sum`
  (HEA-698).
- **CSP hardened** — `Content-Security-Policy` for all `/ui/**` routes now enforces
  `script-src 'self' 'unsafe-eval'` (no `'unsafe-inline'`), `style-src 'self'`,
  `font-src 'self'`, and `base-uri 'self'`. No third-party origins remain in any
  directive (HEA-630).

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
- **License** — promoted to AGPL-3.0-only (`LICENSE`) for OpenSSF machine-detectability; commercial licensing available (see `docs/vision/VISION.md`).
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
