# Development Reference

Commands, local setup and dev-server recipes for working on Hearth. The rules every change
must follow are in [`CLAUDE.md`](../../CLAUDE.md); contributor process is in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## First Commands After Clone

```bash
make setup          # enables repo-managed git hooks (.githooks/)
make tailwind-install  # downloads Tailwind standalone CLI to ui/tailwindcss
```

## Development Commands

| Command | What it does |
|---------|-------------|
| `make check` | clippy + fmt + nextest — run before every PR |
| `make test` | `cargo nextest run --workspace --features hearth/dev-endpoints` (PROTOC env var required) |
| `make test-detached` | The full suite in one `--workspace` pass, detached from the caller — **agents MUST use this (or `scripts/run-detached.sh`) for any long run**; see "Long-running commands" in `CLAUDE.md` |
| `make test-no-dev-endpoints` | Runs the tests that only compile WITHOUT `dev-endpoints` (the production feature set) — CI job `no-dev-endpoints` |
| `make clippy` | `cargo clippy --all-targets -- -D warnings`, once without and once with `dev-endpoints` |
| `make fmt` | `cargo fmt --check` |
| `make build` | Tailwind CSS + `cargo build --features hearth/dev-endpoints` |
| `make css` | Rebuilds `src/protocol/web/assets/app.css` from Tailwind |
| `make css-check` | CI gate — fails if app.css is stale |
| `bacon test` | TDD watch loop (configured in `bacon.toml`) |
| `make ui-test-smoke` | Playwright crawler smoke against a running dev server |
| `make ui-test-accessibility` | axe-core scan — critical/serious = FAIL, minor/moderate = WARN |
| `make ui-test-exploratory` | Deep crawl with pagination + form discovery (always exits 0) |
| `make ui-coverage-check` | Diff crawl manifest vs declared routes → `reports/coverage-gaps.txt` |
| `make ui-test-visual` | Visual regression baselines; `UPDATE=1` locks new snapshots |
| `make ui-test-cross-browser` | Smoke + flows + regression on Chromium, Firefox, WebKit |
| `make ci-local-fast` | Host-side mirror of PR-blocking CI (8 checks, ~5 min) — run before push |
| `make ci-local-full` | Full container reproduction via `act` (~10-15 min) — use when `ci-local-fast` passes but CI fails, or when editing workflow files |
| `make sdk-smoke-local` | Build hearth, boot `--dev`, run TS + Go SDK example smokes, tear down |
| `cd sdks/php && composer test` | Run PHP SDK unit tests (smoke-test the PHP SDK locally) |
| `make seed` | Seed a deterministic corpus onto a running dev instance for load tests — pass params via `ARGS` (see `loadtest/README.md`) |
| `make loadtest` | Run the `hearth-loadtest` Goose harness against a seeded instance; writes JSON + HTML reports. Nightly/pre-release only, **not** a per-PR gate (`loadtest/README.md`) |
| `make coverage` | Line + branch coverage via `cargo-llvm-cov` → `coverage/html/index.html` + `coverage/lcov.info`. Requires `cargo install cargo-llvm-cov` + `rustup component add llvm-tools-preview`. |
| `make scratch-prune` | Prune stale `/scratch` cargo target dirs and temp files (HEA-2198). Retention: `target-hea-*` > 7 d, other `target-*` > 14 d, `/scratch/tmp` > 7 d. |
| `make scratch-prune-dry-run` | Preview what `scratch-prune` would remove without deleting anything. |
| `make scratch-timer-install` | Install a systemd user timer that runs `scratch-prune` daily at 03:00. Idempotent. |

## UI Test Pre-commit Workflow

Before pushing a PR that touches templates, admin handlers, or any `src/protocol/web/` code:

```bash
# 1. Start the dev server (leave running in a separate terminal)
make dev

# 2. In another terminal, run the crawler smoke + accessibility scan
make ui-test-smoke           # ~30 s — crawls all nav-reachable pages
make ui-test-accessibility   # ~60 s — axe-core audit on major pages

# 3. Review any gaps between declared routes and crawled pages
make ui-coverage-check       # writes tests/ui/reports/coverage-gaps.txt

# 4. Optionally run the exploratory deep crawl (pagination + forms, non-blocking)
make ui-test-exploratory
```

Reports land in `tests/ui/reports/`:
- `html/` — full Playwright HTML report (open in browser for traces + screenshots)
- `crawl-manifest.json` — every page visited with pass/fail status
- `axe-*.json` — per-page axe-core violation details
- `coverage-gaps.txt` — routes declared in `web/mod.rs` but not crawled
- `deep-crawl-manifest.json` / `deep-crawl-gaps.txt` — exploratory run output

**Build prerequisites:**
- `PROTOC` env var must point to `protoc` (or set `make PROTOC=protoc check`).
- `buf` is **required** — install via `brew install bufbuild/buf/buf` or https://buf.build/docs/installation. The pre-commit hook and CI both invoke it.
- `ui/tailwindcss` must be present for CSS changes (`make tailwind-install`).
- `hearth.yaml` is **gitignored** — copy from `hearth.example.yaml`.

## Quick Start

```bash
make dev                              # cargo run --features dev-endpoints -- serve --dev  (preferred)
# or:
cargo build --release --features dev-endpoints
./target/release/hearth serve --dev   # binds 127.0.0.1:8420, in-memory storage
curl http://127.0.0.1:8420/health
curl -X POST http://127.0.0.1:8420/admin/bootstrap  # dev-only, creates realm+admin+token
```

`dev-endpoints` is **not** a default cargo feature: it compiles in `/admin/bootstrap`, the
`/dev/seed-*` routes and the hard-coded dev admin password, so a plain `cargo build --release`
is a production build without them. `make dev`, `make build`, `make test`, `make check`, bacon
and CI opt in; a bare `cargo nextest run` compiles the bootstrap-dependent tests out (pass
`--features dev-endpoints` to run them). `serve --dev` on a featureless binary logs a warning
that bootstrap is unavailable.

`--dev` auto-enables the in-process **mailcatcher** email transport. All outbound emails are captured and visible at `http://127.0.0.1:8420/dev/mail`. No Docker or external mail server needed.

## Bootstrap & Browser Login (dev-only)

The bootstrap endpoint creates credentials on **first call only**. Re-bootstrap
(when the dev-realm already exists) refreshes tokens but does **not** change the
admin password — include the Bearer token from the first bootstrap.

```bash
# 1. Start the server (in background or a separate terminal)
make dev &
# Wait for: "listening on 127.0.0.1:8420"

# 2. First bootstrap — creates realm + admin user + API token, and enrols TOTP
#    for both admins. admin_password, totp_secret and admin_totp_secret are
#    returned ONLY on this first call — save them securely.
BOOTSTRAP=$(curl -sf -X POST http://127.0.0.1:8420/admin/bootstrap)
REALM_ID=$(echo "$BOOTSTRAP" | jq -r '.realm_id')
ADMIN_TOKEN=$(echo "$BOOTSTRAP" | jq -r '.access_token')
ADMIN_PASSWORD=$(echo "$BOOTSTRAP" | jq -r '.admin_password')
SYSTEM_TOKEN=$(echo "$BOOTSTRAP" | jq -r '.system_access_token')
SYSTEM_REALM_ID=$(echo "$BOOTSTRAP" | jq -r '.system_realm_id')
ADMIN_TOTP_SECRET=$(echo "$BOOTSTRAP" | jq -r '.admin_totp_secret')  # admin@hearth.test
TOTP_SECRET=$(echo "$BOOTSTRAP" | jq -r '.totp_secret')              # admin@dev.local

echo "Realm:         $REALM_ID"
echo "Token:         $ADMIN_TOKEN"
echo "Password:      $ADMIN_PASSWORD"   # store this — it will not be shown again
echo "System Token:  $SYSTEM_TOKEN"
echo "System Realm:  $SYSTEM_REALM_ID"
echo "Admin TOTP:    $ADMIN_TOTP_SECRET"   # store this — it will not be shown again
echo "Dev TOTP:      $TOTP_SECRET"         # store this — it will not be shown again

# 3. Re-bootstrap (after server restart / token expiry) — requires the Bearer token.
BOOTSTRAP=$(curl -sf -X POST http://127.0.0.1:8420/admin/bootstrap \
  -H "Authorization: Bearer $ADMIN_TOKEN")
ADMIN_TOKEN=$(echo "$BOOTSTRAP" | jq -r '.access_token')
SYSTEM_TOKEN=$(echo "$BOOTSTRAP" | jq -r '.system_access_token')
```

**Browser login:** navigate to `http://127.0.0.1:8420/ui/admin/login` and sign in with:

| Field    | Value                                      |
|----------|--------------------------------------------|
| Email    | `admin@hearth.test`                        |
| Password | the `admin_password` from first bootstrap  |
| TOTP code | a code from `admin_totp_secret`, e.g. `oathtool --totp -b "$ADMIN_TOTP_SECRET"` |

The system realm always requires MFA, so the console asks for a TOTP code after the
password. Add `admin_totp_secret` (base32) to an authenticator app, or compute a code
with `oathtool`. Both TOTP secrets are empty on re-bootstrap. Bootstrap spends the
current 30-second code when it enrols the factor, and a spent code is refused, so right
after bootstrap use the next code (wait up to 30 s).

A successful login answers `303` to `/ui` (the dashboard). `/ui/admin` redirects on to
`/ui/admin/realms`. There is no `/admin` HTML page — that prefix is the JSON admin API
and answers `404` in a browser. Note the two bootstrap admins are different accounts:
`admin@hearth.test` lives in the system realm and is the one the console accepts;
`admin@dev.local` is the dev-realm identity behind `access_token` and `401`s at this form.

**API usage with the tokens:**

```bash
# Dev-realm operations (most admin API calls).
# X-Realm-ID is MANDATORY on every /admin/* route — without it the call answers
# 400 {"error":"missing X-Realm-ID header"}, not 401.
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "X-Realm-ID: $REALM_ID" \
  http://127.0.0.1:8420/admin/realms | jq .

# Cross-realm operations (e.g. rotate a non-dev realm's signing key)
# Use the system token + X-Realm-ID header
curl -s -X POST \
  -H "Authorization: Bearer $SYSTEM_TOKEN" \
  -H "X-Realm-ID: $SYSTEM_REALM_ID" \
  http://127.0.0.1:8420/admin/realms/<other-realm-id>/rotate-signing-key | jq .
```

> `access_token` is scoped to the dev realm only — it 403s on cross-realm operations.
> `system_access_token` carries the nil-UUID system-realm identity and can manage any realm.
> Both are long-lived Bearer tokens. They are **not** session cookies — browser pages require
> the cookie set by the login form above.

## Release-cut procedure

When cutting a versioned release (`vX.Y.Z`):

1. Replace `## [Unreleased]` in `CHANGELOG.md` with `## [X.Y.Z] — YYYY-MM-DD`.
2. Add a fresh `## [Unreleased]` section above it (empty categories can be omitted).
3. Tag the commit: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`.
4. The changelog entry for the release commit itself is the version heading — no bullet needed.
