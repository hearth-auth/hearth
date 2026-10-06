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
make dev
```

Then open **http://127.0.0.1:8420/dev** (the startup panel prints the link) and click
**Sign in** on the account you want. That is the whole local sign-in.

`make dev` runs `cargo run --features dev-endpoints -- serve --dev` on `127.0.0.1:8420`, with
persistent data in `./data/dev` (`make dev-reset` wipes it). The first visit to `/dev` creates the
dev accounts, so a fresh data directory needs no bootstrap call and no setup link.

`dev-endpoints` is **not** a default cargo feature: it compiles in the dev console,
`/admin/bootstrap`, the `/dev/seed-*` routes and the hard-coded dev passwords, so a plain
`cargo build --release` is a production build without them. `make dev`, `make build`,
`make test`, `make check`, bacon and CI opt in; a bare `cargo nextest run` compiles the
bootstrap-dependent tests out (pass `--features dev-endpoints` to run them). `serve --dev` on a
featureless binary logs a warning that these routes are unavailable.

`--dev` auto-enables the in-process **mailcatcher** email transport. All outbound emails are
captured and visible at `http://127.0.0.1:8420/dev/mail` (its password is in the startup panel).
No Docker or external mail server needed.

## Dev console and dev accounts (dev-only)

`/dev` lists the two dev accounts:

| Account | Signs in to | Password |
|---------|-------------|----------|
| `admin@hearth.test` | the admin console (`/ui/admin`), system realm | `HearthTest123!` |
| `admin@dev.local` | the `dev-realm` tenant (`/ui/realms/dev-realm/login`) | `HearthDev123!` |

For each account the page shows:

- **Sign in** — opens a browser session counted as having proved a second factor, then
  redirects to the console (or the realm home). No TOTP code is typed.
- The **current TOTP code** (it refreshes every 30 seconds), the TOTP secret and a QR code, for
  testing the real password-plus-TOTP sign-in.
- A fresh **API access token** (valid 15 minutes; reload for a new one) and the **realm ID**
  for the `X-Realm-ID` header.

The console answers only under `--dev` and only to a loopback client, like every dev endpoint.
A form post from another site cannot use its **Sign in** button.

If `/dev` reports that the accounts could not be set up, the data directory predates the
current code: run `make dev-reset` and reload.

### Admin API from a shell

Copy a token and the realm ID from `/dev`, then:

```bash
# X-Realm-ID is MANDATORY on every /admin/* route — without it the call answers
# 400 {"error":"missing X-Realm-ID header"}, not 401.
curl -s -H "Authorization: Bearer <token>" -H "X-Realm-ID: <realm-id>" \
  http://127.0.0.1:8420/admin/realms
```

The `admin@dev.local` token is scoped to `dev-realm` and answers `403` on cross-realm
operations. The `admin@hearth.test` token carries the system-realm identity and can manage any
realm (for example, rotate another realm's signing key).

### Scripted bootstrap (CI, SDK and UI test harnesses)

Scripts that need tokens without a browser call `POST /admin/bootstrap` on a fresh data
directory. It creates the same accounts and returns, on the **first call only**, the passwords
and TOTP secrets with the tokens:

```bash
BOOTSTRAP=$(curl -sf -X POST http://127.0.0.1:8420/admin/bootstrap)
jq -r '.realm_id, .access_token, .system_access_token' <<< "$BOOTSTRAP"
```

Use `jq ... <<< "$BOOTSTRAP"` (or `printf '%s'`), not `echo "$BOOTSTRAP" | jq`: zsh's `echo`
turns the `\n` escapes inside the JSON strings into line breaks, and `jq` then refuses the input.

Once the accounts exist (after a first bootstrap, or a visit to `/dev`), a call without a token
answers `401`. A re-bootstrap needs the Bearer token of an earlier call, returns fresh tokens,
and never changes a password:

```bash
curl -sf -X POST http://127.0.0.1:8420/admin/bootstrap -H "Authorization: Bearer <access_token>"
```

When the accounts were set up from `/dev`, there is no first-call response to reuse.
`GET /dev/credentials` returns the same fields as the bootstrap response, with fresh tokens and
both TOTP secrets, under the same `--dev` and loopback gates. The UI test harness
(`tests/ui/fixtures/bootstrap.ts`) falls back to it when a re-bootstrap answers `401`.

## Release-cut procedure

Releases are automatic. Do not tag by hand.

- `semantic-release` (`.github/workflows/semantic-release.yml`) runs on every push to `main`. It
  reads the squash-merge title (Conventional Commits): `fix:` cuts a patch, `feat:` a minor, a
  `!` or `BREAKING CHANGE` a major. `docs:`, `chore:`, `ci:` and the like cut no release.
- It first waits for `main`'s CI on that commit (`required-summary`). If CI failed for an
  infrastructure reason (a rate limit, no runner), re-run the failed jobs with
  `gh run rerun <id> --failed`, then re-run the release.
- The `v*` tag triggers `release.yml` (signed binaries, SBOM, provenance), `docker.yml` and
  `helm.yml`. The SDK tags (`sdk-ts-v*`, `sdks/go/v*`, `sdk-python-v*`, `sdk-php-v*`) trigger
  their publish workflows.
- After a new binary release is published, `scripts/check-readme-version.sh` fails every PR until
  the README's install pins name it. Update them in a `docs:` PR.

`CHANGELOG.md` entries stay under `## [Unreleased]`, written with each PR (see `CLAUDE.md`).
