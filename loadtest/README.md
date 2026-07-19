# hearth-loadtest

Load-testing harness for the Hearth identity server, built on
[goose](https://book.goose.rs/). Tracks the load-test plan in
[HEA-1787](/HEA/issues/HEA-1787).

## Why this crate is excluded from the workspace

`hearth-loadtest` is **not** a workspace member — the root `Cargo.toml`
declares `exclude = ["loadtest"]`. goose pulls in a large transitive
dependency tree (an async HTTP client, reqwest, tooling for reports) that we
do not want compiled on every `cargo nextest run --workspace`, which would
slow the unit-test gate for no benefit. The crate is `publish = false` and is
built/run explicitly instead.

## Building and running

**The one-liner.** With no `ARGS`, `make loadtest` runs the *whole* pipeline —
it boots a fresh throwaway dev Hearth on loopback, seeds a deterministic corpus,
runs the Goose journeys, writes `report.json` + HTML into `reports/`, and tears
the server down. No manual bootstrap / seed / attach steps:

```bash
make loadtest                          # boot → seed → run → report → teardown
make loadtest MODE=ramp                # env vars tune it (see below)
make loadtest USERS=50 RUN_TIME=3m THROTTLE=3
```

The pipeline lives in [`scripts/run-loadtest.sh`](scripts/run-loadtest.sh); every
knob is an env var (defaults in brackets):

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `8420` | Loopback port for the throwaway server |
| `MODE` | `steady` | `steady` \| `ramp` \| `soak` |
| `USERS` | `20` | Concurrent Goose users |
| `RUN_TIME` | `90s` | Per-run duration |
| `HATCH_RATE` | `5` | Users spawned per second |
| `THROTTLE` | `3` | Cap total req/s (stays under dev rate limits) |
| `USERS_PER_REALM` | `80` | Seeded user records |
| `SESSIONS_FRAC` | `0.5` | Fraction of users given a live token |
| `REVOKED_FRAC` | `0.1` | Fraction of live tokens pre-revoked |
| `SEED` | `1` | Determinism seed |
| `SETTLE` | `65` | Seconds to wait after seeding so the 100/min admin-write window resets (set `0` to skip) |
| `EXTRA_RUN_ARGS` | — | Extra flags appended to the `run` subcommand |

**Advanced / attach usage.** Passing `ARGS` bypasses the pipeline and invokes the
binary directly (for driving an instance you booted/seeded yourself):

```bash
make loadtest ARGS="run --weight-revoke 0"  # raw binary, no auto boot/seed
make loadtest ARGS="--help"
make loadtest-check                          # cargo check (keeps it from rotting)
make seed ARGS="..."                         # run just the seed step (see below)
```

Or directly:

```bash
cargo run --release --manifest-path loadtest/Cargo.toml -- seed --help
# unit tests (the crate is workspace-excluded, so run them explicitly):
cargo test --manifest-path loadtest/Cargo.toml
```

## Seed step (HEA-1789)

Load numbers are meaningless against an empty database, so before a run the
harness seeds a **deterministic, parameterized** corpus and persists a JSON
**seed-handle** that Goose users draw real, live credentials from.

```bash
# 1. Start a dev instance (separate terminal):
make dev

# 2. Seed it (defaults mirror the plan):
make seed ARGS="--users-per-realm 500 --sessions-frac 0.5 --revoked-frac 0.1"
```

### Parameters

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--target-host` | `HEARTH_LOADTEST_TARGET_HOST` | `http://127.0.0.1:8420` | Running Hearth to attach to |
| `--realms` | `HEARTH_LOADTEST_REALMS` | `5` | Realms to seed (see constraint below) |
| `--users-per-realm` | `HEARTH_LOADTEST_USERS_PER_REALM` | `200` | User records per realm |
| `--sessions-frac` | `HEARTH_LOADTEST_SESSIONS_FRAC` | `0.5` | Fraction of users given a live token |
| `--revoked-frac` | `HEARTH_LOADTEST_REVOKED_FRAC` | `0.1` | Fraction of live tokens pre-revoked |
| `--seed` | `HEARTH_LOADTEST_SEED` | `1` | Determinism seed (reproducible corpus) |
| `--seed-out` | `HEARTH_LOADTEST_SEED_OUT` | `loadtest/reports/seed-handle.json` | Seed-handle output path |
| `--admin-token` | `HEARTH_LOADTEST_ADMIN_TOKEN` | _(none)_ | Admin bearer token to attach to an **already-bootstrapped** instance (see below) |
| `--allow-remote-target` | `HEARTH_LOADTEST_ALLOW_REMOTE_TARGET` | off | Explicit opt-in for a non-loopback target (isolated lab only) |

### Seeding an already-bootstrapped instance (`401 missing authorization header`)

The seed's first step calls `POST /admin/bootstrap`. That endpoint only succeeds
**anonymously on a fresh instance** — on one that was *already* bootstrapped it
requires the bearer token from the first bootstrap and otherwise returns
`401 {"error":"missing authorization header"}`. You hit this whenever you seed a
long-lived dev server you (or the CLAUDE.md quickstart's manual
`curl -X POST /admin/bootstrap`) already bootstrapped, or re-run `make seed`
against the same instance. Note the dev-realm is **persistent across restarts**
when `HEARTH_DEV_DATA_DIR` is set, so restarting alone does not clear it.

Pass the admin token from your first bootstrap to re-bootstrap and attach.
Prefer the environment variable: `make` echoes each expanded recipe line, so a
token passed via `--admin-token` inside `ARGS` is printed to the terminal (and
any CI log) and is visible in `ps` while the seed runs. The env var avoids both.

```bash
# Grab the token once (first bootstrap returns it; re-bootstrap needs it):
ADMIN_TOKEN=$(curl -sf -X POST http://127.0.0.1:8420/admin/bootstrap | jq -r '.access_token')
HEARTH_LOADTEST_ADMIN_TOKEN=$ADMIN_TOKEN \
  make seed ARGS="--users-per-realm 80 --sessions-frac 0.5 --revoked-frac 0.1"
# --admin-token also works, but lands in the make echo / ps output — dev-only.
```

`make loadtest` boots its **own** fresh instance and never needs this. Access
tokens expire after 15 minutes; if the token has expired, re-bootstrap with it to
mint a fresh one (re-bootstrap does not change the admin password).

The dataset shape is echoed to stdout and stored in the seed-handle so every
report can describe the corpus it ran against. The same `--seed` always
produces the same emails and (ephemeral, never-persisted) passwords.

## Load run — the five journeys (HEA-1790)

Once an instance is seeded, `run` drives five **closed-loop** Goose journeys
(not endpoint hammering) against it, drawing real credentials from the
seed-handle. Weights default to the plan (HEA-1787 §4) and are all overridable.

```bash
# Attach to the same instance the handle was seeded on (host taken from the handle):
make loadtest ARGS="run --users 50 --run-time 60s --hatch-rate 5"

# Re-weight the mix (e.g. push issuance harder), or drop a journey with weight 0:
make loadtest ARGS="run --weight-validate 40 --weight-issuance 40 --weight-revoke 0"
```

| # | Journey | Weight flag (default) | HTTP calls |
|---|---|---|---|
| 1 | Validate | `--weight-validate` (70) | `POST /introspect` on a live token, asserts `active:true` |
| 2 | Session lookup | `--weight-session` (12) | `GET /userinfo` (CTO-approved Option A proxy — no public get-session route) |
| 3 | User lookup | `--weight-user` (8) | `GET /admin/users/{id}` with a seeded admin token |
| 4 | Issuance | `--weight-issuance` (8) | `POST /token` (ROPC password grant) |
| 5 | Revoke→re-validate | `--weight-revoke` (2) | `POST /token` → `POST /revoke` → `POST /introspect` asserts `active:false` (exercises the 64-shard revoke cache) |

Other run knobs: `--users`, `--run-time`, `--hatch-rate`, and `--throttle N`
(cap total requests/sec — useful against an instance with per-client token rate
limits, where an unthrottled run is dominated by `429`s rather than the hot
path — see [Rate limits](#rate-limits-on-a-dev-instance-why-you-throttle)). A
weight of `0` drops that journey entirely; at least one journey must be weighted.

## Run modes (HEA-1791)

`--mode` selects the load profile. All modes write the same `report.json`
schema (below); ramp/soak add their extra sections.

| Mode | Flag | What it does | Extra flags |
|---|---|---|---|
| `steady` (default) | `--mode steady` | Fixed `--users` for `--run-time`. The primary report. | — |
| `ramp` | `--mode ramp` | Steps the user ladder upward and records the **saturation knee** — the first step where a budgeted journey's p99 breaches its HTTP budget. Stops early at the knee. | `--ramp-start-users` (10), `--ramp-step-users` (10), `--ramp-steps` (8) |
| `soak` | `--mode soak` | Long fixed-user run split into equal buckets, surfacing latency **drift** over time. Total time ≈ `soak_buckets × run_time`. | `--soak-buckets` (6) |

```bash
make loadtest ARGS="run --mode ramp --ramp-start-users 20 --ramp-step-users 20 --ramp-steps 6"
make loadtest ARGS="run --mode soak --run-time 3m --soak-buckets 6"   # ≈ 18 min
```

## Reading the report

Every run writes two artifacts into `--report-dir` (default `loadtest/reports/`,
which is **git-ignored**):

- `report.json` — the machine-readable report (schema below). This is the
  artifact a nightly diff consumes.
- `steady.html` / `ramp-{N}u.html` / `soak-bucket-{N}.html` — Goose's own HTML
  report(s) for eyeball inspection (traces, per-request timelines).

`report.json` shape (`schema` is [`report::SCHEMA_VERSION`](src/report.rs) —
bumped on any breaking change so a nightly diff refuses to compare across
incompatible schemas):

| Field | Meaning |
|---|---|
| `metadata.git_sha` | Build commit (`HEARTH_GIT_SHA` env override, else `git rev-parse`, else `"unknown"`). |
| `metadata.timestamp_unix` | Wall-clock the report was produced. |
| `metadata.{mode,host,seed,dataset_shape,users,run_time,hatch_rate}` | Run configuration + the corpus it ran against. |
| `journeys[]` | Per-journey rows (sorted by name for diff-stable output). |
| `journeys[].{p50,p95,p99,p999}_ms` | Response-time percentiles (whole ms — Goose's granularity). |
| `journeys[].{requests,failures,failure_rate}` | Volume + non-2xx fraction. A journey that is fast-but-erroring is **not** a pass. |
| `journeys[].spec_engine_p99_us` | The in-process engine p99 target this journey maps to (informational floor). |
| `journeys[].http_budget_p99_us` | The HTTP p99 budget asserted against = engine target + 1 ms loopback envelope. |
| `journeys[].pass` | `true`/`false` vs the HTTP budget **and** failure rate; absent for the compound revoke journey (no atomic target). |
| `ramp_steps[]`, `knee_rps` | ramp mode only — per-step rows and the saturation-knee RPS. |
| `soak_buckets[]` | soak mode only — per-bucket rows for drift inspection. |
| `pass` | Overall: every *budgeted* journey stayed within budget. |

### Budgets — sourced, and why sub-ms budgets read `pass:false` on a dev box

Budgets are **sourced**, not invented (see [src/budget.rs](src/budget.rs)):
each journey's engine p99 target is lifted verbatim from
`docs/specs/TESTING.md`, and the HTTP budget adds a CTO-approved ~1 ms loopback
envelope (axum routing + (de)serialization + loopback syscalls), per the
HEA-1787 plan §6/§9.

| Journey | Engine p99 (spec) | HTTP p99 budget |
|---|---|---|
| `validate` (`/introspect`) | 500 µs | 1.5 ms |
| `session_lookup` (`/userinfo`) | 100 µs | 1.1 ms |
| `user_lookup` (`/admin/users/{id}`) | 200 µs | 1.2 ms |
| `issuance` (`/token`) | 5 ms | 6 ms |

A pass also requires the journey's failure rate to stay at or below
`MAX_FAILURE_RATE` (5%) — a 1 ms journey that 100%-errors must not read green.

**Expect `pass:false` for the sub-ms journeys on a normal dev machine.** Goose
records response times in whole milliseconds, so the smallest non-zero p99 it
can report is 1 ms; ordinary loopback scheduling jitter puts observed p99 at
2–3 ms, which exceeds the sub-ms `session`/`user`/`validate` budgets even though
the engine itself is well under target. `issuance` likewise blows its 6 ms
budget because the HTTP path runs a **real Argon2id** password hash (10–22 ms)
that the in-process engine bench does not. The committed
[baseline](#the-committed-baseline) is a clean, zero-failure run that still
reports `pass:false` for exactly these reasons — the budgets are an aspirational
engine-level ceiling, and this HTTP harness is a **drift detector and capacity
probe**, not a sub-ms pass gate. Sub-ms verification lives in the in-process
`make bench-gate`, not here.

## Rate limits on a dev instance (why you throttle)

A dev boot enforces per-client rate limits that an unthrottled load run trips
immediately, because every journey authenticates as the **single** dev client:

- **Token endpoint** (`/token`, `/introspect`, `/revoke`): 200 req/min per
  client (`TOKEN_RATE_LIMIT`). `validate` + `issuance` + `revoke` share it.
- **Admin writes** (`/admin/users`, …): 100 req/min per admin
  (`ADMIN_RATE_LIMIT`). Bounds both the seed (≤ ~90 users/boot) and
  `user_lookup`.
- **Per-IP request shaper**: 100 req/s per source IP by default.

An unthrottled run is therefore dominated by `429`s rather than the hot path.
Two ways to get a clean run:

1. **Throttle under the limit** (single-subject boot-local corpus): keep the
   token-bucket journeys under ~3.3 req/s combined, e.g.
   `--throttle 3`. This is what the committed baseline uses.
2. **Raise the shaper for a loopback-only run.** Boot with a config that lifts
   `security.request_shaper` (the admin/token per-client caps are compile-time
   constants and are *not* raised by this — they still bound a single-subject
   run):

   ```yaml
   # hearth-loadtest.yaml — loopback dev only, never production
   security:
     request_shaper: { ip_rps: 500000, realm_rps: 5000000 }
   ```
   ```bash
   hearth serve --dev --config hearth-loadtest.yaml
   ```

For a realistic *high-throughput* run the per-client caps must be spread across
**many** subjects — use the multi-subject attach path below.

## ⚠️ Security warnings (read before running)

- **Dev / loopback only — enforced at runtime.** The seed step calls
  `POST /admin/bootstrap`, mints live tokens, and revokes them. It **refuses
  any non-loopback `--target-host`** unless you pass the explicit
  `--allow-remote-target` opt-in; use that only for an isolated lab instance
  you control, never a shared or production instance — it would create real
  users and tokens and could exhaust admin rate limits. (Production servers
  fail closed anyway: `/admin/bootstrap` is disabled outside `--dev` mode, so
  the flow dies at step 1 before any credential is sent.)
- **Deterministic passwords are derivable from the seed.** `--seed` is not a
  secret: anyone who knows (or guesses the default) seed can derive every
  seeded password. That is fine for a loopback dev corpus and is exactly why
  these credentials must never be provisioned on shared infrastructure.
- **The seed-handle holds live bearer tokens.** It is written owner-only
  (`0600`) into `loadtest/reports/`, which is **git-ignored**. Do not commit
  it, paste it into issues/logs, or move it outside that directory.
- **Secrets are never logged or persisted where they shouldn't be.** The admin
  bootstrap token stays inside the HTTP client only; seeded passwords are
  deterministic and discarded; `SeededToken`'s `Debug` redacts the token.

## Server-capability constraints (important)

Two mechanisms the plan assumed are **not available** on the current REST
surface, so the boot-local seed is narrower than the plan text:

1. **`POST /admin/realms` is disabled** (`405`; realms are declared in
   `hearth.yaml`). The boot-local path seeds only the single dev realm that
   bootstrap creates; `--realms > 1` is clamped to 1 with a warning.
2. **`POST /admin/users` cannot set a password**, so admin-created users have
   no credential and cannot drive the ROPC (`/token` password grant) journey.
   Live tokens are therefore minted for the well-known dev admin
   (`admin@dev.local`), giving many live sessions for one subject. The seeded
   user *records* still populate a realistic `lookup_user` / session-count
   corpus.

### Large / multi-subject corpus (`--target-host` attach path)

For a realistic multi-realm, multi-subject corpus, boot the large-scale demo —
which pre-provisions realms and millions of users **with passwords** via
`hearth.yaml` reconcile seed users — then attach the harness to it:

```bash
make seed-large        # boots ./data/demo with examples/large-scale-demo/hearth.yaml
make seed ARGS="--target-host http://127.0.0.1:8420 --users-per-realm 1000"
```

Wiring per-subject ROPC across the demo users (so live tokens span many
subjects) is a follow-up; the deterministic per-user credential API
(`SeedParams::user_password`) already exists for it.

## The committed baseline

[`baseline/steady-baseline.json`](baseline/steady-baseline.json) is a committed
`report.json` from a clean, zero-failure `steady` run so a future nightly diff
has a reference to compare against. It lives outside the git-ignored
`reports/` directory precisely so it can be tracked.

How it was captured (reproducible):

```bash
# 1. Boot a dev instance with the shaper raised (see Rate limits above):
hearth serve --dev --config hearth-loadtest.yaml
# 2. Seed under the 100/min admin-write cap:
make seed ARGS="--users-per-realm 80 --sessions-frac 0.5 --revoked-frac 0.1"
# 3. Wait ~65 s for the admin-write window to reset, then run throttled:
make loadtest ARGS="run --mode steady --users 20 --run-time 90s --hatch-rate 5 --throttle 3"
# 4. Copy the fresh report over the baseline (zero out volatile metadata):
#    cp loadtest/reports/report.json loadtest/baseline/steady-baseline.json
#    then set metadata.timestamp_unix to 0 and metadata.git_sha to the capture commit.
```

### Updating the baseline

Re-capture with the steps above whenever an **intended** perf change moves the
numbers (and note why in the commit). Normalise the two volatile metadata fields
before committing so the diff stays clean:

- `metadata.timestamp_unix` → `0`
- `metadata.git_sha` → the short SHA the baseline was captured at

Everything else (journey percentiles, budgets, `pass`) is the signal.

### Nightly CI consumption + diff sketch (out of scope to wire here)

The intended (not-yet-wired) nightly job would:

1. Boot a dev instance + seed a fixed `--seed` corpus (deterministic).
2. Run `make loadtest ARGS="run --mode steady …"`, producing `report.json`.
3. Diff the fresh `report.json` against `baseline/steady-baseline.json`,
   **ignoring** `metadata.timestamp_unix` and `metadata.git_sha`, comparing
   `journeys[].{p50,p95,p99}_ms` per journey and flagging a regression when a
   percentile grows beyond a tolerance (e.g. `p99` up > 25% or > 1 ms). Refuse
   to compare if `schema` differs.
4. Post the delta as a nightly report; **it is advisory**, not a PR gate.

A minimal diff is a `jq`/small-script comparison — no bespoke tooling. Wiring
the CI job itself is deliberately out of scope for this crate (see below).

## Explicitly out of scope

- **Not a per-PR gate.** `make loadtest` needs a booted, seeded instance and
  minutes of wall-clock; it is a nightly/on-demand probe, never a blocking PR
  check. Sub-ms hot-path regression gating lives in the in-process
  `make bench-gate`.
- **Budgets are sourced, not tuned here.** They come verbatim from
  `docs/specs/TESTING.md` + a fixed loopback envelope (see
  [src/budget.rs](src/budget.rs)); this crate does not invent or relax them.
- **No CI wiring.** The nightly job + baseline-diff automation above is a
  sketch; wiring it into GitHub Actions is a separate ticket.
- **No production/remote targets.** Loopback dev only; the seed refuses
  non-loopback targets without an explicit opt-in.

## Status — DoD (HEA-1792)

Seed (HEA-1789), the five closed-loop journeys + weighting (HEA-1790), and run
modes + JSON/HTML reporters + sourced budgets (HEA-1791) are all implemented.
DoD verified: `make loadtest` runs clean end-to-end (seed → steady run →
`report.json` + HTML, zero request failures), the baseline is committed, and the
crate is `clippy`/`fmt` clean. The workspace `cargo nextest run` is unaffected
because this crate is workspace-excluded.
