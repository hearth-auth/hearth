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
it boots a fresh throwaway dev Hearth on loopback **pre-seeded with the large
corpus**, mints a live-token pool, runs the Goose journeys, writes
`report.json` + HTML into `reports/`, and tears the server down. No manual
bootstrap / seed / attach steps:

```bash
make loadtest                          # that's it — nothing else is required
```

**That command is the entire contract.** No running server, no bootstrap, no
`make seed`, no ARGS, no env vars, no ports to free up. It builds a release
Hearth, boots a throwaway instance on a free loopback port, seeds, runs, writes
the reports, and cleans up. If you can build the repo, `make loadtest` works.

### The large corpus (default for `make loadtest`)

Numbers against an empty DB are meaningless, so `make loadtest` **specifically**
defaults to a large, demo-seeded corpus — a multi-hundred-thousand-user dataset
(~1.2M users across the `acme`/`globex`/`initech`/`umbrella` realms) described by
[`loadtest-corpus.yaml`](loadtest-corpus.yaml). This is the whole point of the
harness: the journeys observe tail latency, saturation, and drift against a
realistically-large storage engine, not a toy DB.

- The corpus is seeded **in-server** by the fast batched demo seeder
  (`demo.enabled`), not over REST — millions of users load in a couple of
  minutes on a release build.
- It runs in a background task, so the pipeline **waits for the server's
  `demo seeding finished (all realms)` log line** before starting load (env
  `SEED_WAIT`, default `1800s`).
- The corpus is **fresh each run** (its data dir is wiped before boot) so the
  dev-realm bootstrap the token pool needs always starts clean.
- Only `make loadtest` gets the large corpus by default. The standalone
  `make seed` / `seed` subcommand keep their small, explicit defaults — the big
  dataset is opt-in there (see [Seed step](#seed-step-hea-1789)).

> **Reading the report — two different "users":** the report's `users` field is
> the **Goose load-generator concurrency** (`USERS`, default `200`), *not* the
> seeded population. The resident corpus is surfaced separately in the report's
> `dataset_shape` as `resident_corpus=<N>` (wired via `--resident-corpus-size`,
> which `make loadtest` passes automatically as the sum of the `CORPUS_*` knobs).
> So a report showing `users: 200` and `dataset_shape: "… resident_corpus=1200000"`
> drove 200 concurrent generators against a 1.2M-user store — the `200` is the
> attack width, the `1200000` is the corpus.
>
> The **HTML report** makes this explicit too: Goose's overview line, which it
> renders as a bare `Users: 200`, is rewritten to
> `Load-generator users (concurrency): 200 — resident corpus under test:
> 1,200,000 seeded accounts`, so the most-prominent number can no longer be
> mistaken for the seeded population. The same clarification is applied to the
> report's dedicated **User Metrics** section — whose active-users graph likewise
> peaks at the `--users` concurrency — which is retitled `Load-generator
> concurrency (active users)` with a note that the graph is the attack width, not
> the seeded population.
- **Fast pipeline smoke:** shrink the corpus with the `CORPUS_*` knobs, e.g.
  `CORPUS_ACME=200 CORPUS_GLOBEX=0 CORPUS_INITECH=0 CORPUS_UMBRELLA=0 make loadtest`.

Everything below is **optional tuning** — the defaults are chosen so the bare
command always produces a valid report. You never need any of it.

```bash
make loadtest MODE=ramp                # optional: env vars tune the run
make loadtest USERS=50 RUN_TIME=3m THROTTLE=3
```

The pipeline lives in [`scripts/run-loadtest.sh`](scripts/run-loadtest.sh); every
knob is an **optional** env var (defaults in brackets):

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `auto` | Loopback port (default: a free ephemeral port — never collides) |
| `MODE` | `steady` | `steady` \| `ramp` \| `soak` (steady at high `USERS` **is** the concurrent fan-out shape) |
| `USERS` | `200` | Concurrent Goose users — raise into the thousands for a fan-out run |
| `RUN_TIME` | `90s` | Per-run duration |
| `HATCH_RATE` | `50` | Users spawned per second |
| `THROTTLE` | `0` | Cap total req/s; `0` = **unthrottled** (default). Server-side rate limits are disabled (see below), so there is no limiter to stay under. Set `>0` only to pin a specific offered load for a controlled ramp |
| `LOADTEST_DATA_DIR` | `./data/loadtest-corpus` | Throwaway corpus data dir (wiped + re-seeded before each boot) |
| `CORPUS_ACME` | `500000` | Users seeded into the `acme` realm (the large default) |
| `CORPUS_GLOBEX` | `400000` | Users seeded into the `globex` realm |
| `CORPUS_INITECH` | `200000` | Users seeded into the `initech` realm |
| `CORPUS_UMBRELLA` | `100000` | Users seeded into the `umbrella` realm |
| `HOT_TIER_CAPACITY` | `100000` | Hot-tier resident capacity (HEA-1800) |
| `SEED_WAIT` | `1800` | Max seconds to wait for background corpus seeding to finish |
| `USERS_PER_REALM` | `80` | Token-pool user records (dev realm; drives the token journeys) |
| `SESSIONS_FRAC` | `0.5` | Fraction of users given a live token |
| `REVOKED_FRAC` | `0.1` | Fraction of live tokens pre-revoked |
| `SEED` | `1` | Determinism seed |
| `SETTLE` | `0` | Seconds to wait after seeding before the run. Default `0`: with rate limits disabled there is no admin-write window to wait out |
| `EXTRA_RUN_ARGS` | — | Extra flags appended to the `run` subcommand |

> **Rate limits are disabled by default.** The pipeline boots the throwaway
> server with `security.load_test_unthrottled: true`, which turns off the token,
> admin, export, and per-IP/per-realm request-shaper limiters so the run
> saturates the `validate_token` hot path instead of measuring a limiter. That
> flag is **dev-mode- and loopback-gated** (see [Rate limits](#rate-limits-on-a-dev-instance-why-you-throttle)):
> it is refused unless the server runs in `--dev` mode **and** every effective
> bind (HTTP and gRPC) is loopback, so it can never silently disable abuse
> protection on a production server — including one bound to loopback behind a
> reverse proxy.

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
(pin total requests/sec to a **specific offered load** — omit it, or the
pipeline's `THROTTLE=0` default, to run unthrottled and let `--users` decide the
load). A weight of `0` drops that journey entirely; at least one journey must be
weighted.

> **Loopback guard (HEA-1807).** Like the seed step, `run` refuses a non-loopback
> `--host` by default — a load run drives sustained traffic, so a remote target
> is a deliberate opt-in via `--allow-remote-target`
> (`HEARTH_LOADTEST_ALLOW_REMOTE_TARGET`), never the silent default. Use it only
> for an isolated lab instance you control.

> The default profile weights `validate` ≫ `session`/`user` ≫ `issuance` ≫
> `revoke`, so an unthrottled run pours load onto the `validate_token` hot path
> with issuance/revoke as small weighted slices — exactly the shape HEA-1796
> wants to saturate.

## Run modes (HEA-1791)

`--mode` selects the load profile. All modes write the same `report.json`
schema (below); ramp/soak add their extra sections.

| Mode | Flag | What it does | Extra flags |
|---|---|---|---|
| `steady` (default) | `--mode steady` | Fixed `--users` for `--run-time`. The primary report. | — |
| `ramp` | `--mode ramp` | Steps the user ladder upward and records the **saturation knee** — the first step where a budgeted journey's p99 breaches its HTTP budget. Stops early at the knee. | `--ramp-start-users` (10), `--ramp-step-users` (10), `--ramp-steps` (8) |
| `soak` | `--mode soak` | Long fixed-user run split into equal buckets, surfacing latency **drift** over time. Total time ≈ `soak_buckets × run_time`. | `--soak-buckets` (6) |
| `tier-miss` | `--mode tier-miss` | Corpus-scale `lookup_user` sweep split into a resident **hot** working set and a uniform **cold** draw, so the report splits hot-tier-hit from cold/SST-miss tail latency. Needs no seed-handle. | see the [tier-miss section](#tier-miss-mode-corpus-scale-per-tier-lookup-latency-hea-1801) |

```bash
make loadtest ARGS="run --mode ramp --ramp-start-users 20 --ramp-step-users 20 --ramp-steps 6"
make loadtest ARGS="run --mode soak --run-time 3m --soak-buckets 6"   # ≈ 18 min
```

## Tier-miss mode: corpus-scale per-tier lookup latency (HEA-1801)

The tier-miss profile proves the storage-engine claim that **lookup latency stays
flat as the corpus grows** — the counterpart to the high-concurrency rework
(HEA-1796, which stresses request *concurrency*). It drives the `lookup_user` hot
path via ROPC `POST /token` against the large bulk demo corpus, and self-attributes
every request to a storage tier **by construction**:

- **hot** — a fixed working set (`--tier-miss-hot-set-size`, default 10000)
  of user indices, hit repeatedly, so they stay resident in the hot tier.
- **cold** — a uniform draw across the whole corpus (`--tier-miss-corpus-size`).
  With the hot tier sized *below* the corpus (`storage.hot_tier_capacity`, see
  HEA-1800), most cold draws fall through to the cold/SST read path.

The proof is the **hot-vs-cold delta** and its stability across a corpus-size
sweep (`10000 → 100000 → 1000000`): if lookups are corpus-size independent, both
per-tier percentiles stay flat as the corpus grows.

> **Read the delta at p50/p95, not p99.** Every request pays a full ROPC Argon2id
> verify, which dwarfs the sub-ms storage lookup, so the storage-tier signal is a
> small slice of each timing. At the **p99 tail** the hot/cold ordering can even
> *invert* under Argon2id lock contention when many concurrent users hash the same
> resident accounts (HEA-1804) — which is why the default hot set is `10000` (keep
> it comfortably above `--users`). `hot_p50_ms`/`cold_p50_ms` and the p95 pair keep
> the correct ordering and are the fields to compare across the sweep.

### 1. Boot a below-working-set instance

Boot the demo config whose hot tier is deliberately capped below the working set
(streams 1M users on first boot; instant thereafter via a per-realm sentinel):

```bash
HEARTH_DEV_DATA_DIR=./data/tier-miss cargo run --release -- serve --dev \
    --config examples/large-scale-demo/hearth-tier-miss.yaml
```

Every seeded user shares one password (`demo.password`, default `DemoPassw0rd!`)
and has a deterministic email `user<7-digit-index>@bulk.demo`, so the generator
addresses any point in the corpus by index.

### 2. Find the realm UUID

Config-declared realms get a **random** v4 UUID at first boot (unlike deterministic
client IDs), so it must be discovered once, not defaulted. Bootstrap an admin token
and list realms, then pick the `bulk` realm's `id`:

```bash
TOKEN=$(curl -sf -X POST http://127.0.0.1:8420/admin/bootstrap | jq -r .access_token)
REALM_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
    http://127.0.0.1:8420/admin/realms | jq -r '.items[] | select(.name=="bulk") | .id')
```

The client is the deterministic `bulk-app` client declared in the config.

### 3. Run the tier-miss sweep

```bash
# Single run at 1M, hot tier capped at 100k (≈90% cold miss rate):
make loadtest ARGS="run --mode tier-miss \
    --tier-miss-realm-id $REALM_ID --tier-miss-client-id bulk-app \
    --tier-miss-corpus-size 1000000 --tier-miss-hot-tier-capacity 100000"

# Corpus-size sweep — run three times, the flat per-tier curve is the proof:
for N in 10000 100000 1000000; do
  make loadtest ARGS="run --mode tier-miss --report-dir loadtest/reports/tier-$N \
      --tier-miss-realm-id $REALM_ID --tier-miss-client-id bulk-app \
      --tier-miss-corpus-size $N --tier-miss-hot-tier-capacity 100000"
done
```

Key knobs (all `--tier-miss-*`, env `HEARTH_LOADTEST_TIER_*`): `realm-id` and
`client-id` (required), `corpus-size` (1M), `hot-set-size` (10000),
`hot-tier-capacity` (informational — recorded and used to estimate the cold miss
rate), `email-domain` (`bulk.demo`), and `weight-hot` / `weight-cold` (50/50;
set `--tier-miss-weight-hot 0` for a pure cold sweep).

For the shared corpus password, **prefer the `HEARTH_LOADTEST_TIER_PASSWORD` env
var over the `--tier-miss-password` flag** (HEA-1807) so the credential does not
land in shell history — e.g. `export HEARTH_LOADTEST_TIER_PASSWORD=…` before the
`make loadtest` line. The flag defaults to the demo config's well-known
`DemoPassw0rd!` purely so a zero-arg dev run works; override it via the env var
for any non-default corpus. (The value never spills to logs regardless — its
holder has no `Debug`.)

### 4. Read the per-tier split

Tier-miss runs add an additive `tier_miss` block to `report.json` (omitted for
every other mode, so existing consumers are unaffected):

```jsonc
"tier_miss": {
  "corpus_size": 1000000,
  "hot_working_set_size": 10000,
  "hot_tier_capacity": 100000,
  "hot_request_fraction": 0.5,       // by construction (weight_hot / total)
  "expected_cold_miss_rate": 0.9,    // 1 - min(1, capacity/corpus); an estimate,
                                     // not a server-observed counter
  "hot_p50_ms": 2,                   // hot-tier-hit  ┐ compare these: the median
  "cold_p50_ms": 4,                  // cold/SST-miss ┘ delta is the storage signal
  "hot_p95_ms": 3,                   // p95 keeps the ordering too
  "cold_p95_ms": 6,
  "hot_p99_ms": 8,                   // tail — can invert under Argon2id contention;
  "cold_p99_ms": 7,                  //        do NOT read the tier delta here
  "hot_max_us": 9100,
  "cold_max_us": 8400
}
```

The `lookup_hot` / `lookup_cold` journeys also appear as normal rows in the
`journeys` table (with the issuance budget, since each is a full `/token` call).
`expected_cold_miss_rate` is a **by-construction estimate** from capacity ÷ corpus,
not a per-request server signal — the HTTP client cannot see which tier served a
given lookup.

## Reading the report

Every run writes two artifacts into `--report-dir` (default `loadtest/reports/`,
which is **git-ignored**):

- `report.json` — the machine-readable report (schema below). This is the
  artifact a nightly diff consumes.
- `steady.html` / `ramp-{N}u.html` / `soak-bucket-{N}.html` — Goose's own HTML
  report(s) for eyeball inspection (traces, per-request timelines). Goose measures
  every response time in whole milliseconds, so its Request Metrics `Min`/`Max`
  and its Response Time Metrics percentile table render Hearth's sub-ms hot path
  as a flat `1`. The harness records a per-journey microsecond histogram and
  post-processes each report to rewrite those two tables — Request `Min`/`Max` and
  every percentile column (50/60/70/80/90/95/99/100), per journey and aggregate —
  at microsecond resolution. All other tables (transactions, scenarios, status
  codes) and the `Users:` count are Goose's own; `Users:` is the `--users`
  concurrency the run used (default 50).

`report.json` shape (`schema` is [`report::SCHEMA_VERSION`](src/report.rs) —
bumped on any breaking change so a nightly diff refuses to compare across
incompatible schemas):

| Field | Meaning |
|---|---|
| `schema` | Report schema version (currently `2`; a nightly diff refuses to compare across versions). |
| `metadata.git_sha` | Build commit (`HEARTH_GIT_SHA` env override, else `git rev-parse`, else `"unknown"`). |
| `metadata.timestamp_unix` | Wall-clock the report was produced. |
| `metadata.{mode,host,seed,dataset_shape,users,run_time,hatch_rate}` | Run configuration + the corpus it ran against. |
| `summary.achieved_users` | Peak concurrent Goose users the run actually reached. |
| `summary.achieved_rps` | Achieved aggregate requests/sec (all journeys, total ÷ duration). |
| `summary.{total_requests,total_failures,failure_rate}` | Aggregate volume + failure fraction. |
| `summary.ceiling` | **Ceiling attribution** (HEA-1796): `server` (a budget p99 breached — the server is the limiter), `load_generator_or_headroom` (no breach, negligible failures — the server kept up, so raise `--users`), or `generator_saturated` (elevated failures with no latency breach — the load generator/host ran out of ports/fds; tune it and re-run). |
| `summary.ceiling_reason` | Human-readable rationale for the `ceiling` verdict. |
| `journeys[]` | Per-journey rows (sorted by name for diff-stable output). |
| `journeys[].{p50,p95,p99,p999}_ms` | Response-time percentiles (whole ms — Goose's granularity). |
| `journeys[].{min_us,max_us}` | Fastest / slowest observed request, in **microseconds**. The generator times each request itself, so these keep sub-ms precision Goose's whole-ms min/max rounds away (a 0.1 ms request is `100`, not `0`). Omitted for a journey with no recorded sample. |
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
can report is 1 ms (the percentile columns therefore only ever resolve to whole
ms — for sub-ms extremes read `min_us` / `max_us`, which the generator measures
at microsecond resolution); ordinary loopback scheduling jitter puts observed p99 at
2–3 ms, which exceeds the sub-ms `session`/`user`/`validate` budgets even though
the engine itself is well under target. `issuance` likewise blows its 6 ms
budget because the HTTP path runs a **real Argon2id** password hash (10–22 ms)
that the in-process engine bench does not. The committed
[baseline](#the-committed-baseline) is a clean, zero-failure run that still
reports `pass:false` for exactly these reasons — the budgets are an aspirational
engine-level ceiling, and this HTTP harness is a **drift detector and capacity
probe**, not a sub-ms pass gate. Sub-ms verification lives in the in-process
`make bench-gate`, not here.

## Rate limits: disabled for load tests (`security.load_test_unthrottled`)

A dev boot normally enforces per-client rate limits that a load run trips
immediately, because every journey authenticates as the **single** dev client:

- **Token endpoint** (`/token`, `/introspect`, `/revoke`): 200 req/min per
  client (`TOKEN_RATE_LIMIT`). `validate` + `issuance` + `revoke` share it.
- **Admin writes** (`/admin/users`, …): 100 req/min per admin
  (`ADMIN_RATE_LIMIT`). Bounds both the seed and `user_lookup`.
- **Export**: 1/hour per admin (`EXPORT_RATE_LIMIT`).
- **Per-IP / per-realm request shaper**: 100 req/s per source IP by default.

Rate limiting works **against** what a load test measures — a limited run is
dominated by `429`s rather than the `validate_token` hot path. So HEA-1796 adds a
config escape hatch:

```yaml
# loopback dev only — never production
security:
  load_test_unthrottled: true
```

When set, it swaps the token, admin, export, **and** request-shaper limiters for
no-op `disabled()` variants, so the run saturates the hot path with no limiter in
the way. `make loadtest` writes this into the throwaway config automatically —
you do not set it by hand for the standard pipeline.

### Why this is production-safe

The flag is **dev-mode- and loopback-gated at boot** (`loadtest_unthrottle_decision`
in `src/main.rs`, unit-tested):

- **Flag unset** → every limiter stays on (normal operation). Default is `false`.
- **Flag set + `--dev` + all binds loopback** (`127.0.0.0/8`, `::1`, or
  `localhost`; the gRPC bind is checked too when the gRPC listener is enabled) →
  limiters disabled; boot logs a **loud `WARN`** naming every disabled limiter.
- **Flag set but not `--dev`** → **refused, fail-safe**: limiters stay **on** and
  boot logs an `ERROR`. A loopback bind can still be internet-reachable behind a
  reverse proxy, so unthrottled load testing is dev-only.
- **Flag set + any non-loopback bind** (HTTP or gRPC, including wildcard
  `0.0.0.0` / `::`) → **refused, fail-safe**: limiters stay **on** and boot logs
  an `ERROR`.

So a production server — whether it binds a routable address directly or sits on
loopback behind a proxy — can never silently ship with brute-force / abuse
protection removed, even if the flag is set by mistake. The gate also covers a
gRPC listener whose bind diverges from the HTTP bind. This mechanism was reviewed
by SecurityAuditor (HEA-1797).

## Driving high concurrency (fan-out) and finding the knee

`steady` mode at a high `--users` **is** the concurrent fan-out shape — there is
no separate "fanout" mode. To push a single node toward its ceiling:

```bash
# Concurrent fan-out: thousands of simultaneous virtual users, unthrottled.
make loadtest USERS=10000 HATCH_RATE=500 RUN_TIME=3m
# Find the p99-breach knee under rising RPS:
make loadtest MODE=ramp EXTRA_RUN_ARGS="--ramp-start-users 500 --ramp-step-users 500 --ramp-steps 20"
```

**Read `summary.ceiling` first.** It tells you honestly whether the number you
got is the *server's* ceiling or the *load generator's*:

- `server` — a budgeted journey's p99 breached; the server is the limiter. In
  `ramp` mode `knee_rps` is the RPS at that step.
- `load_generator_or_headroom` — no breach, failures negligible: the server kept
  up. You have **not** found the server ceiling — raise `USERS`.
- `generator_saturated` — elevated failures with no latency breach: the generator
  ran out of resources. Tune the host (below) and re-run before trusting numbers.

### Load-generator tuning (so the generator isn't the bottleneck)

A single box driving tens of thousands of connections to itself needs OS tuning,
or it — not Hearth — becomes the ceiling:

```bash
ulimit -n 1048576                                   # file descriptors (sockets)
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"   # more ephemeral ports
sudo sysctl -w net.ipv4.tcp_tw_reuse=1              # reuse TIME_WAIT sockets
```

Pin the server and goose to **disjoint CPU cores** so the generator does not
starve the server (or vice-versa):

```bash
taskset -c 0-3  hearth serve --dev --config hearth-loadtest.yaml   # server: cores 0-3
taskset -c 4-15 hearth-loadtest run --users 10000 ...              # goose: cores 4-15
```

For a realistic *high-throughput* run the token cap (now disabled) is no longer
the constraint; spread live tokens across many subjects via the multi-subject
attach path below for a more representative corpus.

## ⚠️ Security warnings (read before running)

- **Dev / loopback only — enforced at runtime.** The seed step calls
  `POST /admin/bootstrap`, mints live tokens, and revokes them. It **refuses
  any non-loopback `--target-host`** unless you pass the explicit
  `--allow-remote-target` opt-in; use that only for an isolated lab instance
  you control, never a shared or production instance — it would create real
  users and tokens and could exhaust admin rate limits. (Production servers
  fail closed anyway: `/admin/bootstrap` is disabled outside `--dev` mode, so
  the flow dies at step 1 before any credential is sent.)
- **`run` refuses a non-loopback `--host` too (HEA-1807).** A load run drives
  sustained traffic, so — like `seed` — a remote target requires the explicit
  `--allow-remote-target` opt-in (isolated lab only). Prefer sourcing
  `--tier-miss-password` from `HEARTH_LOADTEST_TIER_PASSWORD` so the corpus
  credential stays out of shell history.
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

> **Note (HEA-1796):** the committed baseline is a `schema:1`, throttled 20-user
> run. The report schema is now `2` (adds the `summary`/ceiling block) and the
> pipeline now runs **unthrottled**, so that baseline is stale and the nightly
> diff refuses to compare across schema versions by design. The canonical
> `schema:2` baseline is regenerated from a high-concurrency verification run
> (owned by the HEA-1796 QA child) using the steps below.

How it is captured (reproducible — the pipeline sets `load_test_unthrottled`
itself, so no manual config or settle wait):

```bash
# Boot + seed + run + report in one shot, unthrottled:
make loadtest MODE=steady USERS=200 RUN_TIME=90s HATCH_RATE=50
# Copy the fresh report over the baseline (zero out volatile metadata):
#   cp loadtest/reports/report.json loadtest/baseline/steady-baseline.json
#   then set metadata.timestamp_unix to 0 and metadata.git_sha to the capture commit.
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
