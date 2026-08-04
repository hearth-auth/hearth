# HEA-1970 — Saturation rig dry-run (loopback, ungradable by design)

**Date:** 2026-07-31 · **Host:** dev laptop (co-resident generator — ungradable)
**Purpose:** answer "does the loadtest fully saturate now?" by *running* the two-host
rig end-to-end on loopback before spending the droplet booking, rather than reading
the runbook and asserting readiness.

**Answer: no.** No saturation measurement exists anywhere. The first end-to-end
execution of the HEA-1997 rig found four blockers, one of which silently produces a
100%-failure plane and one of which would have made the measured phase report the
rate limiter as the server's knee.

---

## What works

| Check | Result |
|---|---|
| `cargo test --example http_saturation` | **18 passed, 0 failed** |
| Loopback refusal fires in practice | ✅ refuses to grade `127.0.0.1:8422` without `--allow-loopback` |
| Attribution gate | ✅ every rung graded `INCOMPLETE` (no server-CPU sampler) — never silently `ADMISSIBLE` |
| `read` plane | ✅ 5000/5000 2xx, 0 transport errors · p50 **0.83 ms** · p99 **1.44 ms** @1000 rps offered |
| `issuance` plane (HEA-2003 production `client_credentials`) | ✅ 5000/5000 2xx, 0 errors · p50 **4.90 ms** · p99 **6.98 ms** @1000 rps offered |

Those are co-resident loopback numbers at a 1000 rps rung with `max_backlog` 1 —
**nowhere near a knee**. They are evidence the plumbing works, not capacity figures.

## Blocker 1 — `login`/KDF plane fails 100% of requests (404)

Measured: `error_rate: 1.0`, `non_2xx: 5000`, `p50 0.628 ms` — far too fast to be
Argon2id, because no password is ever verified.

`examples/http_saturation.rs:384` builds the path from the realm **UUID**:

```rust
let login_path = format!("/ui/realms/{}/login", realm.realm_id);
```

The route (`src/protocol/web/mod.rs:820`, nested under `/ui` at `mod.rs:1625`) is
keyed by realm **name**, not id. Verified against the live server:

| Path | GET | POST |
|---|---|---|
| `/ui/realms/9a35bdcf-…/login` (what the harness sends) | 404 | **404** |
| `/realms/9a35bdcf-…/login` | 404 | 404 |
| `/ui/realms/dev-realm/login` (correct) | 200 | **303** + `hearth_ui_session` cookie |

The seeded credential is fine — correct password → 303 with a session cookie, wrong
password → 401. Only the path is wrong. This is HEA-1995 repeating: HEA-1998 shipped
the seeding and the plane was never fired.

## Blocker 2 — the measured phase cannot be unthrottled, so the rig would measure the limiter

`security.load_test_unthrottled` is gated on `--dev` **and** all-loopback binds
(`src/main.rs:2131-2149`). Runbook phase 3B deliberately runs **without `--dev`, bound
to `0.0.0.0`** — so both `RefusedNotDev` and `RefusedNonLoopback` fire and the
limiters stay **enabled**. `RequestShaper` then runs at its defaults
(`src/config/types.rs:1423-1428`):

- `ip_rps` = **100**
- `realm_rps` = **1000**

The generator is a single source IP, and the runbook's own example rungs are
`500,1000,2000,4000,8000`. Every rung above 100 rps is shed by the shaper, so the
"knee" the harness reports is the rate limiter, not the server.

This needs an explicit decision (raise `security.request_shaper` on the measured
host and record it, or extend the unthrottle gate to a private-interface case) —
not a silent workaround.

## Blocker 3 — runbook §3A's server command cannot start

`--bind 127.0.0.1:8420` (the form the runbook prescribes) is **refused** by the
HEA-1980 dev gate. `dev_mode_bind_check` (`src/main.rs:705-711`) parses the whole
string as an `IpAddr`, so any `host:port` value fails to parse and falls through
`unwrap_or(false)` → "not loopback":

```
ERROR hearth: dev mode refused: all effective binds must be loopback (HEA-1980).
  bind_address=127.0.0.1:8422 grpc_bind_address="127.0.0.1"
```

`--bind 127.0.0.1 --port 8422` starts fine. Fail-closed, so not a security hole —
but the gate rejects a legitimate loopback bind, and the runbook only uses the
rejected form.

## Blocker 4 — runbook §3A's seed command is wrong twice

1. `make seed ARGS="--target http://…"` → `error: unexpected argument '--target' found`.
   The flag is `--target-host`.
2. Seeding without `security.load_test_unthrottled: true` dies at
   `create_user failed: HTTP 429: rate limit exceeded` (reproduced at 2000 users).
   The runbook's `hearth.yaml` excerpt pins only `data_dir` and the KEK.

With both corrected, seeding 1000 users + 1000 tokens + 1000 sessions + the
confidential `client_credentials` client succeeds.

---

## Reproduction

```bash
export PROTOC=$(which protoc) CARGO_TARGET_DIR=/scratch/cache/target RUSTC_WRAPPER=""
cargo build --bin hearth --example http_saturation
cargo build --manifest-path loadtest/Cargo.toml --bin hearth-loadtest

# hearth.yaml copy with `security.load_test_unthrottled: true`
hearth serve --dev -c hearth-unthrottled.yaml --bind 127.0.0.1 --port 8422 &

HEARTH_LOADTEST_LOGIN_PASSWORD='…' hearth-loadtest seed \
  --target-host http://127.0.0.1:8422 --seed-out seed.json \
  --realms 1 --users-per-realm 1000 --sessions-frac 1.0

for P in read issuance login; do
  http_saturation --target http://127.0.0.1:8422 --seed-handle seed.json --plane $P \
    --rungs 200,1000 --hold 5 --conns 64 --allow-loopback --login-password '…'
done
```
