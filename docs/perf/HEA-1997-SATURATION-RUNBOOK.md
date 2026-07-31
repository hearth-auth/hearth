# HEA-1997 — Two-host HTTP saturation runbook

**Purpose.** Produce the capacity number Hearth has never had: **requests/s before
it falls over**, end-to-end over HTTP, on a rig where the generator provably is
**not** the ceiling. This is the number the board asked for on HEA-1970 and the one
directly comparable to competitors (who all publish end-to-end HTTP capacity).

**Harness.** `examples/http_saturation.rs` — open-loop, fixed-rate ramp with
coordinated-omission-corrected latency and mandatory per-rung bottleneck attribution.
Logic is unit-tested (`cargo test --example http_saturation`); this runbook is the
operational half.

**Cost envelope.** **Two** droplets, a few hours, ~$4. Share the booking with the
HEA-1970 single-host run (do them back-to-back on one booking — cheapest). Destroy
both when artifacts are copied back.

---

## 0. Why two hosts and open-loop (do not shortcut this)

- **Two hosts is non-negotiable.** Generator/server co-residency is the confirmed,
  repeatedly-observed ceiling: HEA-1871 (C3) bisected the throughput cliff to the
  server side only after removing the generator; HEA-1876 (C8) could not seed before
  co-residency voided the run; HEA-1989 hit 100% connect errors while server CPU
  *fell*. The harness **refuses to grade a loopback target** — you must point it at a
  remote host.
- **Open-loop, not a user count.** A closed-loop generator (Goose) cannot tell
  "server is slow" from "generator is waiting"; adding users just deepens the
  client's queue. This harness fires at a fixed offered rate and measures latency
  from each request's *intended* send time.
- **The KDF plane throttles a blended run.** Issuance runs p50 ~2 s behind a
  deliberate Argon2id admission gate; in a blended closed-loop mix it parks ~89% of
  generator capacity in the KDF queue and the read plane never sees real load. That
  is why we measure **per plane** first, then blend.

---

## 0a. Which planes this rig can measure (READ THIS FIRST — HEA-2002)

The HEA-1980 startup gate refuses `--dev` with **any** non-loopback bind, at two
layers (`src/main.rs` `dev_mode_bind_check` **and** `src/config/validate.rs`),
because `--dev` registers unauthenticated endpoints (`/admin/bootstrap`,
`/dev/seed-session`, `/dev/seed-token`, `/dev/seed-password`). On a routable
interface `/dev/seed-password` alone is instance-wide account takeover. **The gate
is correct and is not weakened here** — the runbook works *around* it, it does not
punch a hole in it.

That splits the planes by whether they touch a `/dev/*` endpoint at **run** time:

| Plane | Run-time endpoints | Two-host on this rig? |
|---|---|---|
| `read` | `/introspect`, `/userinfo`, `/admin/users/{id}` | **Yes** — tokens + admin token come from the seed handle |
| `login` (KDF) | `POST /ui/realms/{r}/login` | **Yes** — real login, nothing dev-only |
| `issuance` | `POST /token` (`grant_type=client_credentials`) | **Yes (HEA-2003)** — production grant; the confidential client is in the seed handle |
| `blended` | read + `POST /token` + login | **Yes (HEA-2003)** — all three are production endpoints |

**HEA-2003 removed the last dev dependency.** The `issuance` plane now mints over
the **production** `POST /token` (`grant_type=client_credentials`), not the dev-only
`/dev/seed-token`. The seeder registers a confidential `client_credentials` client
during the loopback seed phase (over DCR, since the admin `POST /clients` handler
strips secrets) and carries its `client_id` + `client_secret` in the seed handle —
so at run time host B needs no `/dev/*` route. `blended` inherits this and is
likewise runnable. **Do not** re-add `--dev --bind 0.0.0.0` for issuance — that is
the exact risk vector HEA-1980 closes, and it is no longer needed.

This rig therefore delivers **all four** planes: the **read** knee (the
competitor-comparable number), the **login/KDF** benchmark, the **issuance** knee,
and the **blended** operator-facing mix.

---

## 1. Provision

- **Provider/plan:** DigitalOcean **CPU-Optimized (Dedicated vCPU)** ×2 — *not*
  shared. Shared vCPU steals cycles invisibly to `loadavg` (see HEA-1970 note).
- **Host A (server):** 8–16 vCPU / 16–32 GB. Runs Hearth.
- **Host B (generator):** same or larger. Runs `http_saturation`. It must have
  **≥ 2× the CPU headroom** it consumes — the harness enforces this per rung; if
  host B is too small every rung grades INADMISSIBLE.
- Same VPC / same region, private networking on. Record the private IP of host A.

## 2. Build

On **both** hosts (or build once and `scp` the binary + a seed handle):

```bash
export PROTOC=$(which protoc)
cargo build --release --example http_saturation      # host B (generator)
cargo build --release                                # host A (hearth) + seeder
```

## 3. Host A — seed over loopback, then serve on the private interface

The corpus is seeded with `--dev` (the `/admin/bootstrap` + `/dev/seed-*` endpoints
are dev-only) **bound to loopback**, then the server is restarted **without `--dev`**
on the private interface for the measured run. The two phases share **one
`hearth.yaml`** so the on-disk corpus written in phase 3A is readable in phase 3B.

**Config parity is load-bearing.** `serve --dev -c hearth.yaml` preserves
`storage.data_dir` and `security.key_encryption_key` from the file and only flips
`dev_mode=true` + `storage.fsync=false` (`Config::from_file_as_dev`). If the KEK or
`data_dir` differed between the two phases, the persisted Ed25519 signing keys would
not decrypt and every seeded token would fail validation after the restart. So the
`hearth.yaml` you use **must** pin both, and both phases must use the **same file**:

```yaml
# hearth.yaml (excerpt) — both phases use THIS file
storage:
  data_dir: /var/lib/hearth-loadtest      # persists across the mode switch
security:
  key_encryption_key: ${HEARTH_KEK}       # identical in both phases (env-substituted)
```

### 3A. Seed phase — `--dev`, loopback only

```bash
export HEARTH_KEK=...                      # 32-byte hex; keep it out of shell history
# Loopback bind keeps the gate satisfied; --dev enables /admin/bootstrap + /dev/seed-*.
./target/release/hearth serve --dev -c hearth.yaml --bind 127.0.0.1:8420 &

# Seed the corpus and write the handle (see loadtest/README.md for ARGS).
# For the login/KDF plane, seed a known password via the env form (NOT a CLI flag,
# which is visible in `ps` / shell history).
export HEARTH_LOADTEST_LOGIN_PASSWORD='L0adT3st!KnownPassword'   # throwaway lab cred; must clear realm policy
make seed ARGS="--target http://127.0.0.1:8420 --seed-out /shared/seed.json \
  --realms 1 --users-per-realm 5000 --sessions-frac 1.0"

# Graceful stop so the memtable flushes to SST (phase 3A runs fsync=false).
kill -TERM %1 && wait      # or `hearth stop` if you started it under a service manager
```

Copy `/shared/seed.json` to host B (it carries live bearer tokens, the admin token,
**and the issuance client's `client_secret`** (HEA-2003) — treat it as a secret, `scp`
over the private network, `chmod 600`). The seeder registers that confidential
`client_credentials` client automatically during this phase (briefly enabling DCR on
the dev-realm and restoring it to `disabled` afterward — no residual exposure on the
phase-3B server); no operator action is required. The seeded
password is **not** written to the handle (secrets discipline); it lives only on the
server as a credential and you supply it to the harness separately (§5).

### 3B. Serve phase — NO `--dev`, private interface

```bash
# Same config file, same data_dir + KEK, but production mode: the /dev/* and
# /admin/bootstrap routes are absent, and the bind may be non-loopback.
export HEARTH_KEK=...                      # same value as phase 3A
./target/release/hearth serve -c hearth.yaml --bind 0.0.0.0:8420 &

# REQUIRED smoke check — prove the corpus survived the mode switch before you
# spend droplet-hours. Pick any live token from the seed handle and introspect it
# over loopback on host A. `active:true` ⇒ KEK/data_dir parity held; anything else
# ⇒ fix config parity (§3) before running the ramp.
TOK=$(jq -r '[.realms[0].tokens[] | select(.revoked | not) | .access_token][0]' /shared/seed.json)
CID=$(jq -r '.realms[0].client_id' /shared/seed.json)
curl -sf -X POST http://127.0.0.1:8420/introspect \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOK\",\"client_id\":\"$CID\"}" | jq '.active'   # expect: true
```

### 3c. Server-CPU sampler (REQUIRED for an ADMISSIBLE grade)

The harness cannot read host A's CPU across the network. Run a 1 Hz sampler on host A
that rewrites a single number (busy %) to a file the harness reads at the end of each
rung. **Without this file every rung grades INCOMPLETE, never ADMISSIBLE** — you get
no publishable knee.

```bash
# Emit host-A total CPU busy % once per second to a file, hosted where host B
# can read it (shared volume, or scp-loop, or an ssh-tail from host B).
while true; do
  read -r _ u n s i _ < /proc/stat
  # crude instantaneous busy%: 100 - idle-share over the tick
  mpstat 1 1 | awk '/Average/ && $2=="all" {printf "%.1f\n", 100-$NF}' > /shared/hostA-cpu.txt
done
```

Any sampler works as long as the **last whitespace-delimited token in the file is the
busy percentage**. `pidstat -p $(pgrep -x hearth) 1` (process-only) is acceptable and
arguably better — note in the artifact which you used.

## 4. Host B — run the read ramp

```bash
T=http://<HOST_A_PRIVATE_IP>:8420
CPU=/shared/hostA-cpu.txt

# Read plane — the competitor-comparable number.
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane read \
  --rungs 1000,2000,4000,8000,16000,32000 --hold 30 --warmup 5 --conns 512 \
  --server-cpu-file $CPU > sat-read.json
```

The `issuance` and `blended` planes are also runnable here (HEA-2003) — they mint
over the production `POST /token` grant using the confidential client the seeder put
in the handle, so nothing dev-only is touched:

```bash
# Issuance plane — Ed25519 sign + grant-family WAL write, over POST /token.
# Argon2id is NOT on this path (it is a write/issuance number, not a KDF one).
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane issuance \
  --rungs 500,1000,2000,4000,8000 --hold 30 --warmup 5 --conns 256 \
  --server-cpu-file $CPU > sat-issuance.json

# Blended — the realistic operator-facing 90/8/2 read/issuance/login mix.
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane blended \
  --login-password "$KNOWN_PW" \
  --rungs 1000,2000,4000,8000,16000 --hold 30 --warmup 5 --conns 512 \
  --server-cpu-file $CPU > sat-blended.json
```

If the handle predates HEA-2003 (no `cc_client_id`/`cc_client_secret`), the issuance
and blended planes error out by design — re-seed with a current seeder. `blended`
without `--login-password` runs read+issuance only (its login slice is skipped).

**Ramp discipline:** start below the expected knee and step up. The knee is the
**highest ADMISSIBLE rung whose achieved rate kept up with offered** (`knee_index` in
the artifact). If the top rung is still ADMISSIBLE and keeping up, you have not found
the knee — add higher rungs.

## 5. The login / KDF plane

The KDF plane measures Argon2id login throughput over HTTP and **must be labelled a
KDF benchmark** in any report. It needs users seeded with a **known password** — set
via `HEARTH_LOADTEST_LOGIN_PASSWORD` in §3A above (the seeder applies it to every
seeded user via the dev-only `POST /dev/seed-password`, over loopback). It uses
`POST /ui/realms/{r}/login`, a production endpoint, so it runs against the
non-`--dev` server from phase 3B with nothing dev-only at run time.

On host B, pass the same known password to the harness. Note the harness reads it as
a CLI flag (visible in `ps`); keep it a throwaway lab credential and clear your shell
history after the run:

```bash
KNOWN_PW='L0adT3st!KnownPassword'   # same value you seeded in §3A
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane login \
  --login-password "$KNOWN_PW" --rungs 50,100,200,400 --hold 30 --conns 64 \
  --server-cpu-file $CPU > sat-login.json
```

Without a seeded password, users have no credential and `--plane login` errors out by
design; the read plane is unaffected.

Keep the login ladder short and shallow — Argon2id is ~10–30 ms of CPU behind a
bounded admission gate, so high rungs just fill the shed queue.

## 6. Rate limiter — record the decision

`security.load_test_unthrottled` requires `--dev` **AND** every effective bind
loopback (`src/main.rs`). The measured run in phase 3B is **not** `--dev` and binds
the private interface, so the escape hatch **cannot** be enabled and limiters stay
**ON**. That is deliberate — we report what the product actually does — but it means
the observed ceiling may be Hearth's own limiter (429s), not CPU. The artifact stamps
`limiter: "on"`. When you write the report you **must** state which resource
saturated first, read from the attribution fields:

- `server_cpu_pinned: true` + `degrading_by_queueing: true` + no 429s ⇒ **CPU-bound**;
  the knee is a real hardware capacity number.
- non-2xx dominated by **429** while `server_cpu_pct` well under 90 ⇒ **limiter-bound**;
  report it as "capacity at the configured limiter setting", not hardware capacity,
  and note the limiter config.

## 7. Copy back, grade, publish

- Copy `sat-*.json` back before destroying the droplets.
- For each plane report: **knee throughput**, **p50/p99 at the knee**, and the
  **degradation shape past it** (`degradation_shape`: graceful vs cliff) — all emitted
  fields.
- Update `docs/perf/PUBLISHED_FIGURES.md` §3.3: replace the "no HTTP capacity claim"
  statement with the measured knee(s) — **read**, **login/KDF**, **issuance**, and
  **blended** from this rig — each with plane label, host, artifact + SHA, and the
  limiter/CPU attribution. The login number carries an explicit "KDF benchmark" label;
  the issuance number is a write/issuance figure (Ed25519 + WAL), **not** a KDF one.
- Tell HEA-1968 exactly which figures (if any) it may quote.

## 8. Admissibility cheat-sheet (what the harness enforces per rung)

| Field | ADMISSIBLE requires |
|---|---|
| `server_cpu_pinned` | host-A CPU ≥ 90% (needs `--server-cpu-file`; absent ⇒ INCOMPLETE) |
| `generator_headroom_2x` | host B used ≤ 50% of its CPU (headroom ratio ≥ 2.0) |
| `transport_clean` | zero connect/transport errors |
| `degrading_by_queueing` | non-2xx rate ≤ 0.5% (ceiling is latency, not an error cliff) |

A rung failing any of these is emitted `INADMISSIBLE` (or `INCOMPLETE`), **never
silently included** in a published knee.
</content>
</invoke>
