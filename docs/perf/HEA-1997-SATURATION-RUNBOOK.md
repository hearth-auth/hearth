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

## 3. Host A — start Hearth and seed the corpus

```bash
# Bind on the PRIVATE interface so host B can reach it. Limiters stay ON (see §6).
./target/release/hearth serve --dev --bind 0.0.0.0:8420   # or config bind

# Seed a corpus and write the handle (see loadtest/README.md for ARGS).
make seed ARGS="--target http://127.0.0.1:8420 --seed-out /shared/seed.json \
  --realms 1 --users-per-realm 5000 --sessions-frac 1.0"
```

Copy `/shared/seed.json` to host B (it carries live bearer tokens + the admin token
— treat it as a secret, `scp` over the private network, `chmod 600`).

### 3a. Server-CPU sampler (REQUIRED for an ADMISSIBLE grade)

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

## 4. Host B — run the ramp, per plane

```bash
T=http://<HOST_A_PRIVATE_IP>:8420
CPU=/shared/hostA-cpu.txt

# Read plane — the competitor-comparable number.
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane read \
  --rungs 1000,2000,4000,8000,16000,32000 --hold 30 --warmup 5 --conns 512 \
  --server-cpu-file $CPU > sat-read.json

# Issuance/write plane (session-create + Ed25519 + WAL fsync; NOT the KDF).
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane issuance \
  --rungs 200,500,1000,2000,4000 --hold 30 --conns 256 \
  --server-cpu-file $CPU > sat-issuance.json

# Blended sizing mix (90/8/2 read/issuance/login).
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane blended \
  --rungs 1000,2000,4000,8000 --hold 30 --conns 512 \
  --server-cpu-file $CPU > sat-blended.json
```

**Ramp discipline:** start below the expected knee and step up. The knee is the
**highest ADMISSIBLE rung whose achieved rate kept up with offered** (`knee_index` in
the artifact). If the top rung is still ADMISSIBLE and keeping up, you have not found
the knee — add higher rungs.

## 5. The login / KDF plane

The KDF plane measures Argon2id login throughput over HTTP and **must be labelled a
KDF benchmark** in any report. It needs users seeded with a **known password**. As of
HEA-1998 the seeder can provision one: pass `--login-password` to the seed step, which
sets that exact password on every seeded user via the dev-only
`POST /dev/seed-password` endpoint. Re-run the §3 seed with the flag added (the same
`$KNOWN_PW` you will pass to the harness):

```bash
KNOWN_PW='L0adT3st!KnownPassword'   # throwaway lab credential; must clear the realm policy
make seed ARGS="--target http://127.0.0.1:8420 --seed-out /shared/seed.json \
  --realms 1 --users-per-realm 5000 --sessions-frac 1.0 --login-password $KNOWN_PW"
```

The password is **not** written to the seed handle (secrets discipline) — it lives only
on the server as a credential; you supply it to the harness separately. Then, on host B:

```bash
./target/release/examples/http_saturation \
  --target $T --seed-handle /shared/seed.json --plane login \
  --login-password "$KNOWN_PW" --rungs 50,100,200,400 --hold 30 --conns 64 \
  --server-cpu-file $CPU > sat-login.json
```

Without `--login-password` at seed time, users have no credential and
`--plane login` errors out by design; the read / issuance planes are unaffected.

Keep the login ladder short and shallow — Argon2id is ~10–30 ms of CPU behind a
bounded admission gate, so high rungs just fill the shed queue.

## 6. Rate limiter — record the decision

`security.load_test_unthrottled` requires `--dev` **AND** every effective bind
loopback (`src/main.rs`), so a two-host rig **cannot** disable the request shaper.
Limiters stay **ON**. That is deliberate — we report what the product actually does —
but it means the observed ceiling may be Hearth's own limiter (429s), not CPU. The
artifact stamps `limiter: "on"`. When you write the report you **must** state which
resource saturated first, read from the attribution fields:

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
  statement with the measured knee(s), each with plane label, host, artifact + SHA,
  and the limiter/CPU attribution. The KDF/login number carries an explicit
  "KDF benchmark" label.
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
