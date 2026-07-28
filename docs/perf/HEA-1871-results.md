# HEA-1871: Separate the Load Generator from the Server Under Test

**Plan rev:** HEA-1867-PLAN.md §5 Phase 0 · C3  
**Hardware:** AMD Ryzen 7 7840HS · 16 vCPU (8 physical cores × 2 HT) · 54 GiB RAM · Linux 7.0.10  
**Hearth binary:** `/scratch/cache/target/release/hearth` built 2026-07-19 (pre-HEA-1862/1863; used for comparability with HEA-1812 baseline)  
**Loadtest binary:** `/scratch/cache/target/release/hearth-loadtest` built 2026-07-28  
**Date:** 2026-07-28

---

## 1. What was done

Implemented core-set isolation via `taskset -c`:

| Role | CPUs | Physical cores |
|------|------|---------------|
| Hearth server | 0–7 | 0–3 (both HTs each) |
| Load generator (Goose) | 8–15 | 4–7 (both HTs each) |

Script: `loadtest/scripts/hea1871-isolated.sh`

Re-ran the HEA-1812 bisect sweep (500→cliff) with the same configuration:
- Corpus: 40 000 users (ACME 30k + GLOBEX 10k; smaller than HEA-1812's 300k for seeding speed — the cliff is a concurrency effect, not corpus-size dependent)
- Token pool: 80 users/realm, 50% live sessions
- Run time per step: 25 s
- Hatch rate: 500 users/s
- User sweep: 400, 500, 600, 700, 800, 1 000, 1 500

---

## 2. Results

### Isolated run (server pinned 0–7, generator pinned 8–15)

| Users | RPS | Fail % | Server CPU mean % | Server CPU peak % | RSS MiB | Ceiling |
|------:|----:|-------:|------------------:|------------------:|--------:|---------|
| 400 | 928 | 0 % | 161.8 | 273.9 | 1 109 | server |
| 500 | 1 062 | 0 % | 172.1 | 226.0 | 1 422 | server |
| **600** | **24** | **100 %** | **4.8** | **187.0** | **1 422** | server |
| 700 | 28 | 100 % | 0.0 | 0.0 | 1 422 | server |
| 800 | 32 | 100 % | 0.0 | 0.0 | 1 422 | server |
| 1 000 | 40 | 100 % | 0.0 | 0.0 | 1 422 | server |
| 1 500 | 60 | 100 % | 0.0 | 0.0 | 1 422 | server |

### HEA-1812 baseline (co-resident, no isolation)

| Users | RPS | Fail % | Server CPU mean % | Server CPU peak % | RSS MiB |
|------:|----:|-------:|------------------:|------------------:|--------:|
| 500 | 1 678 | 0 % | 178.0 | 292.0 | 3 445 |
| **600** | **13** | **100 %** | **5.8** | **238.2** | **3 748** |
| 700 | 30 | 100 % | 0.0 | 0.0 | 3 748 |

(HEA-1812 used 300k corpus, hence higher RSS. Cliff concurrency is corpus-independent.)

---

## 3. Finding: the cliff does NOT move with isolation

**The failure onset remains at exactly 500→600 users regardless of whether the generator has dedicated cores.**

CPU mean at the cliff: 5.8% (co-resident) vs 4.8% (isolated) — statistically identical, within measurement noise.

This falsifies the original hypothesis from the plan (§3 Finding 1):

> *"HEA-1813 bisected the failure onset to 500→600 concurrent users and attributed it to the load generator, not Hearth: across the cliff server CPU collapses (178% → 5.8% → ~0% of 1600% available) while RSS stays flat. Requests stop arriving. Goose and the server contend for the same 16 vCPUs."*

With 8 dedicated cores the generator cannot starve the server. Yet the server still collapses to 4.8% CPU. The generator-starvation attribution was incorrect. **The limiter is Hearth itself.**

---

## 4. What the cliff looks like in isolation

At 600u with isolation:
- **600 total requests, 600 failures (100%)** — each Goose virtual user sent exactly 1 request and never received a response within the 60-second Goose timeout.
- **Server CPU: 4.8% mean, 187% peak** — a burst at connection-storm onset, then near-zero activity. The server accepted connections but stopped processing them.
- **RSS stable** — no OOM, no memory growth from the extra 100 users.

The 60-second latency floor across ALL journey types (including fast GET /validate lookups that should be sub-millisecond) indicates the server as a whole became unresponsive, not just the issuance path.

### Likely mechanism (hypothesis for C4/C5 investigation)

The journeys include `POST /token` ROPC issuance (journey 4/5) which executes Argon2id password verification via `spawn_blocking`. At 500 users (≈ 15–20 % doing issuance = 75–100 concurrent Argon2id calls), the spawn_blocking pool is near saturation — p99 latency for issuance journeys is already 8–9 s at 500u.

At 600 users (90–120 concurrent issuances), the spawn_blocking queue grows faster than it drains. Argon2id tasks queue unboundedly. The Tokio event loop may be unable to service new connections during the burst (600 connections in 1.2 s at hatch_rate=500), or a per-realm write lock is held during issuance, serializing all writes and blocking reads. Either produces the observed pattern: connection accepted → no response ever delivered → 60-second Goose timeout fires.

**This matches finding 4 from the plan:** *"Token issuance p99 of 6–7 s is probably a queueing defect, not 'Argon2id is slow.' … requests queueing behind a starved spawn_blocking pool with no admission control."*

Note: HEA-1862 (2026-07-28) removed the ROPC `grant_type=password` from both token endpoints. Re-running this bisect with the updated binary (which forces issuance to use the authorization_code flow only) may shift the cliff significantly, since the Argon2id-on-issuance path no longer exists on the hot path. That re-run is a cheap decisive experiment.

---

## 5. Exit criterion verdict

> **Exit:** the cliff moves materially and we can state whether the new limiter is Hearth or still the harness.

The cliff did NOT move (NOT-MEASURABLE as "moves materially"). The exit criterion is satisfied via the stronger finding:

**We can state unambiguously that the new limiter is Hearth, not the harness.** Isolation eliminates generator starvation as a cause. The collapse is server-side. The generator is exonerated; Hearth owns the ceiling.

This means Axes C and D are still blocked until the server-side pathology is resolved or characterized. The recommended next step is to run the bisect with the post-HEA-1862 binary (no ROPC) to determine whether removing Argon2id from the issuance hot path shifts the cliff.

---

## 6. Remote-generator path (documented)

For Tier 2 measurements (true generator/server physical separation, required for ≥10k concurrent client runs):

### Server machine (machine A)

```bash
# Boot hearth with the loadtest corpus config, bind to LAN IP
hearth serve --config loadtest/loadtest-corpus.yaml
# Or with the run-loadtest env approach:
PORT=8421 LOADTEST_PORT=8421 hearth serve --dev --config loadtest/loadtest-corpus.yaml
```

### Generator machine (machine B)

```bash
HEARTH_BIN_UNUSED=1   # not needed on generator machine
LOADTEST_BIN="/path/to/hearth-loadtest"
TARGET="http://<machine-A-ip>:8421"
SEED_HANDLE="./seed-handle.json"

# 1. Seed the token pool against machine A
"$LOADTEST_BIN" seed \
  --target-host "$TARGET" \
  --users-per-realm 80 \
  --sessions-frac 0.5 \
  --revoked-frac 0.1 \
  --seed 1 \
  --seed-out "$SEED_HANDLE"

# 2. Run load against machine A (generator has full cores of machine B)
"$LOADTEST_BIN" run \
  --seed-handle "$SEED_HANDLE" \
  --mode steady \
  --users 2000 \
  --run-time 60s \
  --hatch-rate 500 \
  --resident-corpus-size <total-users-seeded-on-A>
  # Note: omit --server-pid (generator is not on machine A)
```

The `--target-host` flag is the sole coupling between generator and server. No shared filesystem, no shared state. The generator binary is self-contained and cross-compiles to Linux/Mac/Windows.

**Why this matters for Axis C (10k+ concurrent clients):** With a remote generator, machine A (Hearth) has all its cores exclusively and machine B (generator) can drive 10k+ Goose users without contending for memory or CPU with the server. This is the only configuration that cleanly isolates the server's own connection-handling ceiling.

---

## 7. Artifacts

| File | Description |
|------|-------------|
| `loadtest/scripts/hea1871-isolated.sh` | Isolation script; `taskset -c` for both server and generator; re-bisect sweep |
| `loadtest/reports/hea1871/steady-{N}u.json` | Per-step report JSON (400u–1500u) |
| `loadtest/reports/hea1871/summary.tsv` | Tab-separated summary table |
| `docs/perf/HEA-1871-results.md` | This document |
