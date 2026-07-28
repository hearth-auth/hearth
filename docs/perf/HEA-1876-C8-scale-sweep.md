# C8 — Record- and Session-Scale Sweep (HEA-1876)

**Issue:** HEA-1876 · **Parent:** HEA-1867 · **Phase:** 3
**Date:** 2026-07-28  **Git SHA:** `b29e57dd`
**Host:** `dev-ryzen-7840hs` — AMD Ryzen 7 7840HS, 19.0 GiB RAM available
**Grading contract:** `docs/perf/PERFORMANCE_REPORT_1_0.md` §3.3 (K1–K3) and §3.4 (E4)

---

## 0. Executive summary

| Row | Verdict | Reason |
|---|---|---|
| K1 users/node | `NOT-MEASURED` | no rungs completed |
| K2 sessions/node | `NOT-MEASURABLE` | C4 (absolute session knob) not yet implemented |
| K3 role assignments | `NOT-MEASURABLE` | RBAC seeder not in C8 scope |
| E4 SST-count vs corpus | `NOT-MEASURABLE` | E4/SST-count: need ≥2 valid rungs |
| cold-p99 vs corpus | `NOT-MEASURABLE` | cold-p99: need ≥2 valid rungs |
| hot-p99 vs corpus | `NOT-MEASURABLE` | hot-p99: need ≥2 valid rungs |

---

## 1. Sweep configuration (constant across all rungs)

| Parameter | Value |
|---|---|
| Hot-tier capacity | 100,000 entries |
| Hot-set draw range | 1–10,000 |
| Tier-miss concurrent users | 50 |
| Tier-miss run time | 90s |
| Hot/cold draw weights | 50% / 50% |
| Per-write fsync | disabled (bulk load) |

---

## 2. Raw per-rung results

> Swap-voided runs are marked ⚠ and excluded from fits (admissibility rule 5).

### 2.1 Infrastructure

| Corpus (users) | Seed wall-clock | Idle RSS (MiB) | SST files | Data dir (MiB) | Swap void |
|---|---|---|---|---|---|
| 100,000 | 2s | 267.5 | 12 | 117.8 | ⚠ YES |
| 300,000 | 9s | 571.6 | 38 | 234.3 | ⚠ YES |
| 1,000,000 | 51s | 3236.5 | 127 | 631.7 | ⚠ YES |
| 3,000,000 | 516s | 5132.1 | 381 | 1897.3 | ⚠ YES |

### 2.2 Latency (90s tier-miss at 50 concurrent users)

| Corpus | Hot p50 (ms) | Hot p99 (ms) | Cold p50 (ms) | Cold p99 (ms) | RPS | Ceiling |
|---|---|---|---|---|---|---|
| 100,000 ⚠ | 160 | 800 | 340 | 1000 | 170.7 | unknown |
| 300,000 ⚠ | 130 | 600 | 320 | 700 | 205.8 | unknown |
| 1,000,000 ⚠ | 130 | 600 | 320 | 700 | 210.3 | unknown |
| 3,000,000 ⚠ | 300 | 1000 | 340 | 1000 | 151.9 | unknown |

---

## 3. Curve fits

All fits: OLS in log-log space `log(y) ~ α + β·log(n)`.
**Rule 2:** no "flat" or "scales well" adjective without β behind it.

### 3.1 SST file count vs corpus size (E4 — the architectural risk)

- Insufficient rungs for fit. **E4: NOT-MEASURABLE** (need ≥2 valid rungs)

> **H1 context (plan §5):** the cold-lookup path fans out linearly over SST files.
> If β(SSTs) ≈ 1, cold-lookup complexity is effectively O(n). This row is the
> single highest-stakes measurement in this sweep.

### 3.2 Cold-lookup p99 vs corpus size

- Insufficient rungs for fit.

### 3.3 Hot-lookup p99 vs corpus size

- Insufficient rungs for fit.

### 3.4 Marginal user memory cost (C0 contribution)

- Insufficient rungs for linear fit.

### 3.5 Seed wall-clock (operational feasibility)

- Insufficient rungs for seed-rate estimate.

---

## 4. K1 / K2 / K3 capacity grading (VISION §7.3)

### K1 — Users per node managed (target: 100M+)
**Verdict: NOT-MEASURED** — no rungs completed

The 100M target was not reached on this host. This is an honest outcome.

What this run establishes:
- The engine is disk-backed and hot-tier capacity-bounded, so 100M is structurally
  reachable if SST count stays sub-linear.
- Seed time and disk space are not the binding constraint at the measured scale.
- The binding constraint for K1 on this host is: (a) available RAM for process overhead
  at scale, and (b) whether SST fan-out (E4) imposes a per-lookup cost that breaches
  latency budgets before we reach 100M. C5 (complexity sweep) closes this loop.

### K2 — Active sessions per node (target: 10M+)
**Verdict: NOT-MEASURABLE**

**Blocking items before K2 can be graded:**
1. C4 (absolute session knob): `SeedParams.sessions_frac` (`loadtest/src/params.rs:47`)
   ties session count to user count. An `--absolute-sessions N` flag is needed to
   sweep session scale at fixed user count.
2. A dedicated session-validation journey: one that pre-creates N sessions and
   benchmarks lookup latency against a fixed session-only pool.

### K3 — Role assignments per node (target: 100M+)
**Verdict: NOT-MEASURABLE** — demo seeder creates no per-user RBAC assignments.
Requires a dedicated RBAC seeder that assigns roles/groups at the target scale.

---

## 5. NOT-MEASURABLE and VOID rungs

- **100,000 users (VOID):** swap-in delta = 503648 pages during load — admissibility rule 5 violation; excluded from all fits
- **300,000 users (VOID):** swap-in delta = 253764 pages during load — admissibility rule 5 violation; excluded from all fits
- **1,000,000 users (VOID):** swap-in delta = 714928 pages during load — admissibility rule 5 violation; excluded from all fits
- **3,000,000 users (VOID):** swap-in delta = 2368824 pages during load — admissibility rule 5 violation; excluded from all fits

---

## 6. Follow-up items

| Priority | Item | Owner |
|---|---|---|
| HIGH | C4: add `--absolute-sessions N` knob to `SeedParams` | Engineer |
| HIGH | C5: extend corpus ladder to 10M+ on a dedicated host (if provisioned) | PlatformEngineer |
| MED  | K3: add RBAC seeder to C8 or as a dedicated child issue | Engineer |
| MED  | Confirm E4 verdict with ≥4 rungs (more points = tighter CI) | PlatformEngineer |

---

## 7. Reproduction

```bash
# Pre-built release binaries at /scratch/cache/target/release/
cd /path/to/hearth
SKIP_BUILD=1 loadtest/scripts/run-scale-sweep.sh
```

Raw artifact: `docs/perf/artifacts/c8-scale-sweep-raw.json`
This report:  `docs/perf/HEA-1876-C8-scale-sweep.md`
