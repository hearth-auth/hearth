# HEA-1951 · C0 disk-slope sweep: WAL/SST split across N

**Date:** 2026-07-29  
**Branch:** `feature/perf-updates-7-28-26`  
**Commit:** `abf179ba` — `perf(identity/HEA-1945): collapse session_create's 2 puts into 1 atomic WAL record`  
**Code state:** duplicate-`UserCreated` bug (HEA-1946 §3.3) **not yet fixed**  
**Benchmark:** `examples/disk_slope_sweep.rs`  
**Run command:** `./disk_slope_sweep 5000 20000 60000 100000 150000 200000`  
**Sweep time:** 15.9 s (0.080 ms/user)

---

## Outcome first

**K7 VERDICT: PASS**

The K7 MISS reported in PERFORMANCE_REPORT v2 was a small-N measurement artifact.
At large N (post-WAL-rotation), the asymptotic SST/user slope is **1,195.6 B/user**,
which extrapolates to **111.3 GiB @100M** — **1.80× headroom** inside the 200 GiB budget.

---

## 1. Measurement method

Seed through `EmbeddedIdentityEngine::create_user` + one explicit second `UserCreated`
audit event (mirroring `admin_create_user` in `src/protocol/http/admin.rs`) — exactly
the method that produced the 2,840 B/user C0 baseline. Nothing synthesized.

At each checkpoint N:

1. Stat the data directory recursively.
2. Partition: WAL = files whose path contains `"wal"`, SST = files with `.sst` extension.
3. Report WAL bytes, SST bytes, and per-user rates.

Storage config: `StorageConfig::dev()` — 64 MiB WAL max_size (production default).

---

## 2. Sweep results

```
        N |     WAL bytes |     SST bytes |  WAL/user |  SST/user |  tot/user | rot
----------------------------------------------------------------------------------
     5000 |       8289266 |       4617805 |      1658 |       924 |      2581 |
    20000 |      33239266 |      23087283 |      1662 |      1154 |      2816 |
    60000 |      32730756 |      71531203 |       546 |      1192 |      1738 | #1
   100000 |      32342328 |     119877850 |       323 |      1199 |      1522 | #2
   150000 |      48733746 |     177441183 |       325 |      1183 |      1508 |
   200000 |      65125072 |     239635849 |       326 |      1198 |      1524 |
```

**`rot`** = WAL rotation detected (WAL file shrank, confirming `set_len(0)` after flush-to-SST).

### WAL term analysis

- N=5k to N=20k: WAL grows O(N) — **1,658–1,662 B/user** — no rotation yet.
- Between N=20k and N=60k: **first rotation** (expected at ~22,600 users = 64 MiB ÷ 2,840 B/user).
- Post-rotation: WAL/user collapses from 1,662 → 546 → 323 → 325 → 326 B/user.
- WAL/user → `max_size / N` → 0. Confirmed O(1), not O(N).

### SST term analysis

| N | SST/user |
|---|---|
| 5,000 | 924 B |
| 20,000 | 1,154 B |
| 60,000 | **1,192 B** |
| 100,000 | 1,199 B |
| 150,000 | 1,183 B |
| 200,000 | 1,198 B |

SST/user converges to ~1,192–1,199 B once compaction stabilises. The spread across
the last four checkpoints is ±10 B. **The slope is flat.**

---

## 3. OLS regression (post-rotation, N ≥ 60k)

```
SST_bytes = 1195.58 × N  +  (−314,700)
R²         = 0.999772
```

Residuals at each post-rotation checkpoint:

```
        N   SST/user   fitted   residual
-----------------------------------------
    60000    1192.2    1190.3      +1.9
   100000    1198.8    1192.4      +6.3
   150000    1182.9    1193.5     −10.5
   200000    1198.2    1194.0      +4.2
```

R² = 0.9998: SST bytes are proportional to N with negligible non-linearity.
Maximum residual ±10.5 B — within noise from compaction timing.

The small negative intercept (−315k B) is consistent with a modest fixed overhead
(realm record, signing key, audit chain head) spread across early SSTs.

---

## 4. K7 verdict

| Metric | Value |
|---|---|
| OLS SST/user slope | **1,195.6 B/user** |
| K7 budget | 2,147 B/user (200 GiB @ 100M users) |
| Projected @ 100M | **111.3 GiB** |
| Headroom | **1.80×** |
| K7 verdict | **PASS** |

---

## 5. Why the PERFORMANCE_REPORT v2 K7 MISS was an artifact

The C0 baseline (HEA-1904, N=12,000) measured 2,840 B/user.
Of those bytes:

- SST/user ≈ 1,154 B (before any compaction stabilisation)
- WAL/user ≈ 1,662 B ← **all of this disappears after WAL rotation**

At N=12,000 the WAL had never rotated (64 MiB > 12k × 2,840 B/user ≈ 34 MiB). The
59% WAL share was measured at a point where it still looked O(N). It is O(1).

At N=60k (first rotation): WAL/user = 546 B, disk/user = 1,738 B. At N=200k: 1,524 B.
**The gap to the 2,147 B/user budget never existed.**

---

## 6. Caveats and follow-up

### 6.1 Duplicate-`UserCreated` not yet fixed

This measurement is on commit `abf179ba` where the duplicate-`UserCreated` audit event
bug (HEA-1946 §3.3) is still present. Each user carries 8 keys instead of the
intended 5. Audit records are 79% of SST bytes.

After the fix lands (~39.5% byte reduction per user):

```
SST/user (expected post-fix) ≈ 1,195.6 × 0.605 ≈ 723 B/user
Projected @ 100M             ≈ 67.3 GiB         (3.18× headroom)
```

Re-run `examples/disk_slope_sweep.rs` after the fix to confirm.

### 6.2 max_sst_count=12 compaction assumption confirmed

The OLS slope is flat across N=60k to 200k (R²=0.9998). The HEA-1931 `max_sst_count`=12
cap is working as expected — compaction keeps SSTs near live data size, so the slope
does not drift upward at large N. This was the load-bearing assumption and it holds.

### 6.3 SST/user at 5k is lower (924 B) — early compaction artifact

At N=5k, SST/user=924 B is below the steady-state ~1,193 B. This is because at very
small N most data is still in the WAL + memtable and hasn't been flushed to SST yet.
The post-rotation measurements are the authoritative figures.

---

## 7. Conclusion

K7 **PASSES** uncompressed at the current code state. The 1.4× "miss" reported in
PERFORMANCE_REPORT v2 was entirely due to measuring at N=12,000 before the first WAL
rotation. There is no product deficiency to fix for K7; Option A (ZSTD compression)
and Option B (compact audit encoding) are nice-to-have improvements, not requirements.

The K7 entry in PERFORMANCE_REPORT v2 should be amended to **PASS (1.80× headroom)**
with a note that the result will improve further after the duplicate-`UserCreated` fix.
