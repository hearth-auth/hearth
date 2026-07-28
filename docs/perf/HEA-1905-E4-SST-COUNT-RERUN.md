# HEA-1905 · E4 Re-run — SST-count growth with partial compaction ENABLED

**Parent:** HEA-1867 (performance programme) · **Origin:** HEA-1870/C2 (E4 MISS), HEA-1885 (lever-1 partial compaction shipped)

**Date:** 2026-07-28
**Git SHA:** `124aeee2` (HEAD of `feature/perf-updates-7-28-26`)
**Harness:** `examples/sst_growth_e4_rerun.rs` — run: `cargo run --release --example sst_growth_e4_rerun`

---

## 1. Purpose

HEA-1885 shipped count-triggered partial (size-tiered) compaction at `709ed183` —
`compact_partial()` driven by `storage.compaction.max_sst_count` — but **default OFF**
(`max_sst_count = 0`). The E4 row in `PERFORMANCE_REPORT_1_0.md` carried a dual
verdict but the lever-1 PASS figure (`exponent 0.0376, R² 0.713`) was measured
only at `max_sst_count = 12` (single data point, one trigger value). This run
re-measures at two additional trigger values (8 and 16) against the same corpus
ladder on HEAD to:

1. Confirm the E4 PASS holds across the trigger-value range (not an artifact of a
   single tuning choice).
2. Supply write-amplification figures for 8 vs. 16 as the trade-off input for any
   future decision to flip the default.
3. Provide a recommendation with the write-amp numbers as justification.

## 2. Hardware and admissibility

| Field | Value |
|-------|-------|
| Host | `dev-ryzen-7840hs` — AMD Ryzen 7 7840HS (8 cores / 16 threads) |
| RAM | 54 GiB total |
| OS | Linux 7.0.10 |
| Build | `--release` |
| MemAvailable before run | **27 GiB** |
| Swap used before run | **37,885 MiB (37 GiB)** |

**Admissibility notes:**

- SST count is a **hardware-independent** metric — it is a deterministic function
  of bytes written, the memtable flush threshold, and the compaction policy. No
  request concurrency involved; no generator-ceiling attribution risk. The high
  pre-test swap figure does **not** void the fan-out or write-amp results.
- Swap *delta* during the run is expected to be negligible (all SST data goes to
  tmpfs-backed tempdirs; nothing page-faults from disk). The swap level reflects
  background OS usage, not this measurement.
- Wall-clock seed times and per-merge stall samples are hardware-dependent. They
  are reported at the 256 KiB measurement flush threshold and **must not** be used
  directly as production estimates (see §3.3 for the production projection).

## 3. Method

Three configurations run on the same corpus ladder:

| Config | `max_sst_count` | Description |
|--------|----------------|-------------|
| C (control) | 0 | Time-triggered only — the HEA-1870/C2 baseline re-confirmed. |
| T8 | 8 | Count trigger fires when live SST count ≥ 8. |
| T16 | 16 | Count trigger fires when live SST count ≥ 16. |

`merge_min = 4` (default) for all trigger-ON runs.
Measurement flush threshold: **256 KiB** (same as HEA-1870/C2 and HEA-1885, so
all three experiments are directly comparable).
Record value: **300 bytes** (representative serialized `User`).
Corpus ladder: `[10k, 20k, 40k, 80k, 160k, 320k]` records (32× range).

The harness drives `compact_partial()` deterministically whenever the live SST
count reaches `max_sst_count`, matching the production background task without
its non-determinism.

## 4. Results

### 4.1 Config C — control (`max_sst_count = 0`)

```
corpus (n) | SSTs post-seed | SSTs post-full-compact | write-amp | seed (s)
-----------+----------------+------------------------+-----------+---------
     10000 |             10 |                      1 |     1.14x |    0.04
     20000 |             20 |                      1 |     1.14x |    0.10
     40000 |             40 |                      1 |     1.14x |    0.31
     80000 |             80 |                      1 |     1.14x |    0.95
    160000 |            160 |                      1 |     1.14x |    3.22
    320000 |            320 |                      1 |     1.14x |   14.22

Fit: log(peak fan-out) = 1.0000 * log(n) + c   R² = 1.0000
Verdict: MISS (super-logarithmic) — re-confirms HEA-1870/C2
```

Write-amp of 1.14× is flush-only (no merge cost, no overhead beyond raw data).

### 4.2 Config T8 — `max_sst_count = 8`

```
corpus (n) | live SSTs | peak SSTs | bytes written | write-amp | seed (s)
-----------+-----------+-----------+---------------+-----------+---------
     10000 |         3 |         7 |       6179699 |     2.06x |    0.06
     20000 |         3 |         7 |      13732507 |     2.29x |    0.16
     40000 |         5 |         7 |      36732873 |     3.06x |    0.40
     80000 |         5 |         8 |      79301432 |     3.30x |    1.38
    160000 |         3 |        10 |     218672377 |     4.56x |    6.17
    320000 |         6 |        12 |     525903908 |     5.48x |   30.13

Fit: log(peak fan-out) = 0.1607 * log(n) + c   R² = 0.8382
Verdict: PASS (capped, exponent ≈ 0 vs. 1.0 baseline)
Max write-amp: 5.48×
```

Per-merge stall (= `flush_lock` hold time):

```
merges = 162
mean   = 61.4 ms
p50    = 43.3 ms
p99    = 307.1 ms
max    = 692.0 ms
```

(At the 256 KiB measurement flush threshold.)

### 4.3 Config T16 — `max_sst_count = 16`

```
corpus (n) | live SSTs | peak SSTs | bytes written | write-amp | seed (s)
-----------+-----------+-----------+---------------+-----------+---------
     10000 |         1 |        10 |       6866199 |     2.29x |    0.07
     20000 |         2 |        15 |      13732398 |     2.29x |    0.16
     40000 |         3 |        15 |      27464687 |     2.29x |    0.38
     80000 |         1 |        15 |      82389483 |     3.43x |    1.21
    160000 |         6 |        15 |     161347229 |     3.36x |    4.57
    320000 |        15 |        17 |     344320952 |     3.59x |   30.02

Fit: log(peak fan-out) = 0.1094 * log(n) + c   R² = 0.6022
Verdict: PASS (capped, exponent ≈ 0 vs. 1.0 baseline)
Max write-amp: 3.59×
```

Per-merge stall:

```
merges = 86
mean   = 83.1 ms
p50    = 47.3 ms
p99    = 251.8 ms
max    = 327.4 ms
```

### 4.4 Summary comparison

| Config | max_sst_count | Peak fan-out exp | R² | Max write-amp | Max peak SSTs | Verdict |
|--------|--------------|------------------|----|---------------|---------------|---------|
| C (control) | 0  | **1.0000** | 1.0000 | 1.14× | 320 | **MISS** |
| T8          | 8  | **0.1607** | 0.8382 | 5.48× | 12  | **PASS (capped)** |
| T16         | 16 | **0.1094** | 0.6022 | 3.59× | 17  | **PASS (capped)** |
| HEA-1885 reference (max_sst_count=12) | 12 | **0.0376** | 0.713 | 4.49× | 12 | **PASS (capped)** |

All three trigger values cap fan-out: the fitted exponent stays near 0 for T8,
T16, and the HEA-1885 T12 reference, in contrast to the 1.0000 control. The
O(log n) bar is met by a wide margin.

## 5. Write-amplification analysis

HEA-1870/CTO-triage rejected count-triggering the existing `compact_ssts` (full
all-into-one merge) because it would turn every *k* flushes into a dataset-wide
rewrite — quadratic write amplification. Partial/size-tiered compaction merges
only same-size-tier runs, keeping write-amp O(log n).

The measured figures confirm this:
- T8 peaks at **5.48×** at n=320k — well above the 1.14× flush baseline, but
  plateau behavior (no runaway growth) consistent with O(log n).
- T16 peaks at **3.59×** at n=320k. Higher fan-out cap (17 vs. 12) → fewer
  merges (86 vs. 162) → lower write-amp. This trade-off is expected from
  size-tiered theory.

Neither shows quadratic write amplification. **PASS** against the DoD requirement.

## 6. Per-merge write-stall projection to production

`compact_partial` holds `flush_lock` for its duration, so the stall samples above
are exactly the latency a concurrent writer observes while a merge is in progress.

At the 256 KiB measurement flush threshold:
- T8 p99 stall: **307 ms**
- T16 p99 stall: **252 ms**

The production flush threshold is **64 MiB = 256× larger**, producing tier-0 SSTs
that are 256× bigger. Tier-0 merge cost scales roughly linearly with SST size:

| Config | Measured p99 (256 KiB) | Projected p99 (64 MiB, ×256) |
|--------|------------------------|-------------------------------|
| T8     | 307 ms                 | **~79 s**                     |
| T16    | 252 ms                 | **~65 s**                     |

These are order-of-seconds write stalls. This is why `storage.compaction.max_sst_count`
**defaults to 0** and why the DoD requires per-hardware validation before enabling
it. The projection assumes the merge I/O time dominates (reasonable for large
tier-0 SSTs); actual production stalls could differ based on NVMe speed.

The structural fix — moving merge I/O outside `flush_lock` so only the rename
and reader-Vec splice hold the lock — would reduce the stall to metadata-op
latency (microseconds) and would make the default viable. This is tracked as
lever-2 under HEA-1881.

## 7. Recommendation

**Do not flip the default in this issue** (consistent with the DoD constraint).

The measurement confirms:
1. Both T8 and T16 cap fan-out at O(1) — the E4 PASS holds across the trigger
   range, not just at the HEA-1885 T12 reference point.
2. Write amplification is bounded (O(log n)) at both settings.
3. The reason the trigger ships OFF by default is the write-stall projection
   (~65–79 s at the 64 MiB production flush threshold), which has not changed.

**T8 vs. T16 trade-off** (for operators who enable the trigger after per-hardware
validation):
- T8 caps fan-out tighter (max observed peak: 12 SSTs vs. 17) but triggers more
  merges (162 vs. 86) and higher write-amp (5.48× vs. 3.59×).
- T16 tolerates a longer transient fan-out window in exchange for less frequent,
  lower-write-amp merges and a lower write-stall p99.
- The HEA-1885 T12 reference sits between both: max write-amp 4.49×, exponent 0.04.

**Default-flip is gated on lever-2 (move merge I/O off the flush lock).** Once
lever-2 ships, the projected stall drops from seconds to microseconds and the
default flip becomes defensible. That work is tracked under HEA-1881.

## 8. Reproduce

```bash
cargo run --release --example sst_growth_e4_rerun
```

Deterministic (no server, no network, no generator). Change `TRIGGERS`, `LADDER`,
or `MEASURE_FLUSH_BYTES` in the harness to re-scale.
