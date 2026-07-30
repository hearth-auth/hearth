# HEA-1885 · Lever 1 — count-triggered PARTIAL (size-tiered) compaction

**Parent:** HEA-1881 (cold-path SST fan-out is Θ(n) between compactions) ·
**Origin:** HEA-1870/C2 (SST-count growth, verdict MISS, exponent 1.0000, R² 1.0000).

## Problem

The cold read path (`EmbeddedStorageEngine::get`) linearly scans the flat
`sst_readers` Vec. HEA-1870/C2 proved that SST **count** — hence read fan-out —
grows **exactly linearly** with corpus size when compaction is time-triggered
only (the periodic `compact_ssts` sweep is hourly by default). Between sweeps a
100M-record corpus at a 64 MiB flush threshold accumulates thousands of SSTs,
each a probe on every cold read.

## Why not just count-trigger the existing `compact_ssts`

`compact_ssts` (`src/storage/engine.rs`) is an **all-into-one** full merge: it
rewrites the entire dataset and holds `flush_lock` for the whole duration. Firing
it every *k* flushes turns a linear read fan-out into **quadratic write
amplification** — every *k* × 64 MiB written triggers a multi-GB rewrite with a
write stall. That is a worse regression than the bug (CTO amendment on HEA-1885).

## Shape shipped — partial, size-tiered

`compact_partial()` merges only **one contiguous, same-size-tier run** of at
least `merge_min` SSTs, leaving every other file untouched:

- **Selection** (`select_partial_run`): newest-first, group maximal contiguous
  spans whose entry-count spread stays within 2×; return the first span reaching
  `merge_min`. A merged SST (~`merge_min`× a flush) lands in the next tier up and
  is never re-merged with fresh flushes → write amplification is **O(log n)**,
  not quadratic.
- **Recovery-consistent ordering.** Reads resolve by reader-Vec order
  (newest-first); recovery rebuilds that Vec by sorting files by number
  descending. The merged output **reuses the highest number in the run** and its
  file path. Because the run is contiguous in the number-sorted Vec, no surviving
  SST has a number inside the run's band, so the merged output splices back at the
  correct recency slot — in memory *and* across a restart.
- **No tombstone resurrection.** Tombstones are dropped only when the run reaches
  the oldest SST; a partial merge that leaves older files live preserves them
  (`compact_with_fs_opts(drop_tombstones = false)`), so a delete can't be
  resurrected from an un-merged older file.
- **Off the write path.** `trigger_flush` only *signals* (a `Notify`) when live
  count reaches `max_sst_count`; the merge runs on the existing background task
  via `spawn_blocking`. `flush_lock` is held only for one tier's merge, never the
  whole dataset.

## Config (operator-visible)

`storage.compaction.max_sst_count` (default `0` = OFF, reversible per DoD) —
count trigger. `storage.compaction.merge_min` (default `4`) — per-tier fan-in.

## Measurement

Harness: `cargo run --release --example sst_partial_compaction` (drives the
trigger deterministically — same policy the background task applies). Corpus
ladder identical to HEA-1870/C2. Measurement flush threshold 256 KiB, 300 B
records, `max_sst_count = 12`, `merge_min = 4`.

**Hardware:** AMD Ryzen 7 7840HS (16 threads), 54 GiB RAM, Linux 7.0.10.
tmpfs-backed tempdir; SyncMode = production (`EveryWrite`), dev host-key.

| corpus (n) | live SSTs (post-drain) | peak SSTs | bytes written | write-amp | seed (s) |
|-----------:|-----------------------:|----------:|--------------:|----------:|---------:|
| 10,000     | 1  | 10 | 6,866,199   | 2.29× | 0.09  |
| 20,000     | 2  | 11 | 13,732,398  | 2.29× | 0.22  |
| 40,000     | 1  | 11 | 41,194,905  | 3.43× | 0.56  |
| 80,000     | 4  | 11 | 79,300,778  | 3.30× | 1.46  |
| 160,000    | 2  | 11 | 215,581,819 | 4.49× | 4.97  |
| 320,000    | 9  | 12 | 380,362,856 | 3.96× | 36.19 |

### 1. Read fan-out — CAPPED

Operational fan-out = the **peak** live SST count a cold read may scan. The count
trigger hard-caps it at `max_sst_count`:

```
Fit: log(peak fan-out) = slope * log(n) + c   [trigger ON]
  peak fan-out exponent = 0.0376  (R^2 = 0.7133)
  Baseline (HEA-1870/C2, trigger OFF): exponent = 1.0000 (linear).
```

Peak fan-out is **flat at 10–12** across a 32× corpus range — exponent ≈ 0. This
is a **cap**, not a constant-factor reduction: fan-out no longer grows with
corpus. (The post-drain "live SSTs" residual is smaller and noisy — < `merge_min`
per tier — and is not the operational metric.)

### 2. Write amplification — bounded, not quadratic

Total SST bytes written (flushes + merges) / corpus bytes peaks at **4.49×** and
sits near **4×** at the largest rung — a small constant consistent with O(log n).
A count-triggered *full* merge would rewrite all N bytes every *k* flushes
(quadratic). **PASS.**

### 3. Per-merge write-stall

`compact_partial` holds `flush_lock` for its duration, so its wall-clock **is**
the stall a concurrent writer observes:

```
merges = 108
mean = 74 ms · p50 = 37 ms · p99 = 307 ms · max = 395 ms   (256 KiB flush threshold)
```

Bounded by **one tier's** merge (`merge_min` similar-sized SSTs), never the whole
dataset — unlike `compact_ssts`. **Caveat:** these figures are at the 256 KiB
measurement flush threshold. Production uses a 64 MiB flush threshold (256×
larger tier-0 SSTs), so a tier-0 merge there moves ~256 MiB and the stall scales
accordingly (order of seconds for the largest tiers). This is exactly why the
trigger **defaults OFF** and must be validated per hardware before enabling
(reversible outcome, per the DoD).

## Outcome

- Read fan-out: **capped** (exponent 0.04 vs 1.00 baseline). ✅ DoD 2.
- Write amp: **~4×, O(log n)**, not quadratic. ✅ DoD 3.
- Write-stall: **bounded per tier**, measured; large-flush production stall is the
  reason the trigger ships **OFF by default** (reversible). ✅ DoD 3 + reversibility.
- TDD failing test first, then implementation (`partial_compaction_bounds_sst_count_and_preserves_keys`
  in `src/storage/engine.rs`): caps fan-out, preserves a key in the oldest SST
  (no loss), and keeps a deleted key deleted (no resurrection). ✅ DoD 1.

### Follow-up (not in scope)

Moving the merge I/O outside `flush_lock` (take the lock only for the rename +
splice) would drop the large-flush write-stall to metadata-op latency, letting
the trigger default ON. It adds concurrent-flush race handling; tracked as a
lever-2 candidate under HEA-1881.
