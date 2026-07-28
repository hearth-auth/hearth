# HEA-1870 · C2 — SST-count growth vs corpus size (settles finding 5)

**Parent:** HEA-1867 · **Phase:** 0.5 · **Owner:** SoftwareEngineer
**Status:** measurement complete — **verdict MISS** (cold-path fan-out is super-logarithmic in the transient state). Per the board's pre-authorised split (HEA-1867 plan §8 decision 5), the remediation is raised as a **separate storage-engine roadmap issue** and flagged to the CTO; it is **not** absorbed here.

---

## 1. Exit criterion (verbatim from the plan)

> Measure file count and depth after seeding at each ladder rung, both immediately
> post-seed and post-compaction, and fit file count against corpus size. **Exit:**
> a stated complexity class for the cold path.

## 2. Hardware (every figure below was measured here)

| | |
|---|---|
| CPU | AMD Ryzen 7 7840HS (8 cores / 16 threads) |
| RAM | 57.4 GB total |
| Disk | NVMe (`/dev/nvme0n1`), XFS |
| OS | Linux 7.0.10 |
| Build | `--release`, `cargo` |

The only hardware-dependent figure is **seed wall-clock**; the SST **counts and the
fitted exponent are hardware-independent** (deterministic functions of bytes written,
the memtable flush threshold, and the compaction policy — no request concurrency
involved, so there is no generator-ceiling attribution risk).

## 3. Method

Harness: `examples/sst_growth.rs` (`cargo run --release --example sst_growth`).

For each corpus rung `n` it opens a fresh `EmbeddedStorageEngine` with:
- memtable flush threshold **256 KiB** (scaled down from the 64 MiB production default
  so a modest corpus yields a countable number of SSTs — the *relationship* is what we
  fit, and it is threshold-invariant);
- 300-byte record values (a `User` serialises to a few hundred bytes — HEA-1867 finding 3,
  `src/identity/types/user.rs`);
- **periodic compaction sweep disabled** (`interval_secs = 0`) so compaction only runs
  when we call it explicitly.

It seeds `n` records, counts `*.sst` files on disk (**post-seed**), calls
`compact_ssts(2)`, and counts again (**post-compaction**). It then fits
`log(#SSTs post-seed)` on `log(n)` by least squares and projects the relationship onto
the 64 MiB production flush threshold.

## 4. Results

```
corpus (n) | SSTs post-seed | SSTs post-compaction | seed wall-clock (s)
-----------+----------------+----------------------+--------------------
     10000 |             10 |                    1 |               0.10
     20000 |             20 |                    1 |               0.21
     40000 |             40 |                    1 |               0.47
     80000 |             80 |                    1 |               2.61
    160000 |            160 |                    1 |               5.51
    320000 |            320 |                    1 |              14.76
```

**Fit (post-seed):** `log(#SSTs) = slope · log(n) + c`
- **slope (empirical exponent) = 1.0000**, **R² = 1.0000**.

**Post-compaction:** exactly **1** SST at every rung.

**Projection to the 64 MiB production flush threshold** (≈223,696 records/SST at 300 B):

| corpus (n) | projected SSTs post-seed (pre-compaction) |
|---|---|
| 1,000,000 | 5 |
| 10,000,000 | 45 |
| 100,000,000 | 448 |

## 5. Stated complexity class for the cold path

The cold read path (`EmbeddedStorageEngine::get`, `src/storage/engine.rs:696-712`) is a
**linear, newest-first scan of the flat `sst_readers` `Vec`** (`engine.rs:187`). There is
no level structure and no per-level key-range index. So the complexity of a hot-tier miss
is **Θ(#SSTs)** in the number of files probed, and #SSTs is what we measured.

The result is **bimodal**:

- **Fully-compacted steady state: O(1).** `compact_ssts` is a *full* compaction — it
  merges every SST into a single file (`engine.rs:650`, `store(vec![new_reader])`). After a
  compaction the fan-out is one file.
- **Transient (between compaction runs): Θ(n) — linear, super-logarithmic.** Each memtable
  flush appends one SST (`trigger_flush`); nothing bounds the count until a compaction runs.
  The fitted exponent is **1.0** with R² = 1.0.

The transient is the operative case, because **compaction is time-triggered only**
(`src/main.rs:1705`, background task on `interval_secs`, default **3600 s / 1 hour**).
There is **no count- or size-triggered compaction**: `min_sst_count` (default 3) is merely a
floor gate *inside* the hourly sweep, not a trigger. Consequently, during any sustained
write window — a bulk import, a migration, or simply steady organic user growth — SST count
grows **linearly and unbounded** until the next hourly sweep, and every cold lookup in that
window fans out over all of them.

Each individual SST is cheap to reject (O(1) min/max key-range prune, `sst.rs:446`, then a
per-file Bloom filter), so the constant is small — but the **number of files probed is
linear in the un-compacted write volume**, and no structure bounds it sublinearly. For
random-UUID user keys (the real workload) SST key-ranges overlap heavily, so the range
prune is weak and the Bloom filters carry the load; a positive lookup for a key living in an
old SST must still be checked against every newer SST's filter first. Worst-case remains
**O(#SSTs)**.

## 6. Verdict

Against the board's `≤ O(log n)` bar (HEA-1867 plan §1a): **MISS.** The fitted exponent is
**1.0 (linear)** in the transient, un-compacted state, which is unambiguously
super-logarithmic. This is the condition the plan flagged as *the single biggest risk to the
board's requirement* (finding 5) and pre-authorised to split out.

The steady-state O(1) after full compaction does **not** rescue the verdict, because the
system spends unbounded time in the transient state by default (hourly sweeps, no
count/size trigger) and because a single full-compaction that rewrites the *entire* dataset
is itself an O(total-data) stall on the flush lock (`engine.rs:583` TODO / HEA-1358) — it
trades linear read fan-out for a periodic linear write stall.

## 7. Recommendation (carried into the remediation issue, not fixed here)

Two independent levers, cheapest first:

1. **Count/size-triggered compaction (cheap mitigation).** Fire compaction when the live
   SST count crosses a threshold, not only on the hourly timer. This alone bounds the
   transient fan-out to ~`min_sst_count` regardless of write volume, and is a small change
   to the existing background-compaction wiring (`src/main.rs:1705`) plus a post-flush hook.
   It does not remove the full-compaction write stall, but it caps read fan-out at a constant.

2. **Levelled read path / per-level key-range index (structural fix — the real O(log n)).**
   Partition SSTs into levels with non-overlapping key ranges per level, so a lookup probes
   O(levels) = O(log n) files via a per-level range index instead of scanning all of them.
   This is the LSM-standard fix and also removes the single-shot full-compaction stall in
   favour of incremental minor compactions. This is the larger, roadmap-scoped work the
   plan anticipated (§8 decision 5) and the parent's top finding.

## 8. Reproduce

```bash
cargo run --release --example sst_growth
```

Deterministic; no server, no network, no generator. Change `LADDER` / `MEASURE_FLUSH_BYTES`
in the harness to re-scale.
