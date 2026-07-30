# CTO triage — cold-path SST fan-out is Θ(n) between compactions

**Source finding:** HEA-1870 / C2 (`docs/perf/HEA-1870-C2-sst-growth.md`), verdict **MISS**,
fitted exponent 1.0000, R² = 1.0000. **Roadmap issue:** `79e51489-5295-4a65-895e-9aefa044b784`.
**Triaged:** 2026-07-28.

## 1. Finding accepted

Re-verified against the code, not just the report:

| Claim | Verified at |
|---|---|
| Cold `get` linearly scans a flat `sst_readers` Vec, no level structure | `src/storage/engine.rs:696-712`, `:187` |
| Each memtable flush appends exactly one SST, unbounded | `src/storage/engine.rs:475` (`trigger_flush`) — no compaction trigger on this path |
| Compaction is **time-triggered only** | `src/main.rs:1704-1707` — `tokio::time::interval(interval_secs)` is the sole caller; `min_sst_count` is a floor gate *inside* the sweep, not a trigger |
| `compact_ssts` is an all-into-one full merge | `src/storage/engine.rs:581`, `:650` (`store(vec![new_reader])`) |

The complexity class stands: **O(1) fully compacted, Θ(n) in the transient**, and the transient
is the operative case by default. This is the programme's top finding.

## 2. CTO amendment to the recommendation (the reason this doc exists)

C2's lever 1 — "fire the existing `compact_ssts` when live SST count crosses a threshold" — is
**not safe to ship as written.**

`compact_ssts` rewrites the *entire* dataset and holds `flush_lock` for the duration. Wiring
that to a count trigger of `k` flushes converts linear read fan-out into **quadratic write
amplification**: every `k · flush_threshold` bytes written triggers a rewrite of all `N` bytes,
each one a write stall. At the 64 MiB production threshold on a 100M-record corpus that is a
multi-GB rewrite on a repeating schedule. It would trade a measured read regression for an
unmeasured, larger write regression.

**Required shape instead: count-triggered *partial* (size-tiered) compaction** — merge only the
`k` newest / size-similar SSTs, leave older files alone. Caps live SST count without ever
rewriting the whole dataset. The merge primitive already accepts an arbitrary reader slice
(`sst::compact_with_fs`), so the work is selection policy, `sst_readers` splice, and config.

## 3. Disposition

| Lever | Issue | Priority | Gate |
|---|---|---|---|
| 1 — count-triggered **partial** compaction | `75e53177-90f3-4cb4-98db-463b7b72ca53` | high, assigned SoftwareEngineer | ship now |
| 2 — levelled read path / per-level range index | `e16b1817-55a7-4a8a-994c-e7de35dad00e` | medium, **design doc first** | blocked on lever 1 landing + re-measurement |

Sequencing rationale: lever 1 retires the board-facing risk cheaply and reversibly. Lever 2 is a
storage-format and read-path rewrite (crash safety, per-SST encryption headers, recovery
ordering) and should not be done under schedule pressure from an unmitigated finding. If lever 1
fails to cap fan-out cleanly, lever 2 escalates to high immediately.

## 4. Binding DoD for lever 1

Beyond the parent programme's grading rules (hardware on every figure; no PASS without a fitted
number):

1. Re-run `cargo run --release --example sst_growth` with the trigger ON; report the new fitted
   exponent. The bound must be a **cap**, not a reduction.
2. Report **write amplification and p99 write-stall** alongside read fan-out. A read win paid for
   by a write-stall regression is not a PASS.
3. Correctness test pins no key loss and no deleted-key resurrection across partial merges
   (newest-first ordering is load-bearing — see the crash-safety contract on `compact_ssts`).
