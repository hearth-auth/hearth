# HEA-1881 · CTO roadmap triage — cold-path SST fan-out

**Date:** 2026-07-28 · **Owner:** CTO · **Source finding:** HEA-1870 (C2), parent HEA-1867
**Disposition:** finding **accepted**; remediation **re-sequenced** and **re-scoped**.

---

## 1. Verification of the reported finding

I re-read the code rather than taking the report on trust. Every claim checks out:

| Claim | Verified at | Verdict |
|---|---|---|
| `get` linearly scans a flat SST vec, newest-first | `src/storage/engine.rs:738-758` — `for reader in sst_readers.iter()` over `ArcSwap<Vec<SstReader>>` (`engine.rs:212`) | **Confirmed** |
| Compaction is a *full* merge to one SST | `engine.rs:676` — `self.sst_readers.store(Arc::new(vec![new_reader]))` | **Confirmed** |
| Compaction is time-triggered only | `src/main.rs:1704-1730` — `tokio::time::interval(interval_secs)`; `min_sst_count` is a floor gate *inside* the sweep (`engine.rs:603`, `:620`), not a trigger | **Confirmed** |
| Defaults `interval_secs = 3600`, `min_sst_count = 3` | `src/config/types.rs:140-141` | **Confirmed** |
| Nothing bounds SST count between sweeps | no count-based call site for `compact_ssts` anywhere | **Confirmed** |

So `Θ(#SSTs)` on the cold path in the transient state is real, and `#SSTs` is unbounded
between hourly sweeps. Finding **accepted as stated**.

## 2. What the report understates — and it changes the ranking

Two facts materially re-rank the two proposed levers.

### 2a. The per-file probe is pure in-memory CPU, not I/O

`SstReader::get` (`sst.rs:499-516`) is: O(1) key-range prune → Bloom probe → binary search over
`entries: Vec<(CompositeKey, MemtableValue)>`. There is **no syscall and no disk read per
probed file**. The linear term is tens of nanoseconds per SST, not a page fault.

Applying that to the report's own production projection (§4, 64 MiB flush threshold):

| corpus | projected SSTs | linear fan-out cost (~50 ns/file) |
|---|---|---|
| 1,000,000 | 5 | ~0.25 µs |
| 10,000,000 | 45 | ~2 µs |
| 100,000,000 | 448 | ~22 µs |

Against the sub-millisecond p99 hot-path bar, and given this is a **hot-tier-miss path only**,
the *absolute* cost at realistic scale is small. The complexity class is still a MISS against
the board's `≤ O(log n)` bar and I am not waving that away — but it is a **correctness-of-shape**
problem well before it is a latency problem.

### 2b. The dominant constraint is memory residency, not fan-out — this is a new finding

`SstReader` holds **every entry of the file in RAM** (`sst.rs:319-321`, `entries: Vec<…>`;
"Opens and validates an SST file, decrypting and loading all entries", `sst.rs:344`). The engine
holds `Vec<SstReader>` for *all* SSTs (`engine.rs:212`) and **never evicts** — there is no reader
unload path, only whole-vec rebuilds (`engine.rs:444`, `:572`, `:676`).

Therefore **resident memory is Θ(total corpus)**, not Θ(working set). The "tiered storage" of the
architecture is realised at the hot tier but *not* below it: the cold tier is also in RAM.

The consequence for this issue: at the 100M-record rung where fan-out reaches 448 files, the
process needs tens of GB resident to have got there at all. **We OOM long before Θ(n) fan-out
becomes the binding constraint.** Building a levelled read path on top of fully-resident readers
optimises a term that is not the limiter.

The root cause is shared: SSTs are encrypted per-file and decrypted whole at open, so there is no
block granularity to page against. **A block-based SST format (per-block encryption + a block
index) is the prerequisite for both lazy paging and a levelled read path.** They are one design
effort, not two.

## 3. Decision

| Lever | Decision | Why |
|---|---|---|
| **1. Count/size-triggered compaction** | **Ship now.** high | Small, reversible, bounds transient fan-out at a constant regardless of write volume. Independent of everything below. |
| **1b. Write-amplification guard** | **In scope of lever 1, non-optional.** | See risk below. |
| **2. Levelled read path** | **Design spec first. Do not implement yet.** medium | Must be re-scoped around §2b or it optimises the wrong term. |
| **3. SST residency (new)** | **Measure, then fold into the same design.** high | Newly identified; plausibly the real scale ceiling. |

### Risk that gates lever 1

A naive count trigger is actively dangerous. `compact_ssts` rewrites the **entire dataset** into
one file. Firing it every time the count crosses `min_sst_count = 3` during a bulk import means
re-writing all data on roughly every third memtable flush — quadratic write amplification, plus
the flush-lock stall already tracked as HEA-1358 (`engine.rs:583`). Lever 1 therefore **must**
carry a debounce: a minimum interval between compactions and/or a threshold that scales with
current data size, with the pathological case covered by a test. This is why lever 1 is a
delegated engineering issue with an explicit acceptance criterion, not a one-line config change.

### What I am explicitly not doing

Not authorising a levelled-LSM rewrite off the back of one microbenchmark. HEA-1869 shipped
cold-path telemetry (observed fan-out, `sst_files` gauge, tier-miss ratio). We should read real
fan-out and real miss rates from a running instance before committing to structural storage work,
and settle the residency question first, because it may reorder the design.

## 4. Sequencing

```
HEA-1881 (this issue — triage, remains open as the roadmap tracker)
  ├─ A. count/size-triggered compaction + write-amp debounce   [high, engineer, ship now]
  ├─ B. SST reader residency — measure RSS vs corpus            [high, engineer, measurement]
  └─ C. block-based SST format + levelled read path — DESIGN    [medium, CTO+engineer]
        blocked by B (and informed by A's telemetry)
```

A is unblocked and independent. B is a measurement with the same shape as C2's harness. C stays
design-only until B lands.

## 5. Evidence

- `docs/perf/HEA-1870-C2-sst-growth.md` — the C2 measurement
- `examples/sst_growth.rs` — `cargo run --release --example sst_growth`
- Code: `src/storage/engine.rs:212,603,620,676,738-758`; `src/storage/sst.rs:319-321,344,499-516`;
  `src/main.rs:1704-1730`; `src/config/types.rs:140-141`
