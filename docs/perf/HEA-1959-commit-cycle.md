# HEA-1959 · The T4 commit cycle — measured mechanism, two fixes, and the residual

**Date:** 2026-07-29
**Branch:** `feature/perf-updates-7-28-26`
**Host:** `dev-ryzen-7840hs`, 16 logical cores
**Driver:** `examples/saturation_throughput.rs` (HEA-1949 ladder) + new per-batch phase timers
**Artifacts:**
`docs/perf/artifacts/c7-saturation-post-hea1959-raw.json` (machine)
`docs/perf/artifacts/c7-saturation-post-hea1959-console.txt` (human)
`docs/perf/artifacts/c7-hea1959-phase-baseline-console.txt` (pre-fix phase split)
`docs/perf/artifacts/c7-hea1959-fdatasync-only-console.txt` (fix 1 in isolation)
`docs/perf/artifacts/c7-hea1959-batched-writes-console.txt` (fixes 1+2)
`docs/perf/artifacts/c7-saturation-post-hea1959-sample2-raw.json` (repeatability sample D)
`docs/perf/artifacts/c7-saturation-post-hea1959-sample2-console.txt`

---

## Outcome first

**T4 does not clear 50,000 ops/s.** The issue asked for a straight answer if it
did not, so: it did not.

| | value |
|---|---|
| Baseline (HEA-1956) | 33,724 ops/s @ T=256 |
| **Measured at HEAD** | **41,255 ops/s @ T=256** |
| Improvement | **1.22×** |
| T4 target | 50,000 ops/s |
| **T4 verdict** | **MISS — 1.21× short** (was 1.48×) |
| Durability | unchanged; `SyncMode::Async` still rejected |

The mechanism the issue asked me to find is identified from instrumentation and
largely removed: serial per-entry work fell 8,984 → 4,584 ns/entry. The residual
is a **different** bottleneck — the cost of waking blocked writers — and §5
quantifies it and shows the target is reachable without weakening durability.

---

## 1. The ceiling model in report 2.x is unreachable by construction

`T × F / W` assumes **T independent fsync streams**. There is one WAL, one leader,
and one commit stream, so that ceiling cannot be approached by any correct
implementation. "Coalescing efficiency decayed from 36.5% to 25.5%" is therefore
not, by itself, evidence of a defect — the denominator grows linearly in `T` while
the achievable numerator cannot.

The physically meaningful model for a single-leader group commit is:

```
cycle      = fsync + serial_per_entry × batch
throughput = batch / cycle
```

Fitting the HEA-1956 artifact to this form gives an intercept of **2.10 ms**
(against a device fsync period of 1.94 ms) and a slope of **10.1 µs/entry**,
R² = 0.91. That fit is what identified the real problem: batch size was growing
with `T` exactly as group commit intends (1.00 → 109.89), but every entry dragged
~10 µs of *serial* CPU and syscall work onto the commit critical path. At
batch = 110 that was a third of the entire cycle.

**Recommendation:** strike `T × F / W` and "coalescing efficiency" from future
reports, or relabel them explicitly as an unreachable reference. They sent
HEA-1955 after a thread-handoff gap that was not the bottleneck.

## 2. Instrumented phase split (the measurement the issue asked for)

`commit_batch` now records `encrypt` / `write` / `fsync` / `signal` timings,
sampled once per batch (not per entry), exposed via
`EmbeddedStorageEngine::wal_commit_profile()`.

Measured at T=256, **before** any fix:

| phase | ns/entry | share of serial |
|---|---:|---:|
| `write_all` — three syscalls per entry | 5,150 | 57% |
| `signal` — one futex wake per slot | 2,584 | 29% |
| `encrypt` — an AES-256 key schedule per entry | 1,250 | 14% |
| **total serial** | **8,984** | |

And one finding the model did not predict: **`sync_all` itself grew with batch
size**, 3.79 ms at batch = 31 to 7.38 ms at batch = 131. That is a metadata
journal commit, not data.

## 3. Fix 1 — `fdatasync` instead of `fsync`

A WAL segment is created and parent-dir-fsynced at open (HEA-1855) and thereafter
only appended to. The only metadata a replay needs is the file length, which
`fdatasync` persists; `fsync` additionally journals `mtime`/`ctime`, which the WAL
does not depend on.

Measured in isolation:

| | before | after |
|---|---:|---:|
| sync per batch @ T=1 | 3.87 ms | **1.90 ms** |
| sync per batch @ batch=131 | 7.38 ms | **flat, ~1.9–2.0 ms** |
| device microbenchmark | 1.94 ms | 1.94 ms |

The post-fix figure matches the raw device rate, which is the check that this is
the metadata commit and not something else.

**Scoping — this is deliberately narrow.** Rotation truncates the segment and
rewrites its headers, so it keeps a full `sync_all`. That split is pinned by
`appends_use_fdatasync_while_rotation_uses_full_fsync`, verified non-vacuous:
temporarily routing `rotate_locked` through `sync_data` turns it red
("15 total syncs and 15 fdatasyncs"), green again on restore.

**Note for whoever verifies durability next:** `kill -9` **cannot** discriminate
`fdatasync` from no sync at all — both survive via the page cache. Do not write
that test believing it proves the guarantee. The argument rests on the documented
Linux semantics plus the precondition (append-only segment, directory entry
already fsynced, rotation full-fsynced), which is what the test above pins.

## 4. Fix 2 — batched writes, one key schedule, O(1) signalling

One `write_all` per batch instead of three syscalls per entry; one AES key
schedule per batch instead of one per entry; one rotation-mutex critical section
per batch; and a shared commit watermark with one `notify_all` replacing one
`notify_one` per writer.

Per-entry serial cost, T=256, before → after:

| phase | before | after | change |
|---|---:|---:|---|
| `write` | 5,150 | **469** | **11× better** |
| `encrypt` | 1,250 | **561** | 2.2× better |
| `signal` | 2,584 | **3,554** | **worse** |
| total serial | 8,984 | **4,584** | 2.0× better |

(after-figures from sample D, the representative run — see §5)

**The signalling change did not deliver.** Collapsing N `notify_one` calls into
one `notify_all` removed the syscalls but not the work: waking N waiters is O(N)
inside the kernel either way, measured at **358 µs per batch** for a single
`notify_all` releasing ~100 threads (~3.5 µs per woken thread). This is stated
plainly because HEA-1955 was closed on a prediction that was never checked against
a measurement; this one was, and it was wrong. The change is retained — it is
simpler, it removes a per-writer mutex and condvar, and it eliminates the
lost-wakeup failure mode by making the wait condition a monotone watermark — but
it should not be credited with throughput.

## 5. The residual is thread-wakeup cost

Two full gated runs at HEAD, plus the earlier isolated runs, give this picture at
T=256:

| run | what was in it | ops/s @ T=256 | fsync ms/batch |
|---|---|---:|---:|
| baseline (HEA-1956) | neither fix | 33,724 | ~1.94 (derived) |
| A | fdatasync only | 35,726 | ~1.96, flat |
| B | + batched writes | 42,456 | ~1.96 |
| C | + ticket watermark (gated) | 30,317 | **3.64, inflated** |
| **D** | same binary as C (gated, sample 2) | **41,255** | **1.94, flat** |

**Run C was an anomaly and its fsync inflation should not be read as a mechanism.**
Sample D, the same binary minutes later, shows `fdatasync` flat at 1.84–1.94 ms
across the entire ladder — matching runs A and B and the raw device rate. An
earlier draft of this document attributed the residual to fsync cost growth on the
strength of run C alone; sample D falsifies that, and the attribution below
replaces it.

Sample D, the representative run:

| T | ops/s | batch | fsync ms/batch | serial ns/entry | of which `signal` |
|--:|------:|------:|---------------:|----------------:|------------------:|
| 1 | 484 | 1.00 | 1.918 | 14,774 | 1,062 |
| 4 | 926 | 1.76 | 1.839 | 11,468 | 1,938 |
| 16 | 3,992 | 7.66 | 1.849 | 6,723 | 2,958 |
| 64 | 15,572 | 31.80 | 1.881 | 4,566 | 3,068 |
| 128 | 29,098 | 65.40 | 1.917 | 4,637 | 3,450 |
| 256 | **41,255** | 100.79 | 1.945 | 4,584 | **3,554** |

The device term is now constant, exactly as group commit intends. The whole
residual is the serial term, and **`signal` is 78% of it** (3,554 of 4,584
ns/entry) — 358 µs per batch to release ~100 writers.

**Arithmetic on the remaining gap.** At T=256 the cycle is 2,407 µs, of which
1,945 µs is `fdatasync` and 462 µs is serial. Driving the serial term to zero
gives `100.79 / 1.945 ms` = **51,820 ops/s — which would clear T4.** So the target
is reachable without touching the durability guarantee, and the single line item
standing between here and there is the cost of waking blocked writers.

**Why the broadcast did not fix it.** Releasing K blocked threads costs O(K)
regardless of how many syscalls you use: ~3.5 µs per thread of futex wake plus
context switch, landing on 16 cores. `notify_all` also wakes writers whose ticket
is *not* yet covered — those that arrived during the fsync and belong to the next
batch — which re-check the watermark and go back to sleep. That is a genuine
thundering herd, and it is why signalling got marginally *worse* (2,584 →
3,554 ns/entry) rather than better.

**This is a design limit, not a tuning problem.** Any design in which every writer
blocks a thread and must be individually woken pays O(threads-in-flight) per batch.
Escaping it means not parking a thread per in-flight write — i.e. a
completion/async acknowledgement path rather than 256 blocked `spawn_blocking`
threads. That is an architectural change well beyond this issue, and it is what
the follow-up should evaluate.

## 6. Measurement honesty — variance on this host

Four runs of the write ladder produced T=256 figures of 35,726 / 42,456 / 30,317 /
41,255. Three cluster at 35–42 k with `fdatasync` flat; one (run C) sat at 30 k
with `fdatasync` inflated to 3.64 ms. **Grade T4 on a quiet, dedicated host, not
this shared workstation.** Hazards observed directly:

- A co-resident agent's HTTP benchmark (HEA-1957) ran during one pass at loadavg 24
  on 16 cores and roughly halved every number. That run was discarded, not
  reported. The same agent also `git stash`-ed this work mid-run to land its own
  commit; it was recovered from `stash@{0}`.
- A long-lived idle `cargo-watch` defeats a naive `pgrep cargo` idle gate; gate on
  `rustc|rust-lld` instead. Note also that `pgrep -c` prints `0` *and* exits
  non-zero on no match, so `$(pgrep -c … || echo 0)` emits two lines and breaks the
  comparison.
- Sample D's own device-calibration probe returned 234 fsyncs/s (against 515–541 in
  every other run), so that run's `T × F / W` ceiling column is garbage and reads
  as ">100% efficiency". Its *measured throughput* and *phase decomposition* are
  unaffected — one more reason to stop reporting that ratio (§1).

The reproducible results are the mechanism measurements — the phase split, the
fdatasync effect, and the wakeup cost — consistent across every run.

---

## What changed in the tree

| commit | change |
|---|---|
| `65e8185f` | fdatasync + one-syscall batched WAL commit; phase instrumentation |
| `2264195c` | O(1) commit signalling via a ticket watermark |
| `dba71183` | clippy `too_many_lines` + rustfmt |
| `f250c5dc` | CHANGELOG entry |
| `bbf49734` | pin the fdatasync/fsync split; FaultFs `datasync_count` |

`make check` green: clippy `-D warnings`, `fmt --check`, **4,504 tests**.
Durability unchanged — the WAL is synced before any write is acknowledged,
rotation still full-fsyncs, and `SyncMode::Async` remains rejected.
