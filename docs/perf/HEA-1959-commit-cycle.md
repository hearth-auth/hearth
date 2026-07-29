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

---

## Outcome first

**T4 does not clear 50,000 ops/s.** The issue asked for a straight answer if it did
not, so: it did not, and the residual is no longer the thing the issue named.

The mechanism the issue asked me to find is identified from instrumentation and
substantially removed. What remains is a *different* bottleneck, and this document
names it rather than restating the old one.

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
| `write` | 5,150 | **395** | **13× better** |
| `encrypt` | 1,250 | **611** | 2× better |
| `signal` | 2,584 | **3,274** | **no better** |
| total serial | 8,984 | **4,279** | 2.1× better |

**The signalling change did not deliver.** Collapsing N `notify_one` calls into
one `notify_all` removed the syscalls but not the work: waking N waiters is O(N)
inside the kernel either way, measured at **428 µs per batch** for a single
`notify_all` releasing ~130 threads (~3.3 µs per woken thread). This is stated
plainly because HEA-1955 was closed on a prediction that was never checked against
a measurement; this one was, and it was wrong. The change is retained — it is
simpler, it removes a per-writer mutex and condvar, and it eliminates the
lost-wakeup failure mode by making the wait condition a monotone watermark — but
it should not be credited with throughput.

## 5. The residual is now the fsync itself, not coalescing

Final artifact, T=256: fsync occupies **84–97% of the entire measurement window**.
The leader is essentially always inside `sync_data`.

| T | ops/s | batch | fsync ms/batch | serial ns/entry | fsync % of window |
|--:|------:|------:|---------------:|----------------:|------------------:|
| 1 | 492 | 1.00 | 1.881 | 14,607 | 92.6% |
| 4 | 1,039 | 2.00 | 1.854 | 8,781 | 96.3% |
| 16 | 3,654 | 7.55 | 2.009 | 6,358 | 97.3% |
| 64 | 11,310 | 31.72 | 2.644 | 4,571 | 94.3% |
| 128 | 15,091 | 61.33 | 3.629 | 5,373 | 89.3% |
| 256 | 30,317 | 130.73 | 3.639 | 4,279 | 84.4% |

Serial work is down to 13% of the cycle at T=256. **The open question is why
`fdatasync` costs 3.64 ms at batch = 130 when it costs 1.88 ms at batch = 1 and
was flat across batch size in the isolated fix-1 run.** Two candidates, in
order of my confidence:

1. **Competing flush I/O.** By the high-`T` cells the corpus has grown enough to
   trigger memtable→SST flushes and compaction, whose own writes and fsyncs
   contend with the WAL sync. This is consistent with the effect being absent in
   the shorter isolated run and with it appearing between T=64 and T=128.
2. **Data volume.** ~130 KB per batch versus ~1 KB. Plausible but too small to
   explain 1.75 ms on this device.

Distinguishing these is the next concrete step, and it is a different problem
from the one this issue was opened on.

## 6. Measurement honesty — variance on this host

T=256 measured **30,317** in the final gated run and **42,456** in an earlier run
of the same binary. That spread is larger than the effect sizes being argued
about, so **no T4 verdict should be graded on this workstation.** Contributing
factors observed directly during this work:

- A co-resident agent's HTTP benchmark (HEA-1957) ran during one pass at loadavg
  24 on 16 cores and roughly halved every number. That run was discarded, not
  reported.
- A long-lived idle `cargo-watch` process defeats a naive `pgrep cargo` idle gate;
  gate on `rustc|rust-lld` instead.

The banked, reproducible results are the *mechanism* measurements — the phase
split and the fdatasync effect — which were consistent across every run. The
graded T4 throughput number needs a quiet, dedicated host.

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
