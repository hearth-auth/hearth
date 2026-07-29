# HEA-1945 · T4 — `session_create` fsync-bound: CTO triage

**Status:** triaged; `W` 3→2 fix landed (`abf179ba`); HEA-1948 (engine fix) in progress,
HEA-1949 (measurement) delivered and folded in below; units-restatement escalated to the board.
**Parent:** HEA-1940 (PERFORMANCE_REPORT v2) · **Ancestor:** HEA-1867
**Source data:** `docs/perf/artifacts/c7-saturation-v2-raw.json` (HEA-1875 C7-v2, HEAD `981516f1`)

---

## Outcome first

The issue framed T4 as "316× below target, close it with Option A or Option B". Both
framings are wrong in an important way, and the arithmetic below is the reason:

1. **The device fsync rate is the binding constraint, and it is flat.** It does not
   improve with threads. Every ops/s number on this path is
   `device_fsync_rate ÷ fsyncs_per_write`, and the engine controls only the denominator.
2. **T4 cannot pass *at the bench's 16-thread ladder* — by arithmetic, not engine
   quality.** A *perfect* engine (one WAL record per op, perfect coalescing) tops out at
   **≈6,700 ops/s** there against a 50,000 target, because the measurement caps in-flight
   concurrency at 16 and durable-write throughput is proportional to concurrency.
   *(Superseded in scope by HEA-1949 — see the post-hoc section: with the ladder extended
   to T=256 and `F` measured directly at 528.7/s, the device ceiling is 67,674 ops/s,
   **above** the target. The hardware supports T4; the audit chain lock is what does not.)*
3. **Option B (`SyncMode::Async`) is rejected as a default.** It violates the standing
   ground rule that the WAL is fsync'd before a write is acknowledged and must survive
   `kill -9`. Buying a throughput number by silently deleting the durability guarantee
   is not closing the gap, it is changing the product.
4. **`ops/s/core` is a category error for this operation.** It is a compute framing
   applied to an I/O-bound one. T4's *units* need restating against a stated device fsync
   rate and concurrency level; its *magnitude* stands. That is a board/spec decision,
   escalated below.

---

## Evidence: the fsync rate is flat

Derived from the C7-v2 raw artifact (`fsyncs/s = agg_ops_s × fsyncs_per_write`):

| threads | ops/s | fsyncs/write | **fsyncs/s** | p99 (ms) |
|--------:|------:|-------------:|-------------:|---------:|
|  1 | 111.0 | 3.000 | **333** |  41.7 |
|  2 | 166.5 | 2.586 | **431** |  19.9 |
|  4 | 244.3 | 1.654 | **404** |  32.2 |
|  8 | 252.1 | 1.727 | **435** |  63.3 |
| 16 | 254.3 | 1.931 | **491** | 117.0 |

The device sustains **≈419 fsyncs/s** (spread 1.47× across a 16× thread range). It is
saturated from 2 threads onward. This single number was not in the issue description and
it determines everything else.

Two consequences the raw ops/s column hides:

- **Group commit did work, then regressed.** `fsyncs/write` fell 3.00 → 1.65 (1T → 4T),
  which is real coalescing. But it then rose again to 1.93 at 16T while p99 blew out
  41.7 → 117.0 ms. Past 4 threads the group-commit path is *losing* ground — convoy
  behaviour, not saturation.
- **The scaling exponent (+0.299) is not a lock-contention signal.** Throughput is flat
  because the fsync budget is flat. Adding cores to an I/O-bound operation cannot help.

## Evidence: where the 3 fsyncs come from

`create_session` (`src/identity/engine/mod.rs`) issued three separate durable writes:

| # | write | mechanism |
|---|-------|-----------|
| 1 | session body | `persist_session` → `storage.put` |
| 2 | user→session index | `storage.put` |
| 3 | `SessionCreated` audit event | `AuditEngine::append` → `put_batch` (4 keys, 1 record) |

Exactly the measured 3.0 fsyncs/write at 1 thread.

**The audit write is the hard floor.** `EmbeddedAuditEngine::append`
(`src/audit/engine.rs:461`) holds the per-realm chain lock across `storage.put_batch` —
i.e. across the WAL append *and its fsync wait*. Group commit can only coalesce writers
that are concurrently in flight, so at most **one audit append per realm can ever be in
flight**. That pins `fsyncs/write ≥ 1.0` and therefore `ops/s ≤ ≈419` for single-realm
traffic, no matter what else is fixed. Measured 254 is already within 1.7× of that
architectural ceiling.

## Feasibility model

With `F ≈ 419` fsyncs/s, `T` concurrent writers, `W` WAL records per op, and *perfect*
coalescing, aggregate throughput is `T × F ÷ W`:

| | W=3 (before) | W=2 (now) | W=1 (ideal) |
|---|---:|---:|---:|
| **T=16** (bench ladder) | 2,234 | 3,351 | **6,701** |
| T=32 | 4,467 | 6,701 | 13,402 |
| T=64 | 8,935 | 13,402 | 26,804 |
| T=128 | 17,870 | 26,804 | **53,609** |

The bench measures T=16. **6,701 ops/s is the best any engine can do there.** The 50,000
target is 7.5× beyond the ceiling of a perfect implementation under the measurement's own
concurrency. T4 as written cannot be passed; it can only be restated.

---

## What landed this heartbeat

**Fix W: 3 → 2 WAL records per `session_create`** (`src/identity/engine/mod.rs`).

The session body and the user→session index entry describe one fact and are now written
as one atomic `put_batch` (one WAL record, one fsync) via a new `persist_session_with`
helper. `persist_session` delegates to it with an empty extras list, so the cache-update
logic stays in exactly one place.

This is also a **correctness** fix, not only a perf one: the two writes were previously
non-atomic, so a crash between them could strand a user→session index entry pointing at a
session that was never persisted.

Expected effect: `fsyncs/write` 3.0 → 2.0 at 1 thread; predicted ≈165 ops/s (from 111).
Modest, because the audit floor is untouched — that is the point of the model above.

Pinned by `tests/session_create_write_amplification.rs`, written test-first: it asserts
the steady-state WAL-record count using `EmbeddedStorageEngine::wal_sync_count()` under
`SyncMode::EveryWrite`. It failed at 3 before the change (independently reproducing the
artifact's 3.0 figure) and passes at 2 after. It also asserts first-call cost equals
steady-state cost, so a one-time per-realm write can never hide inside the number.

---

## Children opened

- **HEA-1948** (`7de487e4`, PlatformEngineer) — split the audit chain lock off the durability wait.**
  The chain lock must
  serialize the hash-chain read-modify-write *and* the WAL enqueue order (releasing it
  before enqueue would let event N+1 reach the WAL ahead of event N and break chain
  recovery). It must **not** cover the fsync wait. Needs a storage API split:
  `enqueue → handle` under the lock, `await_durable(handle)` after release. Removes the
  one-audit-append-in-flight ceiling; unblocks coalescing to `W=2`.
- **HEA-1949** (`b2e58d59`, QA — delivered) — raise bench concurrency above the core count.** The 16-thread ladder caps
  in-flight writers at 16 and therefore caps measurable durable-write throughput at
  `16 × F`. The write sweep needs a concurrency ladder decoupled from core count
  (blocking writers are not CPU-bound), plus the device fsync rate recorded as a
  first-class field in the artifact so future runs are comparable across hosts.

Deferred, not opened: merging the audit event into the *same* WAL record as the session
write (true `W=1`). It requires an identity→audit API that returns pending writes instead
of performing them — a cross-layer change to the `AuditEngine` trait. Worth doing only
after HEA-1948 lands and is measured; sequencing it first would be speculative.

## Post-hoc: HEA-1949 results confirm the model — and correct me on one point

QA delivered HEA-1949 within the same heartbeat
(`docs/perf/HEA-1949-write-coalescing-results.md`). Its independent measurement confirms
the mechanism and **falsifies one of my conclusions in the favourable direction**:

| | my derivation | HEA-1949 (measured) |
|---|---|---|
| device fsync rate `F` | ~419/s (derived from ops×fsyncs) | **528.7/s** (direct: 200 sequential `sync_all`) |
| `W` after this change | 2 (predicted) | **2.000** (confirmed at T=1) |
| coalescing vs concurrency | plateaus, audit-lock-pinned | **confirmed** — 1.52 fsyncs/write flat from T=4 to T=256 |

Confirmed: batch size plateaus at ~0.65 ops/fsync and does **not** grow with concurrency
all the way to 256 writers. That is exactly the one-audit-append-in-flight signature, and
it is now measured rather than argued.

**Where I was wrong.** I wrote that T4 "cannot pass" and part of my board escalation
rested on the target being physically unreachable. That was an artefact of reasoning from
the T=16 ladder and a *derived* `F`. With the ladder extended and `F` measured directly,
the perfect-coalescing ceiling at T=256 is **67,674 ops/s — above the 50,000 target**. The
device supports T4. The gap is entirely the audit chain lock, and 50,000 needs ~190
concurrent writers, which a real server has and a 16-thread bench does not.

So the target is not absurd, and I withdraw the "unreachable" half of my escalation.

**Two mis-citations in the HEA-1949 write-up to fix before any of this reaches the board**
(flagged to QA, not silently corrected here):
- It attributes the `W` 3→2 drop to *HEA-1908* (streaming memtable flush). It was this
  issue — commit `abf179ba`. HEA-1908 does not touch the session write path.
- It names *HEA-1947* as the chain-lock fix. HEA-1947 is the parent ("close the 2
  remaining MISSes"); the chain-lock fix is **HEA-1948**.

## Escalated to the board (via HEA-1940)

T4's **units** need restating; its **magnitude** does not.

`50,000 ops/s/core` applies a compute framing to an I/O-bound operation. Durable-write
throughput scales with *concurrency* and the *device fsync rate*, not with cores — 190
blocked-on-fsync writers is the operative quantity, and it has no relationship to a core
count. Recommended replacement: **aggregate ops/s at a stated concurrency on a stated
device fsync rate**, with `fsyncs/write` as the engine-owned, actually-gradeable metric.
Keep the 50,000 magnitude: HEA-1949 shows the hardware clears it at T≈190.

Option B (`SyncMode::Async`) remains rejected as a default and is now also unnecessary —
the target is reachable *with* durability intact once HEA-1948 lands. Relaxed durability
would only ever be a non-default, opted-in mode with a documented RPO, and there is no
longer a performance argument for it.
