# HEA-1919 — CTO review: WAL group commit (HEA-1915)

**Commit reviewed:** `54b5df4b` on `feature/perf-updates-7-28-26`
**Files:** `src/storage/wal.rs`, `simulation/src/tests/wal_group_commit.rs`
**Verdict:** **CHANGES REQUESTED** — the algorithm is correct, but there is one
new permanent-hang failure mode, and the two invariants the issue asks me to
certify (batch-wide error propagation, rotation atomicity) are not covered by
any test.

---

## What holds up

I walked all six review items. Four are correct as claimed:

**Item 1 — lock ordering (`group → file → rotation`).** Correct, and stronger
than claimed: `group` is *released* before `file` is acquired
(`lead_group_commit` drains under `group`, drops the guard, then `commit_batch`
takes `file`). The only real nesting is `file → rotation`, which matches the
pre-existing ordering inside `rotate_locked`. Slot signalling happens after the
closure returns, so no lock is held across `notify_one`. No inversion, no
deadlock cycle.

**Item 2 — durability.** A slot's `done` flag is set only after the `sync_all`
inside `commit_batch`'s closure has returned, and the closure short-circuits on
any earlier write error. No caller can observe `Ok` for bytes not covered by a
completed fsync. The invariant holds. (The *test* for it does not — see F2.)

**Item 3 — nonce ordering.** Only the leader writes, `record_num` is assigned
and the bytes emitted inside the same `file`-mutex critical section, in queue
order. `scan_records` (`src/storage/wal.rs`) derives `record_num` **positionally**
from a counter starting at 0 — so any on-disk ordering violation fails the AEAD
tag and truncates replay. The ordering test is therefore non-vacuous. Good.

**Item 6 — five simulation tests pass.** Confirmed locally:
`cargo nextest run -p hearth-simulation wal_group_commit` → **5 passed, 51 skipped**
(run ID `dd5cc023`). Worth noting: the sync-failure test completed in **0.046 s**
despite configuring a 10 ms sync latency to force all 4 writers into one batch —
strong evidence the intended batch never formed and the test passed purely on
its `errs >= 1` floor. See F2.

**Item 5 — `SyncMode::None` fast path.** `SyncMode` has exactly two variants, so
`!= EveryWrite` ⇒ `None`, and `write_entry_no_sync` is a faithful extraction of
the old body minus the fsync. Behaviourally unchanged.

Also verified: `rotate_locked` does call `pre_rotate_fn`, and `engine.rs:443`
registers a full memtable→SST flush closure. So the comment "subsequent batches
rely on `rotate_locked` calling `pre_rotate_fn`" is accurate, and HEA-1050's
crash-loss window stays closed. Dropping the *followers'* `pre_rotate` closures
is safe today only because all four call sites in `engine.rs` pass the identical
`|| self.trigger_flush()`. That coupling is implicit and undocumented (N3).

---

## Findings

### F1 — HIGH — Leadership is not released on unwind: one panic hangs every WAL writer forever

`lead_group_commit` sets `leader_active = true` and clears it only on the normal
"queue empty" exit path. There is no RAII guard and no `catch_unwind`.

`commit_batch` calls `pre_rotate()` — which is `engine.rs`'s memtable flush
closure, real code that acquires locks, writes SSTs, and touches the key
registry. If anything under it panics (or anything else in the closure does),
the unwind passes straight through `commit_batch` and `lead_group_commit` and
out of `append_with_pre_rotate`, leaving `leader_active == true` permanently.

Failure sequence:
1. Leader L panics inside `pre_rotate` during rotation.
2. `leader_active` stays `true`; any slots already in `pending` are never
   signalled — those threads block on their condvars forever.
3. Every subsequent `append` pushes a slot, observes `leader_active == true`,
   becomes a follower, and waits on a condvar no one will ever notify.
4. Result: the entire write path hangs silently. No error, no timeout, no
   poisoned-mutex signal. The process must be killed.

This is a **regression in failure mode**, not just a missing nicety. The old
code held the `file` mutex across `pre_rotate`, so the same panic poisoned that
mutex and every later `append` returned `Err` immediately — fail-fast and
observable. Group commit converts that into an unbounded silent hang.

*Fix:* wrap leadership in a guard whose `Drop` sets `leader_active = false`,
drains `pending`, and marks every drained slot `done` with an error. That makes
the unwind path degrade to the old fail-fast behaviour.

### F2 — HIGH — The headline durability claim is not tested

The issue asks me to certify that "sync failure propagates the error string to
**every slot** in the failed batch." `group_commit_sync_failure_propagates_to_all_batch_members`
does not test that:

```rust
assert!(errs >= 1, ...);   // passes if only the leader got the error
assert!(errs <= N, ...);   // tautology — errs is incremented at most once per writer
```

`errs >= 1` would pass with propagation entirely removed (leader errors, all
followers wrongly return `Ok`) — i.e. it passes in exactly the scenario that
would be a silent data-loss bug. `errs <= N` is unfalsifiable by construction
and carries zero information (TESTING.md anti-pattern class: vacuous assertion).

The test's own comment concedes the gap ("the guarantee is: *any* writer whose
bytes hit the failed sync gets Err") because batch membership isn't observable
from outside. That is the thing to fix: make membership deterministic — a
`#[cfg(feature = "test-hooks")]` barrier that holds the leader inside
`commit_batch` until N slots are queued, then assert `errs == N` exactly.

Until then, the change's central durability property is asserted in the commit
message but unverified in CI.

### F3 — HIGH — Rotation under group commit has zero test coverage

Review item 4 is the batch-rotation atomicity claim. All five tests set
`max_size: u64::MAX`, so **`commit_batch`'s rotation branch never executes in
any of them.** The riskiest new code — rotate + `record_counter` reset to 0 +
new DEK, mid-batch, with concurrent appenders queued behind the file mutex — is
entirely untested.

Needed: a concurrent-writers test with a small `max_size` that forces several
rotations, then re-opens and asserts the entries decrypt (a counter-reset bug
here means nonce reuse under the *old* DEK — a confidentiality bug, not just a
correctness one).

### F4 — MEDIUM — The leader can be trapped indefinitely; unbounded tail latency

`lead_group_commit` loops until the queue is empty. The leader's own slot is
satisfied in batch 1, but it keeps committing *other* writers' batches until
drain. Under sustained concurrency the queue may never empty, so an arbitrary
writer thread is held for an unbounded time doing work for others, long after
its own write was durable.

For a change whose stated purpose is lifting the `session_create` write ceiling,
this trades mean throughput for a very long p99.9 on whichever caller draws the
leader role — and it pins a `spawn_blocking` thread for that whole period.

*Fix:* cap iterations (or exit once the leader's own slot is done) and promote
the head of `pending` to leader before returning.

### F5 — MEDIUM — Slot-mutex poisoning silently strands a writer

```rust
if let Ok(mut state) = slot.state.lock() { ... }
```
On a poisoned slot mutex the signal is skipped entirely and that writer waits
forever. Use `unwrap_or_else(PoisonError::into_inner)` so `done` is always set —
the state is a plain bool + Option<String>, so recovering from poison is safe.

### F6 — MEDIUM (pre-existing, widened) — Ok'd writes discarded on replay after a write fault

If a write fails mid-batch, the torn record stays in the file; the leader loops
on to the next batch, whose entries are written *after* the torn bytes, fsynced,
and acked `Ok`. `scan_records` stops replay at the first CRC mismatch, so those
acked entries are silently discarded on recovery.

This existed before group commit, and `concurrent_crash_mid_batch_leaves_valid_prefix`
encodes it as expected behaviour — but group commit widens the window from one
record to a whole batch. Recommend a follow-up: fence the WAL after any write
error so subsequent appends fail rather than acking data that replay will drop.

---

## Nits

- **N1** `sync_count: Arc<AtomicU64>` — never cloned out of `self`; a plain
  `AtomicU64` suffices.
- **N2** `approx_total` decides rotation once per batch, so a batch larger than
  `max_size` still lands in one segment and overshoots the cap. Self-correcting,
  but worth a comment.
- **N3** Followers' `pre_rotate` closures are silently dropped. Safe only because
  every `engine.rs` call site passes the same closure. Document that precondition
  on `append_with_pre_rotate`.
- **N4** `concurrent_crash_mid_batch_leaves_valid_prefix` asserts a count
  (`>= N*K_BEFORE`) but its doc claims "no holes" — the assertion can't
  distinguish phase-1 entries from phase-2 ones. Assert on key contents.

---

## Disposition

Ship-blocking: **F1** (new silent-hang failure mode) and **F3** (untested
rotation path, with a nonce-reuse blast radius). **F2** is ship-blocking for the
*claim* — the commit message asserts a durability property CI does not check.
F4–F6 and the nits are follow-ups.
