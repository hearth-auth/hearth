# HEA-1925 — WAL group commit, review round 3

**Verdict: APPROVE** (2 non-blocking follow-ups filed)
**Reviewer:** CTO · **Date:** 2026-07-29
**Under review:** HEA-1924 `LeaderGuard.in_flight` fix (working tree on `feature/perf-updates-7-28-26`, on top of `919b66a4`)
**Predecessors:** HEA-1919 rounds 1 & 2 (both CHANGES REQUESTED)

## Verification performed

Built and ran in an isolated detached worktree (`/tmp/hea-1925-verify`) — the shared
worktree's `wal.rs` is unreliable for this check.

| Gate | Result |
|---|---|
| `cargo nextest run -p hearth-simulation wal_group_commit` | **7/7 pass** |
| Same suite, `wal.rs` fix reverted, tests kept | **1 fail** (the new regression test) |
| `cargo fmt --check` | clean |
| `cargo clippy -p hearth --lib --all-targets` | clean |

## F1 — in-flight batch stranded on leader panic — **FIXED**

`lead_group_commit` now assigns `guard.in_flight = b` **inside the same
`self.group` lock acquisition that drains `pending`** (`wal.rs:1088-1105`). There is
no window between drain and guard-registration: the two happen under one critical
section, and the only operation between them (a `Vec` move) cannot panic or return
early. `Drop` signals `in_flight` first, then late arrivals still in `pending`.

**The regression test genuinely pins the invariant.** With `wal.rs` reverted to
`919b66a4` and the test retained:

```
assertion `left == right` failed: all 3 writers must return after a leader
panic; only 1 did — in-flight batch members are stranded on their condvars
  left: 1
 right: 3
```

Only the panicking leader returned; both followers hung until the 5 s timeout —
exactly the round-2 defect. With the fix, all 3 return. This is a real red→green
transition, not a test that passes either way.

## Tests — round-1 complaints **RESOLVED**

- **Tautological propagation assert:** `group_commit_sync_failure_propagates_to_all_batch_members`
  now asserts `assert_eq!(errs, N)`, not `errs >= 1`. The `commit_barrier` test hook
  makes batch membership deterministic (all N writers push before the leader drains),
  so `errs == N` is a genuine invariant rather than a lower bound that any single
  error satisfies.
- **Rotation never exercised:** no longer true. `group_commit_rotation_does_not_cause_nonce_reuse`
  runs `max_size: 300` with 4×30 concurrent writes sized so *every* batch overshoots
  the cap and rotates, then re-opens and requires `read_all()` to succeed — a nonce
  collision across a rotation would fail the AEAD tag. The new panic test's
  `max_size: 1` does *not* add rotation coverage (it panics in `pre_rotate` before
  `rotate_locked` runs), but it isn't claimed to.

## Durability invariants — **HOLD**

- **fsync-before-ack.** In `commit_batch`, all `write_all` calls and the single
  `file.sync_all()?` execute inside the inner closure; the per-slot
  `state.done = true` loop runs only *after* that closure returns. No slot is acked
  before its bytes are fsynced. A failing `sync_all` populates `err_msg` for every
  member, so no writer in a failed batch can return `Ok` — pinned by the `errs == N`
  assert above.
- **Positional nonce ordering (HEA-1853/1854) under coalescing.** Record numbers are
  assigned inside the file-mutex critical section, in queue order, one entry at a
  time; `nonce = counter_nonce(record_num)` and `aad = record_num.to_le_bytes()`.
  Rotation (which resets `record_counter`) happens under that same file mutex and
  strictly before any record number in the batch is assigned, so on-disk order always
  matches record-number order. Coalescing changes how many entries share an fsync,
  not their numbering.
- **Fencing.** A write fault sets `self.fenced`, rejecting all subsequent appends
  rather than acking data that replay would discard. Preserved.

## Non-blocking follow-ups (filed as a child of HEA-1915)

Both are latent and gated on `self.group` mutex *poisoning*; neither is reachable on
any path the suite exercises, and neither blocks HEA-1867.

**R1 — `in_flight` is not cleared after a successful `commit_batch`.**
`commit_batch` always returns `Ok` and marks every slot `done=true, error=None` before
returning, but `guard.in_flight` still holds those committed slots. If the subsequent
promotion block returns early via `self.group.lock().map_err(...)?` (`wal.rs:1112`) —
which does **not** set `disarmed` — `Drop` overwrites each slot's `error` with
`"WAL leader exited unexpectedly; write failed"`. A writer that has not yet
re-acquired its slot lock would then report failure for a write that is durably
fsynced. One-line fix: `guard.in_flight.clear();` immediately after `commit_batch`
returns, which also tightens the field's invariant to "drained but not yet committed."

**R2 — `Drop` skips all signalling when the group mutex is poisoned.**
`if let Ok(mut gs) = self.group.lock()` silently no-ops the entire guard body on
poisoning, stranding exactly the writers the guard exists to rescue. Every *slot*
mutex in the same function uses `unwrap_or_else(|e| e.into_inner())`; the group mutex
should be poisoning-tolerant too. Pre-existing since `54b5df4b`, not introduced here.

## Disposition

APPROVE. HEA-1915, HEA-1919 and HEA-1924 may be marked done; HEA-1867 re-measurement
is unblocked.
