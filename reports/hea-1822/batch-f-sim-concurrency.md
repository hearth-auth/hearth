# HEA-1822 Batch F — Simulation Concurrency/Failover Accuracy Audit

Scope: `simulation/src/lib.rs`, `simulation/src/tests/mod.rs`, and the 7 concurrency/failover test files.
Audit only — no tests were modified.

## Method
Read every test body against criteria #1–#5. Verified the framework claim (`lib.rs`
doc: "Uses `madsim` for deterministic scheduling and seed-based reproducibility")
against actual usage via grep.

## Key systemic finding
`madsim` is a declared dependency (`Cargo.toml:11`) but is **never used** anywhere
in the crate (`grep -rn madsim src/` → only doc comments + "for future madsim
integration" notes). Every in-scope test runs on **real** `#[tokio::test]`
(default current-thread) or **real** `std::thread::spawn`, with real `tempfile`
dirs and real wall-clock `tokio::time::sleep` polling. The `let seed = N; let _ =
seed;` locals are decorative — there is no seed loop, no seed exploration, no
deterministic replay. The tests DO create genuine contention/failover (which is
what matters for catching races), but they are **nondeterministic real-thread
races**, not the deterministic seeded simulation the module doc advertises. This
is a reproducibility/flakiness risk and a documentation-accuracy defect, not a
correctness hole.

## Per-file verdict

| File | Real code path? | Real contention/failover? | Negative path pinned? | Verdict |
|------|-----------------|---------------------------|-----------------------|---------|
| cluster_failover.rs | Yes (openraft + EmbeddedStorage) | Yes — partition, leader kill, rolling restart, snapshot | Yes — progress-after-loss + value asserts | STRONG (1 P3) |
| cluster_chaos.rs | Yes | Yes — 50 concurrent writers + leader kill; WAL replay; 2 leadership changes | Partial — split-brain branch often vacuous | GOOD (1 P2, 1 P3) |
| txn_raft_concurrent.rs | Yes (raft PutIfAbsent) | Yes — `tokio::join!` same-key race | Yes — exactly-one-winner, loser=false | STRONG |
| txn_concurrent.rs | Yes (identity engine) | Yes — 2 threads same txn_id | Yes — exactly one Ok, one `TransactionTokenReplayed` | STRONG (dead `seed`) |
| txn_single_use.rs | Yes | Sequential crash-recovery (by design) | Yes — `matches!(Replayed)` | GOOD |
| approval_cas.rs | Yes | Yes — thread approve/deny race; WAL-header crash inject | Yes — one wins, loser=`ApprovalRequestNotPending` | GOOD (2 P3) |
| rbac_concurrent_assignments.rs | Yes | Concurrent, but on distinct keys | Final-set asserts only | GOOD (2 P3) |

## Defect list

- **[CRITERION 5]** simulation/src/lib.rs:2 — (whole batch) — Module documents
  "deterministic scheduling and seed-based reproducibility" via `madsim`, but
  `madsim` is unused; all in-scope tests are real-thread/real-tokio nondeterministic
  races and the `seed` locals are dead (`let _ = seed`). Misleading determinism
  claim + flakiness/non-reproducibility risk. **P2**

- **[CRITERION 4]** simulation/src/tests/cluster_chaos.rs:486 —
  `simulation_leader_kill_mid_write_sequence` — The AC-5(b) split-brain / all-or-nothing
  check is gated on uncommitted keys existing (`if committed.contains_key(&i) {
  continue; }`). With a 12 s per-write retry that spans the election window, all 50
  writes normally commit, so the negative branch (partial visibility across survivors)
  is skipped and never actually exercised. The headline "split-brain violation" assert
  is usually vacuous. **P2**

- **[CRITERION 1]** simulation/src/tests/cluster_chaos.rs:633 —
  `simulation_write_contention_across_leadership_changes` — Named "write contention"
  but writes are issued in a **sequential** `for i in 0..10` loop (single actor); the
  only contention is the leadership change between rounds. No concurrent writers race.
  Failover invariant is still valid; the "contention" framing overstates it. **P3**

- **[CRITERION 2/B]** simulation/src/tests/cluster_failover.rs:564 —
  `simulation_leader_kill_and_election` — AC-2(c) uses
  `cluster.read_from(sidx, &[i]).unwrap_or_default()` in an assertion (anti-pattern B:
  `unwrap_or_default` in a test assert). Not vacuous here (compared against a non-empty
  `vec![i*10]`, so an absent key → empty vec still fails), but it is the forbidden
  pattern and should assert `Some(..)` like AC-2(a). **P3**

- **[CRITERION 2/C]** simulation/src/tests/approval_cas.rs:120 —
  `simulation_approval_cas_create_crash_discards_partial_record` — Doc claims it
  "mimics a crash mid-create of a third request," but it appends a 4-byte orphan
  length header **after** two clean creates. It actually validates trailing-garbage /
  truncated-tail discard at WAL replay, not a partial create rollback. Real path, but
  the claimed scenario is overstated. (Same pattern at approval_cas.rs:320, Test 3.) **P3**

- **[CRITERION 3/note]** simulation/src/tests/approval_cas.rs:212 —
  `simulation_approval_cas_transition_crash_leaves_recoverable_state` — The "crash after
  delete(pending_key)" is simulated by a raw `storage.delete` + clean shutdown, not an
  injected crash. Acceptable proxy for the idempotent-recovery invariant; noted for
  accuracy. **P3**

- **[CRITERION 1]** simulation/src/tests/rbac_concurrent_assignments.rs:41 —
  `concurrent_assign_unassign_converge_to_consistent_set` — Concurrent assigns target
  **4 distinct roles / distinct assignment keys**, so there is no same-key contention
  and no lost-update-on-shared-key coverage; the test validates index consistency +
  no-tear under concurrency (its stated oracle), not a CAS race. Genuinely concurrent
  (4 writers + 8 resolvers), so not sequential, but weaker than a same-key race. **P3**

- **[CRITERION 2/A]** simulation/src/tests/rbac_concurrent_assignments.rs:91 —
  `concurrent_assign_unassign_converge_to_consistent_set` — The 8 concurrent
  `resolve_permissions` handles discard their result (`let _ = ...expect("resolve ok")`),
  so mid-race resolves only assert "did not error/panic," not correctness. Final
  post-quiescence resolve does assert values, so overall test is non-vacuous; the
  in-race resolvers are a weak liveness check. **P3**

- **[CRITERION 5]** simulation/src/tests/txn_concurrent.rs:102 (also :175) —
  `simulation_txn_issue_concurrent_exactly_one_wins` / `..consume..` — `let seed = 70u64;
  let _ = seed;` is dead decoration that implies seed-based exploration which does not
  exist. Cosmetic; the race itself (2 real threads, same key) is correct and strong.
  **P3**

## Notes (accepted, not defects)
- Fixed `tokio::time::sleep` calls in cluster tests are inside deadline-bounded polling
  loops and carry `// AUDIT: justified-sleep` markers — acceptable for Raft convergence
  (no event-driven metric-wait API), not counted as anti-pattern E.
- `txn_raft_concurrent.rs` and `approval_cas.rs` Test 4 correctly pin the negative path
  (loser variant), satisfying criterion #4.
- All tests drive real `EmbeddedStorageEngine` / `openraft` / `EmbeddedIdentityEngine` —
  no mocks (criterion #3 clean across the batch).
