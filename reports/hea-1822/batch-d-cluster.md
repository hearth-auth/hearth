# HEA-1822 Phase 3 Accuracy Audit — Batch D (cluster)

Audit only. No tests were modified. Anti-pattern taxonomy A–I per `docs/specs/TESTING.md`.

## Scope & test inventory

| File | Inline tests | Verdict |
|------|-------------|---------|
| `src/cluster/server.rs` | **0** (no `#[cfg(test)]` block) | N/A — untested module |
| `src/cluster/log_store.rs` | 6 | MOSTLY CLEAN — 1 defect (append path bypassed) |
| `src/cluster/network.rs` | 3 | MOSTLY CLEAN — 1 defect (unpinned error variant) |
| `src/cluster/engine.rs` | 11 | MOSTLY CLEAN — 2 defects (zero-assert, untested false branch) |
| `src/cluster/state_machine.rs` | 9 | CLEAN — 1 minor (weak concurrency claim) |
| `tests/cluster_admin_endpoints.rs` | 12 | CLEAN — auth guards, single-node-only (labeled) |
| `tests/cluster_grpc_loopback.rs` | 1 | CLEAN — genuine 3-node quorum/replication |

## PROMINENT NOTE — single-node vs real consensus

The **only** test in this batch that forms a multi-node quorum and drives real Raft
consensus is `tests/cluster_grpc_loopback.rs::three_node_grpc_loopback_replicates_ten_writes`
(3 `build_clustered` engines, real mTLS gRPC, leader election, 10-write convergence). It is
a strong, real-code-path test.

Everything else exercises **single-node / no-consensus** paths:
- `engine.rs` `single_node_*` (5 tests) test `ClusterEngine::single_node` passthrough only —
  correctly named, no false consensus claim, but note zero Raft coverage here.
- `cluster_admin_endpoints.rs` (12 tests) build `AppState` with **no Raft engine**, so every
  cluster endpoint returns 503 by construction. They validate auth-guard ordering
  (401/403/503) only — never real bootstrap/status/transfer behavior. Multi-node AC-1/2/3
  are explicitly deferred to HEA-738 (documented in the file header). Legitimate, but the
  suite gives **no** functional coverage of the cluster handlers' happy path.
- `log_store.rs` / `state_machine.rs` unit tests drive real openraft trait impls
  (truncate/purge/vote/apply/snapshot) in-process without a cluster — these are the correct
  layer-level tests and DO reach the real storage logic (contra the historical HEA-720
  "unreachable" concern for those two files).

## Defects

- **[CRITERION 3]** src/cluster/log_store.rs:483 — `append_and_read_range` — the "append"
  is performed by helper `append_entries_with_signal` (line 588) which **bypasses the
  `RaftLogStorage::append` trait method** and writes rows directly into `LOG_TABLE` via a raw
  redb write txn ("bypass trait to test raw storage"). The real `append` impl (line 339) is
  never exercised by this test; only the `try_get_log_entries` read path is real. Name/claim
  says append; append-under-test is substituted. (Real `append` IS covered end-to-end by the
  grpc_loopback replication test, so not a coverage hole, but the unit test is mislabeled.)
  Severity **P2**. NOTE: truncate/purge tests reuse the same bypass only for *setup* while
  exercising the real `truncate()`/`purge()` — those are acceptable.

- **[CRITERION 4]** src/cluster/engine.rs:877 — `single_node_reads_ok_always_true` +
  untested false branch — asserts only the trivially-true single-node branch of `reads_ok`
  (`raft.is_none() || reads_allowed`). The security-relevant **read-fencing false branch**
  (`reads_allowed == false` on replication lag) is not asserted here, and the grpc_loopback
  test deliberately sets `read_lag_threshold_ms: 10_000` to *avoid* tripping it — so the lag
  read-block is never exercised anywhere in the suite. Negative/enforcement path missing.
  Severity **P2**.

- **[CRITERION 2 / anti-pattern A]** src/cluster/engine.rs:926 —
  `check_clock_skew_does_not_panic_on_garbage_payload` — zero-assert body: calls
  `check_clock_skew` three times with garbage and asserts nothing; passes purely on absence
  of panic. No behavioral assertion (e.g. that a skew *is* detected/logged for a skewed
  payload). Severity **P3**.

- **[CRITERION 4 / anti-pattern F]** src/cluster/network.rs:297 —
  `vote_returns_network_error_on_connection_failure` — asserts only `result.is_err()`; does
  **not** pin the rejection variant, unlike its sibling
  `append_entries_returns_network_error_on_connection_failure` (line 266) which correctly
  `matches!(e, RPCError::Network(_))`. Would pass on any error kind. Severity **P3**.

- **[CRITERION 2]** src/cluster/state_machine.rs:743 — `concurrent_reads_during_snapshot_build`
  — the spawned "concurrent reader" discards all results (`let _ = engine.get(...)`), so the
  concurrency guarantee named in the test is not asserted; only post-hoc snapshot completeness
  (20 entries) is checked. Effectively a "does not deadlock/panic" test. Severity **P3**.

## Clean / behaviorally sound (representative)

- `log_store.rs`: `vote_persistence_survives_reopen` (durability across reopen),
  `truncate_removes_entries_from_index`, `purge_updates_last_purged_state`,
  `get_log_state_empty_store`, `committed_roundtrip` (incl. None case) — real openraft impls,
  specific assertions.
- `engine.rs`: `compute_lag_ms` suite (caught-up=0, no-log=0, proportional=50, underflow-guard=0)
  — good boundary/edge coverage including the underflow non-panic case.
- `state_machine.rs`: `put/delete/batch_command_*`, `last_applied_tracks_log_index`,
  `snapshot_roundtrip_identical_keyspace` (build on A → install on B → key-by-key verify),
  `snapshot_compress_decompress_roundtrip`, `get_current_snapshot_*` — real state machine,
  strong assertions.
- `cluster_admin_endpoints.rs`: 401/403/403-tenant/503 matrix pins exact `StatusCode` per
  endpoint incl. HEA-763 tenant-realm privilege-escalation guard.
- `cluster_grpc_loopback.rs`: real 3-node quorum, election, replication convergence, per-node
  read consistency — the anchor real-consensus test.

## No dead tests
No `#[ignore]`, no commented-out assertions, no stale markers found in scope.
