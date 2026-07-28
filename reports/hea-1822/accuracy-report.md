# HEA-1822 — Phase 3 Accuracy Audit: storage / WAL / cluster / simulation tests

Per-test accuracy audit per the accepted [HEA-1766](/HEA/issues/HEA-1766#document-plan) plan (Phase 3).
**Audit only — no tests were modified.** Defects feed the Phase 4 triage child.

Criteria: (1) name/claim matches assertions; (2) behavioral, not vacuous (taxonomy A–I,
`docs/specs/TESTING.md`); (3) real code path exercised (not a mock of the unit under test);
(4) negative/failure paths asserted where enforcement is claimed; (5) no stale `#[ignore]`,
commented-out asserts, or tests that pass if the feature is deleted.

Fan-out: 6 subagent batches (A–F). Per-batch detail retained in
`reports/hea-1822/batch-{a..f}-*.md`.

## Summary

| Batch | Scope | Tests | Clean | Defects |
|-------|-------|------:|------:|--------:|
| A | `storage/engine.rs`, `storage/wal.rs` | 62 | 56 | 6 (2 P2, 4 P3) |
| B | `storage/memtable.rs`, `sst.rs`, `tiered.rs` | 60 | 56 | 4 (1 P2, 3 P3) |
| C | `storage/{auto_size,encryption,key_registry,migrations,breach_corpus,error}.rs` | 74 | 66 | 8 (8 P3) + 1 coverage gap |
| D | `cluster/*` + `tests/cluster_*.rs` | 42 | ~37 | 5 (2 P2, 3 P3) |
| E | `simulation/` crash-recovery (10 files) | 26 | 16 | 7 (4 P2 + systemic P2, 3 P3) |
| F | `simulation/` concurrency/failover (7 files) | ~30 | most | 9 (systemic P2 + 1 P2, 7 P3) |
| **Total** | | **~336** | **~287** | **~39** |

**No P0 or P1 defects.** Committed-data-survives and exactly-one-winner invariants are
genuinely verified across the storage and simulation suites. All defects are P2/P3:
overclaiming names, non-load-bearing fault injection, unpinned error variants, and one
systemic documentation-accuracy issue (madsim advertised but unused).

## Systemic findings (highest triage value)

1. **[P2] madsim advertised but never used across the entire `simulation/` crate.**
   `simulation/src/lib.rs:2` and every module docstring claim "deterministic scheduling and
   seed-based reproducibility" via madsim. madsim is a declared dependency (`Cargo.toml:11`)
   but is used nowhere — all tests run on real `std::thread`/`#[tokio::test]` with real
   `tempfile`/`std::fs`. Every `let seed = N; let _ = seed;` is dead decoration; there is no
   seed loop, exploration, or deterministic replay. Only `realm_concurrent_io.rs` exercises the
   real `FaultFs` fault hook. Tests catch real races but are **nondeterministic** — a
   reproducibility/flakiness risk, not a correctness hole. (Batch E, F)

2. **[P2] Non-load-bearing corrupt-SST fault injection.** `sst_crash.rs` injects SSTs with
   all-garbage encryption headers; on reopen with `allow_missing_keks=true` they route to the
   missing-KEK skip branch and are never CRC/format-validated. The tests pass identically if the
   injection is deleted (data served from WAL). The real body-corruption path
   (`open()` → `Err`) is untested. (Batch E: `sst_crash.rs:30`, `:90`)

## Defect list (per batch, file:line + failed criterion)

### Batch A — engine / WAL
- **[C1] P2** `wal.rs:1034` `wal_fsync_durability_across_restart` — same-process drop→reopen
  reads from OS page cache; passes with fsync disabled. Does not prove fsync-before-ack.
- **[C2/C5] P2** `engine.rs:1739` `engine_compaction_succeeds_at_exact_min_sst_count` — every
  assert wrapped in `if sst_before >= 2`; no-ops (vacuous) if flush yields <2 SSTs.
- **[C4] P3** `engine.rs:1982` `wal_rotation_flushes_memtable_to_sst_before_truncating` — comment
  claims crash-loss simulation; never reopens/crashes, reads through live engine.
- **[C2/C1] P3** `engine.rs:1479` `engine_scan_merges_memtable_and_sst` — asserts `len() >= 4`
  of 5 keys; never verifies any key lived in SST vs memtable.
- **[C2] P3** `engine.rs:1918` `engine_data_is_encrypted_at_rest` — WAL-plaintext check guarded by
  `if wal_path.exists()`; silently skips if path changes.
- **[C2] P3** `engine.rs:1530` `engine_is_send_and_sync` — zero runtime asserts (compile-time
  trait check; has value but taxonomy A).

### Batch B — memtable / sst / tiered
- **[C1/C4] P2** `sst.rs:1220` `bloom_filter_rejects_different_realm_same_key_bytes` — discards the
  negative result (`let _ = filter.might_contain(...)`), asserts only positive; realm-rejection
  never asserted. (Real coverage exists at `sst.rs:1299`; this test is redundant/misleading.)
- **[C1/C2] P3** `tiered.rs:690` `proptest_random_access_correct_eviction` — only hard post-cond is
  `len() <= 20`; eviction *correctness* not verified.
- **[C2] P3** `tiered.rs:743` `proptest_power_law_converges` — asserts only `hot_in_tier >= 1` of 5;
  thin for a convergence property.
- **[C2] P3** `tiered.rs:656` `default_config_admits_every_promotion` — constant-assertion on a
  default value (documents a real contract; low severity).

### Batch C — storage misc
- **[F] P3 ×7** `encryption.rs:463,481,509,523,537,581,594` — seven security-relevant AEAD/KEK
  rejection tests assert bare `is_err()` without pinning `StorageError::Crypto`; would pass on an
  unrelated error (e.g. key-length branch).
- **[C] P3** `breach_corpus.rs:285,297` `is_pwned_finds_entry_at_{beginning,end}_of_corpus` — named
  for public `is_pwned` but assert the internal `binary_search` helper (drift documented in-body).
- **Coverage gap (not a defective test) [C4]** `migrations.rs` — two `Err(DeserializationFailed)`
  branches (`:57` chain-gap, `:65` incomplete-reach) have no negative test.

### Batch D — cluster
- **[C3] P2** `log_store.rs:483` `append_and_read_range` — "append" done via helper that bypasses the
  `RaftLogStorage::append` trait method (raw redb write); real `append` untested here (covered by
  grpc_loopback replication, so no hole, but mislabeled).
- **[C4] P2** `engine.rs:877` `single_node_reads_ok_always_true` — asserts only the trivially-true
  branch; the read-fencing false branch (replication-lag read-block) is untested anywhere
  (grpc_loopback sets `read_lag_threshold_ms: 10_000` to avoid tripping it).
- **[C2/A] P3** `engine.rs:926` `check_clock_skew_does_not_panic_on_garbage_payload` — zero-assert;
  passes on absence of panic.
- **[C4/F] P3** `network.rs:297` `vote_returns_network_error_on_connection_failure` — bare `is_err()`;
  sibling at `:266` correctly pins `RPCError::Network(_)`.
- **[C2] P3** `state_machine.rs:743` `concurrent_reads_during_snapshot_build` — spawned reader
  discards results (`let _ = engine.get(...)`); concurrency guarantee not asserted.
- **Note:** `cluster/server.rs` has **0 inline tests**; the 12 `cluster_admin_endpoints.rs` tests
  build `AppState` with no Raft engine → every endpoint returns 503, so they validate only
  auth-guard ordering, not handler happy-paths (multi-node deferred to HEA-738). Only
  `cluster_grpc_loopback.rs` drives real 3-node consensus.

### Batch E — simulation crash-recovery
- **[C4/C5] P2** `sst_crash.rs:30` `simulation_crash_during_memtable_flush` — corrupt-SST injection
  non-load-bearing (missing-KEK skip); passes if injection deleted.
- **[C4/C5] P2** `sst_crash.rs:90` `simulation_crash_during_compaction` — same; KEK-valid body-corrupt
  path untested.
- **[C1/C2] P2** `tiered_crash.rs:13` `simulation_tier_transitions_concurrent` — in a `*_crash` file
  but injects no crash; final loop asserts only `val.is_some()`.
- **[C4/C5] P2** `migration_crash.rs:164` `simulation_crash_mid_migration_resumes_correctly` — crash
  state also deletes source users, so resume skips by *absence*, not marker logic; marker-skip
  invariant not exercised.
- **[C5] P3** `wal_rotation_crash.rs:16` `simulation_memtable_flushed_before_wal_rotation` —
  survival-only; never asserts a rotation actually occurred.
- **[C1] P3** `wal_crash.rs:172` `simulation_disk_io_failure` — mis-named; appends orphan header, no
  real I/O fault (behaviorally correct otherwise).
- **[C4] P3** `sst_crash.rs:131` `simulation_power_loss` — survival-only; torn-tail discard implicit.

### Batch F — simulation concurrency/failover
- **[C4] P2** `cluster_chaos.rs:486` `simulation_leader_kill_mid_write_sequence` — split-brain assert
  gated on uncommitted keys existing; with 12 s retry all writes commit, so the negative branch is
  usually skipped (vacuous headline assert).
- **[C1] P3** `cluster_chaos.rs:633` `simulation_write_contention_across_leadership_changes` — writes
  are sequential; only contention is the leadership change. Name overstates.
- **[C2/B] P3** `cluster_failover.rs:564` `simulation_leader_kill_and_election` — `unwrap_or_default()`
  in an assert (not vacuous here, but the forbidden pattern).
- **[C1] P3** `approval_cas.rs:120,320` — "crash mid-create" actually validates trailing-garbage
  discard, not partial-create rollback.
- **[C3] P3** `approval_cas.rs:212` — "crash after delete" is raw `delete` + clean shutdown, not an
  injected crash (acceptable proxy).
- **[C1] P3** `rbac_concurrent_assignments.rs:41` — concurrent assigns target 4 distinct keys; no
  same-key contention / lost-update coverage.
- **[C2/A] P3** `rbac_concurrent_assignments.rs:91` — in-race `resolve_permissions` handles discard
  results; only final post-quiescence resolve asserts values.
- **[C5] P3** `txn_concurrent.rs:102,175` — dead `seed` decoration (race itself is strong).

## Strong tests worth noting (not defects)
- `put_if_absent_exactly_one_winner_under_concurrency` (engine.rs:1078), 16-thread TOCTOU race.
- `concurrent_writes_during_flush_are_not_lost` (engine.rs:1280).
- `wal_tampered_gcm_ciphertext_detected` / `wal_recovery_stops_at_corruption` — genuine reject paths.
- `key_registry.rs` (18/18) — corruption/HMAC/host-key-rotation negatives pin exact variant + assert
  `affected_realms`. Model examples of criterion F done right.
- `memtable.rs` (23/23) — tombstone-vs-absent, failed-flush-preserves-data, oracle proptest.
- `three_node_grpc_loopback_replicates_ten_writes` — the anchor real-consensus test (3-node quorum,
  mTLS, election, convergence).
- `wal_crash.rs`, `audit_crash.rs`, `realm_concurrent_io.rs` (real `FaultFs`) — both-direction asserts.
- `txn_raft_concurrent.rs`, `txn_concurrent.rs` — exactly-one-winner with loser-variant pinned.

## No dead tests
No `#[ignore]`, no commented-out assertions, and no stale markers found in any in-scope file.
The systemic weaknesses are documentation-accuracy (madsim) and non-load-bearing fault injection,
not disabled tests.
