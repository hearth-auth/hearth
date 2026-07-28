# HEA-1822 Phase 3 Accuracy Audit — Batch A: storage engine + WAL

Scope: `#[cfg(test)] mod tests` in `src/storage/engine.rs` and `src/storage/wal.rs`.
Audit only — no fixes applied. Criteria 1–5 per task brief; anti-pattern taxonomy A–I per `docs/specs/TESTING.md`.

## Per-file verdict

| File | #Tests | Clean | Defects | Notes |
|------|--------|-------|---------|-------|
| src/storage/wal.rs | 19 | 18 | 1 | Serde/rotation/CRC/GCM-tamper/counter-reset all strong; one fsync-labelled test does not actually exercise fsync. |
| src/storage/engine.rs | 43 | 38 | 5 | put_if_absent race, realm isolation, missing-KEK reject, encryption-at-rest, compaction all solid; 1 conditionally-vacuous test + 4 cosmetic. |
| **Total** | **62** | **56** | **6** | No P0/P1. 1 P2 in each file, 4 P3. |

Note: 3 of the 19 wal.rs "tests" are `proptest!` cases (serde round-trip, write ordering, replay-prefix consistency) — all behavioral and counted as clean.

## Defect list

- **[CRITERION 1]** wal.rs:1034 — `wal_fsync_durability_across_restart` — **P2**. Name/comment claim fsync durability, but the test only writes-then-drops-then-reopens in the same process. Drop flushes userspace buffers into the OS page cache, so the reopen would read the data back identically under `SyncMode::None`; the `SyncMode::EveryWrite` config is decorative and the test would still pass with fsync disabled. Does not prove fsync-before-ack / `kill -9` survival. (Real crash-safety is covered elsewhere by `wal_recovery_stops_at_corruption` and the GCM/counter tests.)

- **[CRITERION 2/5]** engine.rs:1739 — `engine_compaction_succeeds_at_exact_min_sst_count` — **P2**. Every assertion is wrapped in `if sst_before >= 2 { ... }`. If flush behaviour ever yields <2 SST files the whole body no-ops and the test passes while verifying nothing (conditional-assertion / vacuous-under-condition anti-pattern). Should assert `sst_before >= 2` first, then compact unconditionally.

- **[CRITERION 4]** engine.rs:1982 — `wal_rotation_flushes_memtable_to_sst_before_truncating` — **P3**. Doc-comment claims a "simulated kill after rotation would lose those writes," but the test never reopens or simulates a crash — it reads back through the live engine (memtable+SST still resident). It proves rotation produced an SST and data is readable, an indirect proxy, but does not exercise the crash/recovery path the comment describes.

- **[CRITERION 2/1]** engine.rs:1479 — `engine_scan_merges_memtable_and_sst` — **P3**. Writes 5 keys but only asserts `results.len() >= 4`, and never verifies any key actually resided in the SST layer vs the memtable, so it does not strongly prove the cross-layer merge its name claims. Weak-`.len()` assertion.

- **[CRITERION 2]** engine.rs:1918 — `engine_data_is_encrypted_at_rest` — **P3**. The WAL-plaintext half of the check is guarded by `if wal_path.exists()`; if the WAL filename/path ever changes the WAL encryption assertion silently skips with no failure. (The SST half is correctly gated on a non-empty assert first.)

- **[CRITERION 2]** engine.rs:1530 — `engine_is_send_and_sync` — **P3**. Zero `assert*!` macros in the body (taxonomy A: zero-assert test). It is a legitimate compile-time trait-bound check (`assert_send_sync::<EmbeddedStorageEngine>()` fails to compile if the bound is lost), so it has value, but it is technically a zero-runtime-assertion test.

## Strong tests worth noting (not defects)

- `put_if_absent_exactly_one_winner_under_concurrency` (engine.rs:1078) — 16-thread barrier race, asserts exactly one winner. Real TOCTOU coverage.
- `concurrent_writes_during_flush_are_not_lost` (engine.rs:1280) — 4×800 concurrent writes under constant flushing, no-loss assertion. Strong.
- `wal_tampered_gcm_ciphertext_detected` (wal.rs:1275) & `wal_recovery_stops_at_corruption` (wal.rs:1062) — genuine reject/failure-path coverage (tampered tag / garbage bytes → dropped records).
- `rotation_counter_resets_atomically_with_dek` (wal.rs:1176) — nonce/DEK atomicity regression, live + reopen assertions.
- `engine_refuses_to_start_with_missing_keks` (engine.rs:1536) — pins `Err(StorageError::Crypto{..})`, not a bare `is_err()`.
- Realm-isolation tests across `get`/`scan_keys`/`count_prefix`/`scan_prefix_paged` all assert the other realm's data is absent, not just present in its own.
