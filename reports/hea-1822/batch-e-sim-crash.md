# HEA-1822 — Batch E: Simulation Crash-Recovery Accuracy Audit

Scope: `simulation/` madsim crash-recovery tests. **Audit only — no fixes applied.**

Criteria: (1) name/claim match, (2) behavioral not vacuous, (3) real code path under real
fault hook, (4) both negative (torn discarded) AND positive (committed survives) directions,
(5) no dead/vacuous tests.

## Cross-cutting finding (applies to ~9 files)

**S1 — "madsim" is claimed everywhere but never used; all `seed` vars are dead.**
`simulation/src/lib.rs:1-14` and every module docstring claim "Uses madsim for deterministic
scheduling and seed-based reproducibility." No test in scope invokes madsim scheduling — they
use `std::thread::spawn`, real `tempfile`, and real `std::fs` byte manipulation. Every crash
test declares `let seed = N; let _ = seed;` (e.g. `wal_crash.rs:53-55`, `sst_crash.rs:16-17`,
`session_crash.rs:19-21`) — the seed is pure decoration; nothing is seeded, so replay/repro is
a no-op. Tests are deterministic *by construction*, but the determinism/reproducibility claim
and the `madsim` dependency are misleading. Criterion 3 & 5. **Severity P2 (systemic).**

## Per-file verdicts

| File | Tests | Verdict | Notes |
|------|-------|---------|-------|
| wal_crash.rs | 6 | CLEAN | Real `Wal::read_all`; every test asserts BOTH committed-survive + torn-discard; AEAD tamper asserts `Err(Crypto)` (no silent truncation). Strong. |
| wal_rotation_crash.rs | 1 | MINOR | Survival-only regression test; does not assert a rotation actually occurred. |
| sst_crash.rs | 3 | DEFECTS | Corrupt-SST injection is non-load-bearing (skipped via missing-KEK branch); "corruption detected" claim overstated. |
| sst_compact_crash.rs | 1 | CLEAN | Real `compact_ssts` + leaked-file restore; exact-value asserts on all 30 keys. |
| tiered_crash.rs | 2 | DEFECTS | One test is not a crash test; weak final assert. Other is CLEAN. |
| realm_crash.rs | 3 | CLEAN | Idempotent-cascade convergence + negative `RealmNotFound`. Crash = constructed durable state (documented). |
| migration_crash.rs | 2 | DEFECTS | Resume test does not actually exercise marker-skip logic. |
| audit_crash.rs | 3 | CLEAN | Both directions + `verify_integrity` chain check; CRC-flip and orphan-header cases. Strong. |
| session_crash.rs | 2 | CLEAN | Real drop+WAL recovery with user-binding assert; TTL/clock-skew behavioral (not a crash claim). |
| realm_concurrent_io.rs | 2 | CLEAN | **Only tests using real FaultFs fault injection** (latency + `fail_write_after`); assert record⇔key atomicity + WAL-replay equivalence. Strong. |

## Defect list

- **[CRITERION 4/5]** sst_crash.rs:30-62 — `simulation_crash_during_memtable_flush` — the
  injected `000001.sst` has an all-garbage 76-byte encryption header, so on reopen
  (`allow_missing_keks=true`) it routes to the missing-KEK `continue` skip at
  `engine.rs:297-305` — it is never parsed/CRC-validated as an SST. The test passes identically
  if the injection is deleted entirely (data is served from the WAL regardless), so the
  corrupt-SST path is **not load-bearing**. The module claim "Corrupt SSTs are detected and
  skipped" is only satisfied by the missing-KEK branch, not by corruption detection. **P2.**
- **[CRITERION 4/5]** sst_crash.rs:90-104 — `simulation_crash_during_compaction` — same defect:
  injected `999999.sst` is skipped via missing-KEK, not corruption detection; non-load-bearing.
  A KEK-valid but body-corrupt SST would instead make `open()` return `Err` (engine.rs:331-335)
  and panic the `.expect("recovery")` — that real corruption path is untested. **P2.**
- **[CRITERION 1/2]** tiered_crash.rs:13-77 — `simulation_tier_transitions_concurrent` — lives in
  a `*_crash` file but injects no crash/drop/recovery (it is a pure concurrency test). Reader
  threads assert nothing on `None` (line 42-47); the final loop asserts only `val.is_some()`
  (line 72), never that the value survived correctly. Weak. **P2.**
- **[CRITERION 4/5]** migration_crash.rs:164-241 — `simulation_crash_mid_migration_resumes_correctly`
  — the constructed crash state also deletes the first 50 users from source (line 179-181), so on
  resume they are skipped by *absence*, not by the per-user progress markers. `report.migrated == 50`
  holds whether or not marker-based skip logic works, so the documented "Skip the 50 already-marked
  users" invariant is not actually exercised. Overall convergence asserts are still valid. **P2.**
- **[CRITERION 5]** wal_rotation_crash.rs:16-58 — `simulation_memtable_flushed_before_wal_rotation`
  — survival-only (acceptable for a regression test), but never asserts that a WAL rotation
  actually occurred, so a future change to rotation thresholds could silently make the HEA-1050
  guard vacuous. **P3.**
- **[CRITERION 1]** wal_crash.rs:172-215 — `simulation_disk_io_failure` — name implies a real
  I/O fault, but the test manually appends an orphan 4-byte length header (no FaultFs, no I/O
  error). Behaviorally correct (asserts torn record discarded) but mis-named. **P3.**
- **[CRITERION 4]** sst_crash.rs:131-183 — `simulation_power_loss` — survival-only; torn-tail
  discard is only implicit (open succeeds, 10 keys return). No assertion that a record *after*
  the corruption point is dropped. Acceptable but one-directional. **P3.**

## Summary

- 16 of 26 tests CLEAN. wal_crash, audit_crash, realm_crash, session_crash, sst_compact_crash,
  and realm_concurrent_io are strong and assert both directions.
- No P0/P1 correctness failures found; committed-data-survives is genuinely verified everywhere.
  Weaknesses are non-load-bearing fault injection and one mis-placed concurrency test (all P2/P3).
- Systemic P2: the entire suite advertises madsim determinism it does not use; all `seed`
  variables are dead. Only `realm_concurrent_io.rs` exercises the real `FaultFs` fault hook.
