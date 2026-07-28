# HEA-1822 Phase 3 Accuracy Audit — Batch B: memtable / sst / tiered

Scope: test blocks in `src/storage/memtable.rs`, `src/storage/sst.rs`,
`src/storage/tiered.rs`. Audit only — no fixes applied.

Criteria: (1) name/claim match, (2) behavioral not vacuous, (3) real code path,
(4) negative/failure paths asserted, (5) no dead tests.

## Verdict table

| File | #Tests | Clean | Defects | Notes |
|------|--------|-------|---------|-------|
| src/storage/memtable.rs | 23 | 23 | 0 | Exemplary. Real memtable throughout; tombstone-vs-absent distinction, failed-flush-preserves-data (neg path), size accounting, sorted-order, realm isolation, WAL apply, oracle-based proptest, and a genuine multi-threaded snapshot test with `iterations > 0` liveness guard. |
| src/storage/sst.rs | 22 | 21 | 1 | Strong negative coverage: wrong DEK, wrong SST number, ciphertext corruption, invalid magic (`InvalidSstFormat`), tombstone compaction, bloom no-false-negative proptest. One name/claim mismatch (bloom realm-rejection). |
| src/storage/tiered.rs | 15 | 12 | 3 | Clock-sweep eviction + promote-sampling admission counters are real and well-asserted. Two weakened property tests and one constant-assertion. |

Totals: 60 tests, 56 clean, 4 defects (0 P0/P1, 1 P2, 3 P3).

## Defects

- **[CRITERION 1 & 4]** src/storage/sst.rs:1220 — `bloom_filter_rejects_different_realm_same_key_bytes` — **P2.** The test name asserts the filter *rejects* a different realm's identical key bytes, but the body deliberately discards the negative result (`let _ = filter.might_contain(&realm_b, b"shared-key");`) and only asserts the positive (`realm_a` present). The realm-rejection / realm-scoped-hashing branch it claims to prove is never asserted; the test passes even if realm-scoping were removed from the negative path. The inline comment honestly explains the FP-flakiness reason, but the name overclaims. (Note: `sst_get_bloom_rejects_wrong_realm_without_false_negative`:1299 *does* make the hard negative assertion via `get`, so real coverage exists — this test is redundant/misleading as written.)

- **[CRITERION 1 & 2]** src/storage/tiered.rs:690 — `proptest_random_access_correct_eviction` — **P3.** Name claims "correct eviction," but the only hard post-condition is `tier.len() <= 20` (capacity bound); the comment self-admits "this is a weaker check." Value correctness is asserted only conditionally inside `Get` (when both tier and oracle hold the key), and eviction *correctness* (that the right entries were dropped) is not verified at all. Provides capacity-invariant + no-corruption coverage but under-delivers on its name.

- **[CRITERION 2]** src/storage/tiered.rs:743 — `proptest_power_law_converges` — **P3.** Asserts only `hot_in_tier >= 1` of 5 hot keys. The "converges to active working set" claim is loosely verified; a single surviving hot key barely distinguishes convergence from chance. Weakening is justified in-comment (PRNG sequences can evict a hot key pre-check), but the assertion is thin for a convergence property.

- **[CRITERION 2]** src/storage/tiered.rs:656 — `default_config_admits_every_promotion` — **P3.** Asserts a constant default value (`TieredConfig::default().promote_sample_rate == 1`). Borderline constant-assertion; it does document a real contract (dev/embedded default = deterministic immediate caching), so low severity. Related compile-time guard `const _: () = assert!(PRODUCTION_PROMOTE_SAMPLE_RATE > 1);` at line 654 is a legitimate static invariant, not a runtime test — not counted as a defect.

## Notes / non-defects

- No `#[ignore]`, no commented-out asserts, no `assert!(true)` / zero-assert bodies found in any of the three files.
- All tests exercise the real `Memtable` / `SstWriter`+`SstReader` / `HotTier` structures — no mocks of the unit under test. SST tests round-trip through real AEAD encryption via `encryption::generate_dek/wrap_dek`.
- Promote-sampling admission tests (tiered.rs:591, 631) are strong: exact-count assertions (`n` vs `n/8`) plus a >4x churn-reduction check and first/hot-key admission guardrails.
