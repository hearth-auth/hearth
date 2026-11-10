## 1. The guarded batch

- [ ] 1.1 Write `a_guarded_batch_applies_only_when_the_guard_matches` in `src/cluster/state_machine.rs` (match, mismatch, absent guard; a mismatch writes nothing and answers `success: false`). See it fail to compile, then add `RaftCommand::WriteBatchIf` and its apply as one `write_batch`
- [ ] 1.2 Write `a_replayed_guarded_batch_gives_the_same_answer` (re-apply after a snapshot install reaches the same result on every node), then make it pass
- [ ] 1.3 Write a `StorageEngine::write_batch_if` test for the single-node default (applies without a guard check; the trait doc says one process must be the only writer), then add the method in `src/storage/mod.rs`
- [ ] 1.4 Write a `ClusterStorageAdapter` test: a forwarded `write_batch_if` from a follower returns the leader's answer and returns after the follower applied the entry. Then implement the adapter method

## 2. The audit engine uses the guard

- [ ] 2.1 Add a test storage in `src/audit/engine.rs` tests that checks the guard under one lock, as Raft apply does. Write `two_nodes_appending_at_once_keep_one_chain` with `two_engines_over_one_store` over it (two threads, 500 appends each, then `verify_integrity` is `true`). See it fail
- [ ] 2.2 Make `with_pending_append` and `append` write through `write_batch_if` with the head bytes they read; on `false`, drop the cache, reload the head, rebuild and retry. 2.1 passes
- [ ] 2.3 Write `an_append_that_keeps_losing_is_refused_and_writes_nothing` (a storage that always rejects the guard: after 8 tries a new retryable `AuditError`, no event row, chain still verifies). Then add the bound, the error and its `503` / `HEARTH_CLUSTER_UNAVAILABLE` mapping, and the conflict counter in `src/metrics`
- [ ] 2.4 Write `a_slow_clock_does_not_reorder_the_chain` (two engines, one `FakeClock` an hour behind, alternating appends, `verify_integrity` is `true`). Then add `ChainHead::last_timestamp` under the head MAC and clamp the event timestamp to it
- [ ] 2.5 Write `a_tampered_last_timestamp_is_detected` (edit the field in the stored head; verification answers `false`), then make it pass
- [ ] 2.6 Write `a_prune_and_an_append_racing_keep_one_chain` and `an_import_and_an_append_racing_keep_one_chain`, then move `prune_before`, `prune_oldest` and `import_events` to `write_batch_if`

## 3. Merged appends pass rows

- [ ] 3.1 Write `a_merged_append_that_loses_once_commits_its_rows_once` (the caller's rows and the audit rows land together after one retry, and only once). Then replace `AuditEnqueueFn` with the caller's rows in `with_pending_append`
- [ ] 3.2 Move the session-creation caller in `src/identity/engine/mod.rs` and the decorator in `src/webhook/mod.rs` to the new call. Their existing tests stay green
- [ ] 3.3 Check that single-node group commit is unchanged: the existing HEA-1948 / HEA-1954 coalescing tests pass without edits

## 4. Black-box proof on a real cluster

- [ ] 4.1 Write `tests/cluster_audit_chain.rs`: a three-node cluster (the `spawn_node` pattern of `tests/cluster_serve_admin_status.rs`), audited admin changes on all three nodes at once, then `POST /admin/audit/verify` on each node answers `"ok": true` with the same `event_count`. Run it on the current branch first and see it fail
- [ ] 4.2 With sections 1–3 in place, 4.1 passes. Run `make test-detached`; the whole suite passes
- [ ] 4.3 Change `audit` in `jepsen/expectations.edn` from `{:xfail "G4"}` to `:pass`. Run `make jepsen TEST=audit`; it reports `PASS`. Record the conflict counter from the run in `design.md` Open Questions
- [ ] 4.4 Run `make jepsen`: no other test changes its result

## 5. Docs and spec

- [ ] 5.1 `docs/dev/CONSISTENCY.md`: W7 becomes **Implemented** with file:line evidence, G4 is closed, the section 9 `audit` row expects pass
- [ ] 5.2 `docs/guides/clustering.md`: replace the note that the Jepsen `audit` test broke the chain with the new behaviour and the `503` on a lost race
- [ ] 5.3 `CHANGELOG.md` under `### Fixed`: concurrent audited changes on different cluster nodes no longer break the audit chain; an append that cannot join it answers `503`
- [ ] 5.4 `make check` and `make ci-local-fast` pass; `openspec validate cluster-audit-chain --strict` passes
