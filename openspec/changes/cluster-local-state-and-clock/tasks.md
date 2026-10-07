## 0. Before any code

- [ ] 0.1 `cluster-jepsen-harness` is archived, so `openspec/specs/cluster-consistency/spec.md` exists. Proof: `openspec list --specs` shows `cluster-consistency`, and `openspec validate cluster-local-state-and-clock --strict` passes
- [ ] 0.2 Owner decision on design Open Question 1 (where the openraft 0.10 follow-up lives). Record it in `design.md`

## 1. G3: node-local rows stay on their node

- [ ] 1.1 Test first, `src/storage/` unit test: `is_node_local_key` is true for a key with the reserved prefix and false for `rl:user:...` and for the applied-state rows. Then add `NODE_LOCAL_KEY_PREFIX` and `is_node_local_key` in a storage submodule, re-exported from `src/storage/mod.rs`
- [ ] 1.2 Test first, `src/identity/keys.rs` unit test: each of the six tracker encoders (`encode_attempt_tracker`, `encode_ip_login_tracker`, `encode_mfa_tracker`, `encode_magic_link_rl_tracker`, `encode_password_reset_rl_tracker`, `encode_registration_email_rl_tracker`) and its scan prefix returns a node-local key. Then move them under the prefix. `encode_prompt_none_tracker` stays replicated
- [ ] 1.3 Test first, `src/cluster/engine.rs` unit tests: `ClusterStorageAdapter::put_node_local` refuses a key without the prefix; `put`, `delete`, `put_batch`, `write_batch`, `put_if_absent` and `increment_u64` refuse a key with it. Then add the checks
- [ ] 1.4 Test first, `src/cluster/state_machine.rs` unit test: a built snapshot holds no node-local row. Then filter node-local keys in the snapshot builder, beside `is_state_machine_meta_key`
- [ ] 1.5 Test first, `src/cluster/state_machine.rs` unit tests: an install keeps the node's node-local rows of a realm in the snapshot; deletes every row, node-local ones included, of an on-disk realm absent from the snapshot; drops a node-local row found in a payload. Then change phases 1 and 2 of `restore_snapshot_in_place`
- [ ] 1.6 Multi-node test first, using the isolate, write, compact and heal pattern of `tests/cluster_peer_message_size.rs`: a follower counts 3 failed logins and the leader 5 for the same user; the follower installs a snapshot; it still counts 3, not 5, and still counts 3 after a restart (spec scenarios "A follower installs a snapshot" and "A follower restarts after a snapshot install")
- [ ] 1.7 Multi-node test: a realm deleted while a follower is cut off leaves no rows on that follower after its install (spec scenario "A realm deleted while a follower was behind")

## 2. G6: a leader steps down before a graceful shutdown

- [ ] 2.1 Test first, `src/cluster/engine.rs` unit test: with the stepping-down flag set, a write this node would propose fails with `ClusterUnavailable` and proposes nothing. Then add the flag and the check
- [ ] 2.2 Test first, `src/cluster/engine.rs` unit test of a pure shutdown-plan function: leader → step down, then stop the peer server; follower → stop the peer server at once; the step-down wait never exceeds the drain deadline. Then add the function and a `ClusterEngine` entry point that sets the flag and calls `transfer_leadership`
- [ ] 2.3 Test first, `tests/cluster_serve_admin_status.rs` (real processes): `SIGTERM` to the leader of a 3-node cluster; another node reports role `leader` before the old process exits; a write sent to the old leader after the signal gets `503` `HEARTH_CLUSTER_UNAVAILABLE` and is absent on every node. Then give the peer server its own shutdown signal in `src/main.rs`, raised after the step-down
- [ ] 2.4 Test: with a majority of the other voters down, `SIGTERM` to the leader logs the handover warning and the process exits within `operational.shutdown_timeout_secs` (spec scenario "No successor can be elected")
- [ ] 2.5 Jepsen: a `leader-restart` test (nemesis: `SIGTERM` the current leader, then restart it) with the `register` checkers, plus a checker that no write answered by the stopping node after its signal is `:info`. Prove the checker on a planted violation first. Add it to the catalog and to `jepsen/expectations.edn` as `:pass`, and to `docs/dev/CONSISTENCY.md` §9

## 3. G8: C3 restated

- [ ] 3.1 Test first: give the in-process cluster harness in `tests/cluster_three_node_control_coherence.rs` one `FakeClock` per node (today it shares one). Then a test: a user created on a follower whose clock is 10 s ahead has the same `created_at` on every node, equal to that follower's clock (spec scenario "A user created on a follower with a fast clock")
- [ ] 3.2 Test: records created on two nodes with skewed clocks keep each handling node's time (spec scenario "Records created on two nodes with skewed clocks")
- [ ] 3.3 Correct the `RaftCommand` doc comment (`src/cluster/types.rs`): only the C4 check reads `leader_timestamp`; followers do not apply it to records

## 4. Docs and release notes

- [ ] 4.1 `docs/dev/CONSISTENCY.md`: C3 restated and marked Implemented; G3, G6 and G8 moved out of section 8 with the commits that closed them; section 6 says shutdown steps down; section 7 says snapshots no longer carry tracker rows
- [ ] 4.2 `docs/dev/ARCHITECTURE.md` §12.5: remove the "Not yet implemented" note, and say the handover is a step-down whose gap is bounded by the leader lease plus an election timeout on openraft 0.9.25
- [ ] 4.3 `docs/guides/clustering.md`: a leader stopped gracefully hands over first, and writes during the handover get `503` `HEARTH_CLUSTER_UNAVAILABLE`; a leader's shutdown can take up to about 6 s longer
- [ ] 4.4 `CHANGELOG.md` under `## [Unreleased]`: `### Fixed` for G3 (a snapshot install no longer replaces a node's lockout counts) and G6 (graceful shutdown of a leader hands over leadership); `### Changed` for the C3 wording if an operator-visible doc states it
- [ ] 4.5 `make check` and `make test-detached` pass; `make jepsen` reports `leader-restart` as `PASS`; `openspec validate cluster-local-state-and-clock --strict` passes
