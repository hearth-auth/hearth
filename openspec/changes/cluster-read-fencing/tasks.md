## 0. Prerequisite

- [ ] 0.1 `cluster-jepsen-harness` is archived, so `openspec/specs/cluster-consistency/spec.md` exists. Proof: `openspec validate cluster-read-fencing --strict` passes against it

## 1. The gate

- [ ] 1.1 Test first: a unit test in `src/cluster/engine.rs` shows a deadline gate that allows a read before its deadline, refuses it after, and refuses it at once when closed. Then add the `AtomicU64` deadline that replaces `reads_allowed`
- [ ] 1.2 Test first: a unit test shows that the apply-lag check above `read_lag_threshold_ms` closes the gate. Then move `reads_allowed_for_lag` onto the deadline
- [ ] 1.3 Test first: a unit test shows a leader whose `millis_since_quorum_ack` exceeds the threshold is out of contact, and a sole voter never is. Then set the leader's deadline from the lag monitor
- [ ] 1.4 Test first: a test in `src/cluster/server.rs` shows an accepted `AppendEntries` from the current leader moves the deadline forward, and a refused one does not. Then record contact in the peer server
- [ ] 1.5 Test first: `tests/cli_config.rs` shows `hearth config validate` refuses `read_lag_threshold_ms: 150` and accepts `200`. Then add the floor and lower the heartbeat to `100 ms`

## 2. Token validation obeys the gate (V2)

- [ ] 2.1 Test first: a unit test shows `StorageEngine`'s new read-gate method answers `true` for single-node storage and follows the deadline for `ClusterStorageAdapter`. Then add the method
- [ ] 2.2 Test first: a test in `src/identity/engine/tests/` with a closed gate shows `validate_token` returns the unavailable storage error on a warm claims-cache hit. Then check the gate in `validate_token`, the session lookup and the refresh path
- [ ] 2.3 Test first: a protocol test shows a closed gate answers a bearer request `503` with `HEARTH_CLUSTER_UNAVAILABLE`, never `401` or `403`
- [ ] 2.4 Prove the hot path is unchanged: the allocation-count test for `validate_token` still counts zero, and `make bench-gate` passes

## 3. The snapshot install fence (R3, R4)

- [ ] 3.1 Test first: a test in `src/cluster/state_machine.rs` shows a read during `restore_snapshot_in_place` is refused, with a storage stub that pauses between Phase 1 and Phase 2. Then close the gate in `install_snapshot` before Phase 1
- [ ] 3.2 Test first: the same test shows the gate stays closed until `on_replicated_reset` returns, and stays closed after a failed install. Then reopen it only through a fresh heartbeat

## 4. Readiness

- [ ] 4.1 Test first: `tests/cluster_serve_admin_status.rs` shows a follower cut off from the leader reports `/readyz` `503` with `"cluster": "not_in_contact"`. Then add the reason to `not_ready_reason`

## 5. Jepsen

- [ ] 5.1 Flip `staleness`, `revocation-isolated` and `snapshot` to `:pass` in `jepsen/expectations.edn`
- [ ] 5.2 Proof: `make jepsen` reports every test `pass` or its remaining expected `xfail`, with `0 fail` and `0 xpass`. Record the run date in `docs/dev/CONSISTENCY.md` §9
- [ ] 5.3 If a flipped test fails, find the cause before any change to its checker. A checker change needs a new planted-violation test first

## 6. Docs

- [ ] 6.1 `docs/dev/CONSISTENCY.md`: R2, R3, R4 and V2 become Implemented, G1 and G2 move to a closed list, and §9 marks the three tests `pass`
- [ ] 6.2 `docs/guides/clustering.md`: replace the stale-read and revocation warnings with the new `503` behaviour, and tell operators to retry `503` on another node
- [ ] 6.3 `docs/guides/configuration-reference.md`: `read_lag_threshold_ms` describes the contact check and its `200 ms` floor
- [ ] 6.4 `CHANGELOG.md` under `### Changed`: a cluster node out of contact, or installing a snapshot, now answers `503` to reads and token validation
- [ ] 6.5 `make check` and `make ci-local-fast` pass; `openspec validate cluster-read-fencing --strict` passes
