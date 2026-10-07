## Why

Three open items in `docs/dev/CONSISTENCY.md` break cluster promises that need no new feature to fix: G3, G6 and G8. Design decision 10 of `cluster-jepsen-harness` names this change for them, and the `trusted-core-confidence` freeze allows fixes.

- **G3.** Attempt-tracker rows are node-local by design, but a snapshot carries them. A node that installs a snapshot loses its own lockout counts and gets the leader's.
- **G6.** Graceful shutdown calls only `raft.shutdown()`. When the leader stops, the cluster has no leader for one lease plus one election (4.5–6 s), and writes fail.
- **G8.** Every `RaftCommand` carries a `leader_timestamp`, but the state machine discards it. The C3 promise ("stored timestamps come from the leader's clock") is not true.

## What Changes

- Node-local rows get one reserved key prefix, owned by the storage layer. The snapshot builder leaves those rows out. The install's delete phase keeps them. The cluster adapter refuses to replicate a key with that prefix, and refuses a node-local write outside it.
- The six attempt-tracker key families move under the reserved prefix. This is greenfield: the old on-disk rows are not migrated (they only rehydrate in-memory counters).
- On graceful shutdown, a cluster node that is leader steps down before the Raft peer server drains. The step-down is bounded by `operational.shutdown_timeout_secs`. A failed step-down is logged, and the shutdown continues.
- C3 is restated to what the code can honestly promise: every node stores the same timestamp for a record, and that timestamp comes from the clock of the node that handled the request. The leader's timestamp is not written into records. `leader_timestamp` stays, for the C4 clock-offset check, and its doc comment stops claiming that followers apply it.
- `docs/dev/CONSISTENCY.md` marks G3, G6 and G8 closed, and `docs/dev/ARCHITECTURE.md` §12.5 drops its "not yet implemented" note.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cluster-consistency`: adds three promises — node-local rows stay on their node across a snapshot install (G3); a leader steps down before a graceful shutdown (G6); C3, restated (G8). The capability is added by `cluster-jepsen-harness`, so that change must be archived first.

## Impact

- **Code:** `src/storage/mod.rs` (reserved prefix and the node-local contract), `src/cluster/engine.rs` (`ClusterStorageAdapter`, a step-down entry point for shutdown), `src/cluster/state_machine.rs` (snapshot build at `:144-165`, restore phase 1 at `:933-951`), `src/identity/keys.rs` (tracker encoders at `:2019-2129`), `src/main.rs` (shutdown sequence at `:3020-3061`), `src/cluster/types.rs` (doc comment at `:19-22`).
- **Tests:** unit tests in `src/cluster/state_machine.rs`; multi-node tests in `tests/cluster_three_node_control_coherence.rs` (in-process) and `tests/cluster_serve_admin_status.rs` (real processes).
- **Jepsen:** no existing test flips. Node-local state is outside the Jepsen checkers (CONSISTENCY.md §9), and Docker cannot give one node its own clock. G6 adds one Jepsen test (see design.md).
- **Operators:** a stopping leader hands over leadership first, so a rolling restart no longer causes an election timeout on each leader stop. Shutdown of a leader can take up to about 6 s longer.
- **No new config key, endpoint or dependency.**
