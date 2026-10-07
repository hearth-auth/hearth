## Why

A cluster node serves reads and validates tokens from local state, with no check that it is still in contact with the leader. The Jepsen suite proves it. In `staleness`, cut-off nodes served reads up to 273 writes behind. In `revocation-isolated`, a cut-off node accepted a revoked session for the whole 4 s watch. In `snapshot`, reads during a snapshot install saw partial state: a valid admin token got `401` or `403`. These are open items G1 and G2 in `docs/dev/CONSISTENCY.md`. Hearth is an identity server, so a revoked session that still works on one node is a security defect, not only a consistency defect.

## What Changes

- A cluster node serves a read only while it is **in contact**: a follower has heard from the current leader within `read_lag_threshold_ms`; a leader has had a quorum acknowledgement within `read_lag_threshold_ms`. Otherwise it answers `503` with `HEARTH_CLUSTER_UNAVAILABLE` (closes G1).
- Token and session validation on the hot path obeys the same gate. Today it reads in-memory caches and never consults the gate. A node out of contact refuses a credential it cannot prove is still live (V2).
- A node refuses reads, and token validation, from the start of a snapshot install until the install and the rebuild of node-local caches finish (closes G2).
- The gate becomes one deadline check in memory. The hot path keeps zero allocations, no locks and no I/O.
- The Raft heartbeat interval drops from `500 ms` to `100 ms`, so a healthy follower stays in contact with the default threshold. `hearth config validate` refuses a `cluster.read_lag_threshold_ms` below `2 ×` the heartbeat interval.
- The Jepsen tests `staleness`, `revocation-isolated` and `snapshot` flip from `xfail` to `pass` in `jepsen/expectations.edn`.
- **BREAKING (cluster mode only):** a node that loses contact now answers `503` to reads and token validation instead of answering from stale state. Cluster mode is experimental, and single-node mode is unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cluster-consistency`: adds the requirements R2 (bounded staleness), R3 (monotonic reads on one node), R4 (no partial state) and V2 (no credential accepted out of contact). The capability is created by the change `cluster-jepsen-harness`; this change requires that change to be archived first.

## Impact

- `src/cluster/engine.rs`: the read gate (`reads_ok`, `read_inline`, `run_lag_monitor`), the leader contact check, the heartbeat interval.
- `src/cluster/server.rs`: records each accepted `AppendEntries` from the current leader.
- `src/cluster/state_machine.rs`: `install_snapshot` closes the gate before Phase 1 of `restore_snapshot_in_place` and opens it after the node-local rebuild.
- `src/storage/` and `src/core/`: a read-gate query that the identity engine can call without a dependency on `src/cluster/`.
- `src/identity/engine/`: `validate_token` and the session lookup check the gate.
- `src/config/validate.rs`: the threshold floor.
- `jepsen/expectations.edn`, `docs/dev/CONSISTENCY.md`, `docs/guides/clustering.md`, `docs/guides/configuration-reference.md`, `CHANGELOG.md`.
- Availability: clients of a node in a minority partition get `503` instead of stale answers. A load balancer must retry on another node.
