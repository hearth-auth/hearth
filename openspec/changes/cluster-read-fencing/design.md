## Context

Reads in cluster mode are local. `ClusterEngine::read_inline` and the async `get`/`scan` check one flag, `reads_allowed`. A task, `run_lag_monitor`, sets that flag every 50 ms. It estimates lag as `(last_log_index − last_applied) × 5 ms` (`compute_lag_ms`). That counts only entries the node received and did not apply. A node that receives nothing shows lag `0`, so a cut-off follower or a deposed leader keeps serving reads (G1).

Token validation does not use the flag at all. `validate_token` and the session lookup read in-memory caches on the hot path. So the flag cannot fence them, even when it is down. This is why the Jepsen test `revocation-isolated` saw a cut-off node accept a revoked session for its whole 4 s watch.

A snapshot install calls `restore_snapshot_in_place`. Phase 1 deletes every key, Phase 2 writes the snapshot, and then the observer rebuilds node-local caches (`on_replicated_reset`). Nothing fences reads in that window (G2). With the default threshold, the lag monitor happens to close the flag within about 30 ms of the snapshot's arrival, before Phase 1 starts. The Jepsen test `snapshot` therefore runs with `read_lag_threshold_ms: 3600000`. With that value, 4 installs gave 69 reads that saw partial state: the realm admin's valid token got `401` or `403`.

Raft settings today: heartbeat `500 ms`, election timeout `1500`–`3000 ms`, and openraft's leader lease equal to `election_timeout_max`. openraft 0.9 reports `millis_since_quorum_ack` on a leader. It reports nothing about leader contact on a follower.

Hot path rules (CLAUDE.md): zero heap allocations, no syscalls for reads, no locks, no `.await`. `src/identity/` may depend on lower layers, but the gate should reach it through `src/core/` or `src/storage/` traits, so identity code does not import cluster types.

## Goals / Non-Goals

**Goals:**

- Close G1: no read and no credential check on a node out of contact (R2, V2).
- Close G2: no read and no credential check during a snapshot install (R3, R4).
- Keep the hot path within its rules: one atomic load and one compare with a clock value it already reads.
- Flip `staleness`, `revocation-isolated` and `snapshot` to `pass` in `jepsen/expectations.edn`.

**Non-Goals:**

- Linearizable reads. Hearth promises bounded staleness only.
- Membership changes or node replacement (G5, G9).
- Node-local state in snapshots (G3), shutdown step-down (G6) and leader timestamps (G8). Those belong to `cluster-local-state-and-clock`.

## Decisions

### 1. Contact check from heartbeats, not a read index

Three options were compared:

| Option | How it works | Hot-path cost | Verdict |
|---|---|---|---|
| Read index (`ensure_linearizable`) | Each read asks the leader to confirm its quorum, then waits for local apply | One or more network round trips per read, and an `.await` | Rejected: breaks the hot path rules and gives linearizability that Hearth does not promise |
| Leader lease only | The leader serves reads while its quorum acknowledged it within the lease; followers forward reads | No cost on the leader; every follower read becomes a forward | Rejected: followers stop serving reads, so the cluster loses its read scaling |
| Heartbeat contact check | A follower records when it last accepted `AppendEntries` from the current leader; a leader uses `millis_since_quorum_ack` | One atomic load and one compare per read | **Chosen** |

The chosen check matches the "In contact" term the spec already defines. A follower in contact applies the leader's commit index from the last heartbeat it accepted. So a read misses only writes acknowledged after that heartbeat was sent, which bounds staleness by `read_lag_threshold_ms` plus one network delay.

A leader in contact is safe. A follower that acknowledged the leader in the last `read_lag_threshold_ms` will not vote for a new leader until its lease (`3000 ms`) runs out. So while a quorum acknowledged the leader recently, no other leader can commit a write. This holds only when `read_lag_threshold_ms` stays below the lease. Larger thresholds stay legal: they weaken R2 to the threshold the operator chose, which the spec allows.

### 2. One deadline word, set off the hot path

The gate is an `AtomicU64` that holds a deadline in coarse monotonic milliseconds. A read is allowed while `now < deadline`. Two writers move the deadline forward:

- The peer server, after each accepted `AppendEntries` from the current leader: `deadline = now + read_lag_threshold_ms`.
- The lag monitor on a leader, from `millis_since_quorum_ack`.

The lag check and the install fence set the deadline to `0`, which closes the gate at once. The lag monitor keeps its 50 ms tick for the apply-lag check only.

Hot-path cost: `validate_token` already reads the clock for expiry checks, so the gate adds one `Acquire` load and one compare. No allocation, no lock, no syscall beyond the existing clock read.

Alternative: keep the boolean flag and let the 50 ms monitor compute contact. Rejected, because it adds up to 50 ms to every fence and needs a second clock source to judge follower contact.

### 3. The identity engine sees the gate through a storage trait

`StorageEngine` gets a method that answers whether the node may serve reads now. The default is `true`, so single-node storage is unchanged. `ClusterStorageAdapter` answers from the deadline word. `validate_token`, the session lookup and the refresh path call it before they read any cache. When it is closed, they return the same storage error that a fenced read returns, so the protocol layer answers `503` with `HEARTH_CLUSTER_UNAVAILABLE` through the existing mapping. This keeps `src/identity/` free of cluster types.

### 4. The install closes the gate before Phase 1

`install_snapshot` closes the gate before it calls `restore_snapshot_in_place`. It opens it again only after `on_replicated_reset` finishes, and only through a fresh heartbeat. A failed install leaves the gate closed. The fence does not depend on `read_lag_threshold_ms`, so the `snapshot` Jepsen test passes even with its raised threshold.

### 5. Heartbeat interval `100 ms`, threshold floor `2 ×` heartbeat

With a `500 ms` heartbeat and the default `500 ms` threshold, a healthy follower would fall out of contact between heartbeats. The heartbeat drops to `100 ms`. `hearth config validate` refuses a threshold below `200 ms`. The election timeouts stay as they are.

## Risks / Trade-offs

- [Minority partitions answer `503` instead of stale data] → This is the promise. Docs tell operators to retry `503` on another node behind a load balancer.
- [5× more heartbeat traffic] → Heartbeats are empty `AppendEntries`, five per second per peer. The load test gate (`make bench-gate`) checks for regressions.
- [Clock steps on one node] → The deadline uses a monotonic clock, so a wall-clock jump cannot extend it (C1).
- [A GC-like pause on a leader after its last quorum ack] → The leader may serve reads for up to `read_lag_threshold_ms` after it was deposed. This is within R2's bound by definition.
- [Token validation now fails during partitions] → Users on a cut-off node must sign in again elsewhere. This is the V2 promise: refuse what cannot be proven live.

## Migration Plan

Cluster mode is experimental, and there are no deployed clusters to migrate (greenfield). Single-node mode is unchanged. The `CHANGELOG.md` entry goes under `### Changed`, marked as a behaviour change for cluster mode.

## Open Questions

- Should the refresh-token grant on a node out of contact also forward to the leader, rather than answer `503`? This proposal answers `503`; forwarding can follow later.
- Should `/readyz` report `not_in_contact` as a third reason, next to `no_leader` and `no_quorum`? This proposal says yes, as a small task, so load balancers drain cut-off nodes.
