## Context

`docs/dev/CONSISTENCY.md` lists three open items that this change closes. All three are in code that exists today; none needs a new feature.

**G3 — node-local rows ride in snapshots.** The identity engine keeps six attempt trackers per node: user login, IP login, MFA, magic link, password reset and registration. It persists their rows with `put_node_local` (`src/identity/engine/mod.rs:2448`, `:2634`, `:2951`, `:3041`, `:3115`, `:3223`). In cluster mode, `ClusterStorageAdapter::put_node_local` writes straight to the node's own engine and bypasses Raft (`src/cluster/engine.rs:1898-1923`). The key families are `rl:`-prefixed strings built in `src/identity/keys.rs:2019-2108`. But the snapshot builder scans every key of every realm and skips only the two applied-state rows (`src/cluster/state_machine.rs:144-165`, `is_state_machine_meta_key` at `:697`). The install deletes every key of every on-disk realm and then writes the payload (`restore_snapshot_in_place`, phase 1 at `:933-951`, phase 2 at `:953-961`). So an installing node loses its own trackers and takes the snapshot leader's.

**G6 — shutdown does not step down.** After the HTTP and peer listeners drain, `run_serve` calls `ClusterEngine::shutdown` (`src/main.rs:3061`), which calls only `raft.shutdown()` (`src/cluster/engine.rs:549-555`). The Raft peer server starts to drain at the signal, alongside HTTP (`src/main.rs:3047-3060`). `docs/dev/ARCHITECTURE.md` §12.5 says a cluster node MUST start a leadership transfer before the drain.

**G8 — `leader_timestamp` is discarded.** Every `RaftCommand` carries `leader_timestamp`, and the leader restamps a forwarded command (`src/cluster/engine.rs:1208`). The state machine ignores it (`leader_timestamp: _`, `src/cluster/state_machine.rs:497-535`). The only reader is the C4 clock-offset check (`src/cluster/engine.rs:1614-1660`). The doc comment on `RaftCommand` says followers use it verbatim (`src/cluster/types.rs:19-22`); that is not true.

Constraints:

- Layers depend downward only. `src/cluster/` cannot import `src/identity/keys.rs`. A rule the snapshot code applies must live in `src/storage/` (or `src/core/`).
- openraft is pinned at 0.9.25. It has no targeted leadership transfer. It refuses every vote request while the old leader's lease is valid (`engine_impl.rs:284-313` in openraft). `Trigger::transfer_leader` exists only in openraft 0.10, which is still alpha (`0.10.0-alpha.36`).
- Greenfield: there are no deployed clusters, so no on-disk migration is needed.

## Goals / Non-Goals

**Goals:**

- A node-local row never leaves its node, and a snapshot install never removes one of a realm that still exists.
- A leader that stops gracefully hands over leadership while its peer links still work, and answers writes in that window as unavailable, never as outcome unknown.
- C3 states what the code does, and a test proves it.
- Each fix has a failing test first: a unit test, then a multi-node test.

**Non-Goals:**

- Replicating the trackers. They stay per node by design (spec "Node-local state is per node").
- The `prompt=none` probe counter (`encode_prompt_none_tracker`, `src/identity/keys.rs:2129`). It is replicated on purpose and is not node-local.
- A faster handover than openraft 0.9.25 allows. A targeted transfer waits for a stable openraft 0.10.
- Clock-skew testing in Jepsen. Docker containers share one kernel clock.

## Decisions

### 1. One reserved key prefix for node-local rows (G3)

The storage layer reserves the prefix `\0node:` for node-local rows, next to the existing `\0raft:sm:` rows. It exports `NODE_LOCAL_KEY_PREFIX` and `is_node_local_key(key)` from a storage submodule, re-exported from `src/storage/mod.rs`.

- The six tracker encoders build `\0node:rl:...` keys.
- `ClusterStorageAdapter::put_node_local` and `delete_node_local` refuse a key without the prefix. Every replicated write method of the adapter refuses a key with it. A misplaced key then fails in tests, not in production snapshots.
- The snapshot builder skips node-local keys, as it skips the applied-state rows.
- The install keeps the node-local keys of every realm that the snapshot contains. It deletes all keys, node-local ones included, of an on-disk realm that the snapshot does not contain, so a deleted realm leaves no orphan rows.
- The install also drops any node-local key in a payload, in case a leader on an older build sends one.

Alternatives considered:

- *A list of tracker prefixes in the cluster layer.* Rejected: the cluster layer would have to know identity key formats, which breaks the layer rule. A new tracker family would also need a second edit.
- *A separate column family or realm for node-local rows.* Rejected: it changes the storage engine for six key families. A prefix gives the same isolation.
- *Rebuild the trackers after an install.* Rejected: the counts are already lost by then.

### 2. Step down before the peer server drains (G6)

At the shutdown signal, a cluster node that is leader:

1. sets a `stepping_down` flag in `ClusterEngine`. While it is set, a write this node would propose fails at once with `ClusterUnavailable` (nothing is proposed). A proposal would send `AppendEntries`, renew the followers' leases and block the election.
2. calls the existing step-down (`ClusterEngine::transfer_leadership`, `src/cluster/engine.rs:673`): heartbeats off, no candidacy, wait for a new leader.
3. only then lets the Raft peer server drain, and the rest of the shutdown runs as today.

The whole step-down is bounded by `operational.shutdown_timeout_secs` (default 30 s; the step-down itself is bounded by `STEP_DOWN_WAIT`, 20 s). A failed or timed-out step-down is logged at `warn`, and the shutdown continues. A follower skips the step-down.

The peer server needs its own shutdown signal, raised after the step-down, instead of the process signal.

What this gains, honestly: openraft 0.9.25 makes the cluster wait out the old leader's lease (3 s) plus an election timeout (1.5–3 s) either way. A graceful stop therefore leaves about the same leaderless gap as a crash, 4.5–6 s. The gains are that writes in the gap get a clean `503` `HEARTH_CLUSTER_UNAVAILABLE` instead of an outcome-unknown answer, that the successor is elected while the old node still answers peer RPCs, and that the node meets ARCHITECTURE.md §12.5.

Alternatives considered:

- *Upgrade to openraft 0.10 and use `Trigger::transfer_leader`.* The gap would shrink to about one election round. Rejected for now: 0.10 is alpha, and the upgrade touches the log store, the state machine and the network traits. Record it as the follow-up that makes the handover fast.
- *A Hearth peer RPC that tells the best follower to call `trigger().elect()`.* Rejected: other followers still refuse its vote until their lease from the old leader expires. It saves at most the election timeout and adds a wire message.
- *Drop the ARCHITECTURE.md §12.5 rule.* Rejected: the clean `503` and the orderly handover are worth the small change.

### 3. Restate C3; do not write the leader's clock into records (G8)

C3 becomes: every node stores the same timestamp for a replicated record, and that timestamp comes from the clock of the node that handled the request. Records written on two nodes can be out of order by up to the clock offset between those nodes; C4 warns when an offset exceeds 1 s, and C2 tolerates 60 s in expiry checks.

The first half is true today: a record replicates as bytes, so every node stores the same value. A test makes it a checked promise.

Alternatives considered:

- *Apply the leader's timestamp to records.* Rejected. The state machine applies opaque bytes; it cannot find a timestamp inside a value. The identity engine builds the record, and checks expiry against its own clock, before the leader stamps the command. To honour "leader's clock" every write path would need the leader's time before it builds the record (forward the request, not the bytes), or a timestamp slot the state machine fills. That redesign touches every record type, for a gain C2 and C4 already cover.
- *Remove `leader_timestamp`.* Rejected: C4 reads it.

The `RaftCommand` doc comment is corrected to say that only the C4 check reads `leader_timestamp`.

### 4. Tests, and what Jepsen can and cannot show

| Item | Unit test | Multi-node test | Jepsen |
|---|---|---|---|
| G3 | `state_machine.rs`: build skips `\0node:` rows; install keeps them for a snapshot realm, deletes them for a missing realm, drops them from a payload. Adapter refusals. Encoder prefix. | A follower and the leader count different login failures; the follower is cut off and installs a snapshot (the isolate, compact, heal pattern of `tests/cluster_peer_message_size.rs`); the follower keeps its count and lacks the leader's. | none: §9 keeps node-local state out of the checkers |
| G6 | `stepping_down` refuses a proposal with `ClusterUnavailable`. | `tests/cluster_serve_admin_status.rs` (real processes): SIGTERM the leader; another node is leader before the old process exits; a write sent to the old leader after the signal gets `503` `HEARTH_CLUSTER_UNAVAILABLE`. | new test `leader-restart`: a nemesis stops the leader with SIGTERM and restarts it; the `register` checkers, plus no `:info` write answered by the stopping node after its signal |
| G8 | none | A three-node in-process cluster with one `FakeClock` per node (the harness in `tests/cluster_three_node_control_coherence.rs` shares one clock today); a user created on a follower whose clock is 10 s ahead has the same `created_at` on every node, equal to that follower's clock. | none: Docker cannot skew one node's clock (C1 and C3 need VMs) |

No existing Jepsen test flips from `xfail` to `pass`. The suite gains one required test, `leader-restart`.

## Risks / Trade-offs

- [A leader's shutdown takes up to about 6 s longer on a healthy cluster, and up to `STEP_DOWN_WAIT` (20 s) when no successor can win] → Bounded by `operational.shutdown_timeout_secs`; a timed-out step-down is logged and the shutdown continues.
- [A follower restarted from an old data directory still holds tracker rows under the old `rl:` keys] → Greenfield: no deployed data. The rows only rehydrate in-memory counters; an unknown key is never read.
- [Writes fail for the whole leaderless gap during a rolling restart] → Unchanged from today in length; they now fail as unavailable, so a client may retry them safely.
- [A new tracker family written with the replicated `put` would bypass the prefix] → The adapter refuses replicated writes of `\0node:` keys, and `put_node_local` refuses other keys, so either mistake fails its test.

## Migration Plan

No migration. Old `rl:` tracker rows on a development data directory are ignored; a fresh directory has none. Rollback is a revert of the change.

## Open Questions

- Should the follow-up that upgrades to openraft 0.10 (targeted transfer, shorter gap) be its own change, or part of `cluster-membership`, which needs membership changes from the same release line?
