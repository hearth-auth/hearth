## Why

Cluster membership is fixed when the cluster first starts (`docs/guides/clustering.md` C-6, `docs/dev/CONSISTENCY.md` G5 and G9). No code calls openraft's `add_learner` or `change_membership`. So a node cannot be added, a dead voter cannot be removed, and a dead voter cannot be replaced. A 3-node cluster with one dead node keeps working, but it tolerates no further failure until it is rebuilt from a backup. The only replacement path in the docs (restart the node under its old ID with an empty data directory) discards its Raft vote. The Jepsen `replace` test shows that this path breaks the cluster. A cluster that cannot replace a node cannot be operated as HA. This is roadmap item HEA-2178 (W5-2).

## What Changes

- **Operator API.** New system-realm admin endpoints under `/admin/cluster/members`: list the membership, add a learner, promote a learner to voter, remove a member, and replace a voter in one joint change. A thin `hearth cluster` CLI calls the same endpoints with the same token. Any member accepts a call and forwards it to the leader over the peer channel, as writes are forwarded today (H-3).
- **Flow.** A new node joins as a learner, catches up by log or snapshot, and is promoted only when it is caught up and its preflight passes (right cluster, right node ID, same build, can unwrap the cluster's keys). Every voter change goes through openraft's joint consensus. Only one change runs at a time.
- **Refusal rules.** Refuse a change that leaves fewer than 3 voters, a change whose new or joint configuration has no reachable quorum, a change while another one is in progress, a reused node ID, an address that another member already has, and the removal of the current leader.
- **Joining nodes.** New config key `cluster.join_existing: true`. Such a node never self-initialises, does not read `cluster.peers`, and waits with no deadline to be added. Its `/readyz` answers `503` with `"cluster": "learner"` until it is a voter.
- **Peer identity.** Every peer RPC carries the cluster ID and the sender's and target's node IDs. A node refuses an RPC meant for another node, from another cluster, or from a node that is not a member. A peer certificate names its node ID, and peers check it. A removed node learns it was removed and stops serving.
- **Retired IDs.** A removed node ID is retired and can never be added again. This closes the G9 path: a replacement always gets a new ID.
- **Interrupted changes.** A leader that finds the cluster in a joint configuration finishes the change.
- **`cluster.peers`** becomes the bootstrap seed only. After a change it may be stale. A node logs a warning when its `peers` differ from the Raft membership, and `/admin/cluster/status` reports it.
- **Prerequisite: P-2.** A new node at 1M users catches up through a snapshot of about 2 GB. Today a snapshot is built, held, sent and installed in memory (`SnapshotData = Cursor<Vec<u8>>`), as several full copies. A separate change must first make snapshots file-backed and streamed (P-2). See design decision 10.
- **Jepsen.** A membership nemesis (add, promote, remove, replace, during partitions and `kill -9`). The `replace` test switches to the new procedure and flips from `xfail` to `pass`.
- **BREAKING (cluster mode only):** peer certificates need a node-ID URI SAN, the Raft node record and `raft.db` gain fields, and nodes of the old and new release cannot form one cluster. Cluster mode is experimental and has no production users. Single-node mode is unchanged.

## Capabilities

### New Capabilities

- `cluster-membership`: how an operator changes a running cluster's membership, which changes Hearth refuses, how a node joins, and how nodes check each other's identity.

### Modified Capabilities

- `cluster-consistency`: adds W6, acknowledged writes survive a membership change.
- `cluster-fault-testing`: adds the membership-change fault.

## Impact

- `src/cluster/engine.rs`: membership operations, the change planner and its refusal rules, joint-change completion on leadership, the removed-node state.
- `src/cluster/network.rs`, `src/cluster/server.rs`: peer identity metadata and checks, certificate node-ID check, membership forwarding.
- `src/cluster/types.rs`, `src/cluster/state_machine.rs`, `src/cluster/log_store.rs`: cluster ID, retired IDs, node record fields.
- `proto/hearth/cluster/v1/raft.proto`: one new internal RPC, `ForwardMembershipChange`, and a node preflight RPC, `GetNodeInfo`. Internal transport only, not a client API.
- `src/protocol/cluster_admin.rs`, `src/protocol/http/admin.rs`: the new endpoints. `docs/api/openapi.supplement.yaml` documents them.
- `src/main.rs`: `hearth cluster` subcommands; the start-up window for a joining node.
- `src/config/`: `cluster.join_existing`, validation.
- `src/audit/types.rs`: membership audit actions.
- `jepsen/`: the membership nemesis and workload, `replace` rewritten, `expectations.edn`.
- Docs: `docs/guides/clustering.md` (C-6, procedures, certificates), `docs/dev/CONSISTENCY.md` §6 and §9 (G5, G9), `docs/dev/ARCHITECTURE.md` §16, `docs/guides/configuration-reference.md`, `CHANGELOG.md`, and the capability table in `CLAUDE.md`.
- Depends on the P-2 change `cluster-file-snapshots` (file-backed snapshots), merged in #943–#945. Touches the same files as `cluster-read-fencing` (`server.rs`, `state_machine.rs` `install_snapshot`), merged in #947–#951; design decision 12 says how the two fit.
