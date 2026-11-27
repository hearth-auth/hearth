## Context

**Today.** Membership is set once. The node with the lowest ID in its own `cluster.peers` calls `raft.initialize()` on an uninitialised node (`engine.rs`, `self_initialise_if_designated`), or an operator calls `POST /admin/cluster/bootstrap`. Nothing calls `add_learner` or `change_membership`. Peer addresses come from the Raft membership (`HearthNode { addr }`), not from `cluster.peers`, once a node is initialised. The state machine persists the applied membership (`\0raft:sm:membership`) with every membership entry.

**Peer authentication.** Peers use mTLS. The server accepts any client certificate the cluster CA signed (`server.rs`, `client_ca_root`). The client checks the server certificate's SAN against the address it dials. No side checks which node ID the other end is. A peer RPC carries no target node ID and no cluster ID.

**Secrets.** `HEARTH_MASTER_KEY` and `security.key_encryption_key` must be identical on every node, because they wrap replicated rows. They reach each node out of band today (`clustering.md`, Prerequisites §5).

**Snapshots (P-2).** `SnapshotData = std::io::Cursor<Vec<u8>>`. The builder scans every realm into memory, encodes the whole set as CBOR, gzips it, and keeps the compressed copy in an in-memory slot to serve followers. The receiver collects every chunk into one `Vec`, decompresses the whole payload, and then restores it (`restore_snapshot_in_place`). After a restart a node has no snapshot until it builds one. The snapshot policy is openraft's default, a snapshot every 5,000 entries.

**Size.** In the #913 session 913a, a 1M-user Hearth store was 2.0 GB on disk (`docs/perf/2026-11-25-aws-913a-comparison.md`). That server had 4 GiB of RAM.

**openraft 0.9.25** (`Cargo.lock`), source read from `~/.cargo/registry`:

| API | Behaviour |
|---|---|
| `add_learner(id, node, blocking)` | Proposes `ChangeMembers::AddNodes` with `retain: true`, a one-step (uniform) membership entry. With `blocking: true` it then waits with `wait(None)`, which is a 100-year timeout, until the learner's matched index is within `replication_lag_threshold` (default 5,000) of the leader's last log index. With `blocking: false` it returns once the entry is committed. Re-adding an existing node re-adds it. |
| `change_membership(changes, retain)` | Proposes a joint configuration, waits for it to commit, then proposes the uniform one. Every new voter must already be a learner (`LearnerNotFound`). A change while the last membership entry is uncommitted fails with `InProgress`. If the leader dies before the uniform entry commits, the cluster stays in the joint configuration. |
| `ChangeMembers` | `AddVoterIds`, `RemoveVoters`, `ReplaceAllVoters`, `AddNodes`, `RemoveNodes`, `SetNodes`. `SetNodes` can split the brain when a node's address is changed to another node's address; openraft's docs say to use `RemoveNodes` + `add_learner` instead. |
| Network | openraft's docs make the network layer responsible for reaching the right node: "Connecting to a wrong node can lead to data inconsistency and even data loss." |

**Constraints.** Hot path rules (CLAUDE.md) are untouched: nothing here runs on `validate_token()`, `lookup_session()` or `lookup_user()`. Membership operations are rare admin operations. Cluster mode is experimental, with no production users, so on-disk and wire formats may break.

## Goals / Non-Goals

**Goals:**

- An operator can add a node, remove a node, and replace a dead voter on a running cluster without losing an acknowledged write (closes G5).
- A replacement never reuses a node's identity (closes G9 by its stated resolution).
- Every change is refused when it would leave the cluster unable to reach a quorum.
- A change interrupted by a leader change, a crash or a partition ends in a defined state that the operator can see and that the cluster finishes.
- A Jepsen nemesis proves the above under partitions and `kill -9`.

**Non-Goals:**

- Automatic membership (auto-join, auto-remove of a dead node). Every change is an operator action.
- Permanent learners or read replicas. A learner exists only on its way to becoming a voter.
- Changing a member's address in place (`SetNodes`). A node that moves is replaced.
- Fencing a node whose data directory was wiped and which is restarted under its old ID by hand. See Open Question 1.
- P-2 itself. It is a prerequisite with its own change (decision 10).
- Read fencing (G1, G2), shutdown step-down (G6) and the other open items.

## Decisions

Each decision lists the options, their pros and cons, and a recommendation. **The owner decides.**

### 1. Operator surface

| Option | Pros | Cons |
|---|---|---|
| A. Admin REST API only | Same auth, audit and forwarding as every other admin operation; callable from automation | Operators must write `curl` calls for a multi-step procedure |
| B. CLI only, with a node-local credential | Works without an operator account | A second auth path; whoever holds a node's peer certificate controls membership; no realm audit trail; `hearth admin token` already covers "no account at hand" |
| **C. REST API, plus a `hearth cluster` CLI that calls it** | One implementation and one auth path; the CLI scripts the multi-step `replace` and polls catch-up | The CLI needs a base URL and a token |

**Recommendation: C.** Endpoints (all under the existing cluster gate, decision 2):

| Method | Route | Effect | Answer |
|---|---|---|---|
| `GET` | `/admin/cluster/members` | Voters, learners, each with address, matched index, lag, last contact; the change in progress (`joint` and its two voter sets); retired IDs; `peers_drift` | `200` |
| `POST` | `/admin/cluster/members` | `{node_id, address}`: add a learner (`add_learner(.., blocking: false)`) | `202` with the member record |
| `POST` | `/admin/cluster/members/{node_id}/promote` | Learner to voter (`AddVoterIds`) | `200` when the uniform configuration commits |
| `DELETE` | `/admin/cluster/members/{node_id}` | Remove a voter (`RemoveVoters`, `retain: false`) or a learner (`RemoveNodes`); retires the ID | `200` when the uniform configuration commits |
| `POST` | `/admin/cluster/members/{node_id}/replace` | `{new_node_id}`: one joint change from the current voters to the current voters minus `node_id` plus `new_node_id` (`ReplaceAllVoters`), after `new_node_id` caught up as a learner; retires `node_id` | `200` when the uniform configuration commits |

CLI: `hearth cluster members list|add|promote|remove|replace --url <base> --token-env <VAR>`. `hearth cluster members replace --dead 3 --new 4 --address 10.0.0.4:8421` runs add, waits for catch-up, then replace.

A call whose commit wait times out answers `503` with `HEARTH_CLUSTER_MEMBERSHIP_OUTCOME_UNKNOWN`. The caller re-reads `GET /admin/cluster/members`. Every call is idempotent on its target state: promoting a voter, or removing a retired ID, answers `200` with no change.

**Schema.** The existing `/admin/cluster/*` endpoints use hand-written JSON DTOs documented in `docs/api/openapi.supplement.yaml`, with node IDs as JSON numbers.

| Option | Pros | Cons |
|---|---|---|
| **Hand-written DTOs + supplement** | Matches the three existing cluster endpoints; node IDs stay `u64`; no SDK surface for an experimental feature | No generated SDK types |
| Proto RPCs with `google.api.http` | Generated SDK types and OpenAPI | `docs/dev/PROTO.md` puts every API in `hearth.<service>.v1` and asks for a discussion before a new package; `hearth.cluster.v1` is the committed tonic transport, not a schema-only package; PROTO.md says IDs are strings, not `int64`, so `node_id` would differ from `/admin/cluster/status` |

**Recommendation: hand-written DTOs**, listed in `openapi.supplement.yaml` and covered by `tests/openapi_contract.rs`. The two new **internal** peer RPCs (`ForwardMembershipChange`, `GetNodeInfo`) go in `proto/hearth/cluster/v1/raft.proto` and follow PROTO.md: `VerbNoun` names, new field numbers only, no `google.api.http` binding (node-to-node only), a comment saying so. Adding an RPC is a safe change under its backward-compatibility rules.

### 2. Who may call

| Option | Pros | Cons |
|---|---|---|
| **A. The existing cluster gate**: system realm, `hearth.admin` (`extract_cluster_admin_auth`) | Already guards bootstrap and step-down; a system-realm token needs an MFA sign-in, or host access through `hearth admin token`; changes are audited in the system realm | A stolen 15-minute admin token can change membership |
| B. A plus fresh MFA (`auth_time` within 5 minutes) | Narrows a stolen-token window | No other admin endpoint does this, including backup restore, which is as powerful; `hearth admin token` tokens would need a special case |
| C. A node-local credential (peer certificate or a socket) | No operator account | See decision 1, option B |

**Recommendation: A.** Add audit actions `ClusterMemberAdded`, `ClusterMemberPromoted`, `ClusterMemberRemoved` and `ClusterMemberReplaced`, written by the leader after the change commits. (The leader writes them, so G4's concurrent-append defect does not apply to them.)

### 3. How a new node gets the secrets and its TLS identity

| Option | Pros | Cons |
|---|---|---|
| **A. Out of band, as for the first nodes, plus a preflight before promotion** | Nothing secret crosses the peer channel; no new trust; same runbook as bootstrap | Operator work; a mistake is caught at promotion, not at start |
| B. A join token: the leader sends `HEARTH_MASTER_KEY` and the KEK to a node that presents it | One less manual step | The peer channel then carries the keys that wrap every signing key; a leaked join token or CA-signed certificate yields them; a new secret to issue, expire and revoke |

**Recommendation: A.** The operator issues the new node a leaf certificate from the cluster CA (decision 5 adds a node-ID SAN) and gives it the same `HEARTH_MASTER_KEY` and KEK. Before promotion, the leader calls the learner's `GetNodeInfo` RPC. It returns the node's configured ID, its cluster ID, its build version, and whether it could unwrap the system realm's global signing key with its own KEK once it held that row. Promotion is refused unless all four match. A learner with a wrong KEK is caught before it can vote.

### 4. Joining node configuration

A new node needs to be told it is joining, or it may self-initialise a cluster of its own (when it has the lowest ID in its `peers`).

**Decision: `cluster.join_existing: true`** (default `false`). Such a node:

- never self-initialises and refuses `POST /admin/cluster/bootstrap`;
- does not read `cluster.peers` (it learns the membership from the leader); `hearth config validate` warns when both are set;
- waits in the start-up window with no deadline until it holds the system realm, logging every 30 s the `hearth cluster members add` command that adds it;
- answers `/readyz` `503` with `"cluster": "learner"` while it is not a voter, so a load balancer keeps it out.

After its first start the key has no effect: the node is initialised.

### 5. Peer identity

Membership changes make wrong-node delivery likely: a replacement often takes the dead node's address while the dead node's ID is still a member. openraft makes the network layer responsible for reaching the right node.

| Option | Pros | Cons |
|---|---|---|
| A. Addresses only (today) | No work | A replacement at the dead node's address receives RPCs meant for the dead ID; a wiped node can fork (G9) |
| **B. Metadata on every peer RPC: cluster ID, source node ID, target node ID** | Cheap; the receiver refuses an RPC for another node (`WRONG_NODE`), from another cluster (`WRONG_CLUSTER`), or from a node that is not a member or a learner being added (`NOT_A_MEMBER`, `REMOVED`); a removed node learns it was removed | A node with any CA-signed certificate can still claim any source ID |
| **C. B, plus the node ID in the certificate** (URI SAN `urn:hearth:node:<id>`), checked by both ends | A stolen node certificate impersonates that node only; closes the "no pinning" gap in `clustering.md` | Breaking: every peer certificate must be re-issued; the `openssl` recipe and Jepsen's `gen-material.sh` change |

**Recommendation: C.** The cluster ID is a random UUID. The initialising node generates it and writes it to `raft.db` before `initialize()`. A pristine node adopts the first cluster ID it sees from a leader whose certificate passes, and persists it before it answers. After that it refuses every other. A wiped node that self-initialises gets a new cluster ID, so the real cluster refuses its RPCs and it cannot disturb them (it never finds a quorum and exits after its start-up window).

### 6. Add, promote, remove, replace

**Add.** The operator starts the new node with `join_existing: true`, then calls `POST /admin/cluster/members`. The leader checks the refusal rules (decision 7) and calls `add_learner(id, node, false)`. Never `blocking: true`: its wait has no timeout, and an HTTP handler must not wait for a snapshot transfer. The learner catches up by log when the leader still holds the entries after the learner's last index, or else by snapshot (decision 10). `GET` shows its lag.

**Promote.** Refused unless the learner's matched index is within 100 entries of the leader's last log index on two metrics reports in a row, and its preflight passes (decision 3). Then `change_membership(AddVoterIds{id}, false)`: joint, then uniform.

**Remove.** `change_membership(RemoveVoters{id}, false)` for a voter, `RemoveNodes{id}` for a learner. The ID is first written to the replicated retired-ID set, as a normal Raft command, then the membership change is proposed. A crash between the two leaves an ID retired but still a member, which only blocks re-adding it.

**Replace a dead voter.** Options:

| Option | Steps | Fault tolerance while it runs (3 voters, 1 dead) |
|---|---|---|
| Remove, then add | `{1,2,3}` → `{1,2}` → learner 4 → `{1,2,4}` | 0; a 2-voter phase that lasts the whole catch-up |
| Add, then remove | learner 4 → `{1,2,3,4}` → `{1,2,4}` | 0; a 4-voter phase whose quorum is 3 of 1, 2, 4 |
| **Learner, then one joint change** | learner 4 → joint `{1,2,3}`+`{1,2,4}` → `{1,2,4}` | 0 for the two commits only; no even-size voter set |

**Recommendation: learner, then one joint change** (`ReplaceAllVoters`). The learner catches up first, so the joint phase lasts two commits. Nothing can raise fault tolerance while a voter is dead; this option keeps the exposed window shortest.

**A removed node.** When a node applies a membership that does not hold it, or a peer answers it `REMOVED`, it records that in `raft.db`, stops voting and campaigning, answers `/readyz` `503` with `"cluster": "removed"`, and logs at `ERROR` that it must be decommissioned. It stays removed across restarts. Its data directory must not be reused under any ID.

### 7. Refusal rules

All rules live in one pure function, `plan_membership_change(current membership, leader replication metrics, retired IDs, request) -> Result<Plan, Refusal>`, so unit tests cover every rule without a cluster.

| Rule | Answer |
|---|---|
| Not the leader and the leader is unknown | `503` `HEARTH_CLUSTER_UNAVAILABLE` |
| A membership entry is uncommitted, or the configuration is joint | `409` `HEARTH_CLUSTER_MEMBERSHIP_IN_PROGRESS` |
| The new voter set has fewer than 3 voters | `409` `HEARTH_CLUSTER_TOO_FEW_VOTERS` |
| The new voter set, or the joint configuration, has no quorum among the voters that acknowledged the leader within the last 2 election timeouts | `409` `HEARTH_CLUSTER_NO_QUORUM_AFTER_CHANGE` |
| The node ID is a member (for add) or is retired | `409` `HEARTH_CLUSTER_NODE_ID_USED` |
| The address is another member's address | `409` `HEARTH_CLUSTER_ADDRESS_IN_USE` |
| Promote or replace with a learner that is not caught up, or fails preflight | `409` `HEARTH_CLUSTER_LEARNER_NOT_READY` with the reason |
| Remove or replace the current leader | `409` `HEARTH_CLUSTER_TARGET_IS_LEADER`; step it down first |

Owner choices inside this table:

- **Minimum of 3 voters.** Pro: a cluster never shrinks into a size with no fault tolerance by accident. Con: a 3-node cluster cannot drop to 2 on purpose. The alternative is no minimum. **Recommendation: minimum 3.** An operator who wants one node uses single-node mode.
- **Removing the leader.** openraft allows it: the leader commits the change and steps down. Pro of allowing: one call. Con: the change's outcome depends on an election, which adds failure paths to test. **Recommendation: refuse**, and point to `POST /admin/cluster/transfer-leadership`.
- **Which node takes the call.** Leader only (a follower answers `409` with `leader_id`) is less code, but the operator cannot reach the leader's HTTP address from a peer ID. **Recommendation: any node**, forwarding over a new internal `ForwardMembershipChange` RPC, as writes are forwarded (H-3).

### 8. An interrupted change

| Option | Pros | Cons |
|---|---|---|
| **A. A new leader finishes a joint configuration** (on `on_leadership_acquired`) by proposing its newest voter set | The cluster leaves the joint state, which needs two majorities, without an operator | The new leader acts on a change it did not accept; it can only finish toward the newest set, never undo it |
| B. The operator re-issues the call | No automatic action | The cluster stays in a joint configuration, with two quorum requirements, until someone notices |

**Recommendation: A.** The operator's call already committed the joint entry, so finishing it is what the operator asked for. A change whose joint entry never committed is lost with the old leader; `GET` shows the old membership, and the operator re-issues it.

### 9. `cluster.peers` after a change

| Option | Pros | Cons |
|---|---|---|
| **A. `peers` is the bootstrap seed only; warn on drift** | Restarts always work; no node depends on its file being current | Files go stale; an operator must update them before a cold re-bootstrap from a backup |
| B. Refuse to start when `peers` differs from the Raft membership | Files stay current | A node cannot restart during an outage until every file is edited; a typo stops a node |
| C. Hearth rewrites `hearth.yaml` | Files stay current | Config is immutable after start (CLAUDE.md); config management tools own the file |

**Recommendation: A.** At start, and after each membership change it applies, a node compares its `peers` with the Raft membership. On a difference it logs a `WARN` naming both sets, and `/admin/cluster/status` and `GET /admin/cluster/members` report `peers_drift: true`. Docs tell the operator to update every node's file after a change. Restarts read the membership and addresses from `raft.db`, never from `peers`.

### 10. Snapshots: P-2 must come first

A learner at 1M users catches up by snapshot: the leader keeps about 1,000 entries after a snapshot (`max_in_snapshot_log_to_keep`), so any node that joins after the first 5,000 entries needs one. Today:

- The leader scans the whole store into a `Vec`, encodes all of it as CBOR, then gzips it. For a 2.0 GB store that is several GB of anonymous memory at once on a node that may have 4 GiB. It keeps the compressed copy in memory afterwards.
- The learner buffers every chunk into one `Vec`, then decompresses the whole payload before it writes a row.
- A learner that restarts during a transfer starts over, and a leader that restarts has no snapshot and builds a new one.

A leader that runs out of memory during an add takes the cluster's leader down at the moment it has a node in flux. So:

| Option | Pros | Cons |
|---|---|---|
| **A. P-2 first, as its own change: file-backed, streamed snapshots** (`SnapshotData = tokio::fs::File`; the builder streams rows to a file; install reads and writes in bounded batches) | Bounded memory on both ends; snapshots survive restarts (P-2's stated goal); openraft 0.9 already streams `AsyncRead + AsyncSeek` data in chunks | A storage-format change and its own crash tests before membership work can be used at size |
| B. Membership first, with a store-size cap for adds | Membership ships sooner | The cap would be below one realistic customer; the first real replacement hits the limit |
| C. Membership first, unsupported above a size | Same | Same, and an operator learns it from an OOM |

**Recommendation: A. P-2 must come first** for any store of realistic size. Phases 1–3 below can be built and tested on small stores in parallel with P-2. Phase 4's large-store check and the docs that call the feature usable wait for P-2. The P-2 change must keep the read fence that `cluster-read-fencing` adds to `install_snapshot` (decision 12).

### 11. Retired IDs and the G9 path

A removed ID is kept in a replicated retired-ID set (a system meta row, not in `cluster.peers`). `add` refuses a retired ID, and a peer RPC from a retired ID is answered `REMOVED`. With decision 5, a node that reused a retired ID would also fail the certificate check, because the operator issues certificates per ID. The documented replacement is always a new ID. The old "restart with an empty data directory under the same ID" procedure is removed from the docs.

### 12. Fit with `cluster-read-fencing`

That change (parked, now being resumed) closes reads during a snapshot install and records leader contact in `server.rs`. This change adds identity checks in `server.rs` and depends on P-2, which rewrites `install_snapshot`. Rules: the identity check runs before the contact is recorded (an RPC from the wrong node is not contact); P-2 closes the read gate before its first delete, as `cluster-read-fencing` requires of today's Phase 1. A learner that is out of contact or installing a snapshot is refused reads under that change; this change does not alter the gate.

## Failure cases

| Case | What happens | What the operator sees |
|---|---|---|
| The leader dies after the joint entry commits | The cluster stays joint; the new leader finishes it (decision 8) | The call answers `503` `..._OUTCOME_UNKNOWN`; `GET` shows `joint`, then the new set |
| The leader dies before the joint entry commits | The new leader may or may not hold the entry; if it does not, the change is gone | `503` unknown; `GET` shows the old or the new set; re-issue is idempotent |
| A partition during the joint phase | Commits need a majority of both sets. A side with both majorities elects a leader and finishes the change; otherwise no side commits and writes fail until the heal. Never two leaders | `503` on writes on the cut-off side; `GET` on the majority side |
| A learner never catches up (slow disk, a write rate above its apply rate, P-1's per-entry sync) | It stays a learner; it does not count to any quorum; promote is refused | `GET` shows lag and `catching_up_since`; `DELETE` aborts and retires the ID |
| A learner crashes during a snapshot install | The restore marker refuses its restart (HEA-2132). A learner has never voted, so nothing is lost by starting over: remove it, and add it again under a new ID with an empty data directory. P-2 may let a node resume instead; that is P-2's choice | The node's start-up error names the marker; `GET` shows the learner with no contact |
| A wrong KEK or master key on the learner | Preflight fails | Promote answers `409` `..._LEARNER_NOT_READY` with `kek_mismatch` |
| A wrong address (another node is there) | That node answers `WRONG_NODE`; the learner never catches up | `GET` shows the last refusal for the learner |
| `kill -9` of a voter during the change | The change needs a quorum of both sets among live voters; the planner refused changes that had none when they began | As a partition |
| A removed node keeps running | Peers answer it `REMOVED`; it goes inert (decision 6) | Its `/readyz` answers `503` `"removed"` |
| A wiped node restarts under its old, live ID | Not fenced (Open Question 1); same hazard as today | Documented as forbidden |

## Tests

Per `docs/dev/TESTING.md`. Every test is written first and fails before the implementation.

- **Unit (layer 1).** `plan_membership_change`: one case per refusal rule, and the accepted plans. Peer metadata checks in `server.rs` and `network.rs`: wrong target, wrong cluster, non-member, retired, and the pristine node's adoption of a cluster ID. Certificate node-ID extraction. `join_existing` validation. Drift detection.
- **Property (layer 3).** For any sequence of requests against a model membership with up to 7 nodes, some dead: every plan the planner accepts leaves at least 3 voters, never reuses an ID, and has a quorum of live voters in both the joint and the new set.
- **Black box, in process (layer 2).** `tests/cluster_fixture` gains a node that starts later and a fourth and fifth node. Tests: add and promote, caught up by log; caught up by snapshot (after `compact_log`); remove a voter; replace a dead voter; the leader isolated (`PeerFaults`) right after the joint entry commits, and the new leader finishes; a learner isolated so it never catches up, and promote refused; a partition during the joint phase, and convergence after the heal; a removed node that keeps running goes inert; a node with a wrong KEK is refused at promote; every acknowledged write is present on every voter afterwards.
- **Black box, real processes (layer 2).** `hearth serve` processes, as in `tests/cluster_serve_admin_status.rs`: the full HTTP flow with a system-realm token, forwarding from a follower, `GET` output, `/readyz` `learner` and `removed`, the `hearth cluster members replace` CLI, and `openapi_contract` coverage of the new routes.
- **Simulation (layer 5).** With P-2: `FaultFs` crashes during a snapshot file write and during a streamed install.
- **Jepsen (layer 5).** A `membership` nemesis on 3 initial voters plus 2 spare containers. Ops: `:add-learner`, `:promote`, `:remove`, `:replace` (kill a voter, wipe a spare, start it with a fresh ID and `join_existing`, run the CLI flow), mixed with partitions and `kill -9`, including `kill -9` of the leader during a change (CONSISTENCY.md §9). Checkers: the `set` and `register` checkers, plus a new membership checker: after the heal every live node reports the same membership, it is reachable from the acknowledged changes (an unknown outcome may go either way), no retired ID is a voter, and there are at least 3 voters. The checker is proven first on a planted violation (a history with a retired ID still a voter). The `replace` test switches to the new procedure.
- **Large store.** With P-2: a 1M-user store (bulk import), a learner added and promoted on AWS-sized nodes. Record catch-up time and the peak RSS rise on leader and learner. The check: neither node's RSS rises by more than 512 MiB.

## Phases and size

Rough sizes include tests. Each phase ends in a check.

| Phase | Work | Size | Check |
|---|---|---|---|
| 0 | **P-2** as its own change: file-backed, streamed snapshot build, send and install | L: ~1.5k lines, 2 PRs | Simulation crash tests; a 1M-user snapshot builds and installs with RSS rise under 512 MiB; Jepsen `snapshot` keeps its expectation |
| 1 | Peer identity: cluster ID, source and target IDs, certificate node-ID SAN, `REMOVED` | M: ~700 lines, 1 PR | Unit tests; `tests/cluster_grpc_loopback.rs` refuses a wrong-node certificate; full `make jepsen` unchanged (`0 fail`, `0 xpass`) |
| 2 | Engine: planner, add, promote, remove, replace, retired IDs, joint completion, removed state, `GetNodeInfo` preflight | L: ~1.5k lines, 2 PRs | Property test; in-process multi-node tests, including every failure case above |
| 3 | Operator surface: endpoints, forwarding RPC, audit actions, CLI, `join_existing`, start-up window, `/readyz` reasons, drift warning | M–L: ~1.2k lines, 2 PRs | Real-process tests; `openapi_contract`; `make ui-test-*` not needed (no UI); `make check` |
| 4 | Jepsen membership nemesis and checker; `replace` rewritten; large-store run (needs phase 0) | M: ~600 lines of Clojure, 1 PR | `make jepsen` with `membership` and `replace` `pass` on 3 consecutive runs, `0 fail`, `0 xpass`; the large-store numbers recorded in `docs/perf/` |
| 5 | Docs: C-6 fixed, add/remove/replace runbooks, certificate recipe, CONSISTENCY §6 and §9, ARCHITECTURE §16, configuration reference, CHANGELOG | S: 1 PR | `make ci-local-fast`; `openspec validate cluster-membership-changes --strict` |

About 5.5k lines in 9 PRs. Phase 0 runs in parallel with phases 1–3. Phase 4's large-store run and phase 5's "usable" wording wait for phase 0.

## Risks / Trade-offs

- [openraft 0.9 leaves a joint configuration on leader loss] → decision 8 finishes it; the in-process and Jepsen tests kill the leader between the two entries.
- [A new peer-identity check refuses a legitimate RPC and stalls the cluster] → phase 1 lands alone, with the full Jepsen suite as its check, before any membership code.
- [P-1's per-entry sync means a learner replays log entries at about 27 per second] → a learner that falls behind catches up by snapshot instead; `GET` shows lag, and the docs say to add nodes at low write load. P-1 stays its own item.
- [Re-issuing every peer certificate (decision 5C)] → breaking, but cluster mode has no production users; Jepsen's `gen-material.sh` and the guide's recipe change in the same PRs.
- [Scope: P-2 plus membership is about 9 PRs] → phases end in checks, so the work can stop after any phase with the cluster no worse than today.

## Migration Plan

Cluster mode only, no production users. A cluster on the old release is rebuilt: take a backup, start the new release's nodes from it with new certificates (the guide's rebuild procedure). Nodes of the two releases refuse each other (peer metadata). Single-node mode needs nothing. Rollback is the same rebuild on the old release.

## Open Questions

1. **A wiped node under a live ID.** A node restarted by hand under its old, still-member ID with an empty data directory has forgotten its vote, and none of the checks above detect it (it has the right certificate and adopts the cluster ID). A fix: each node generates an incarnation UUID on first start; the leader records it in the member's Raft node record when it first hears from it; a peer with a different incarnation is refused. It adds a field to every RPC and a learn-on-first-contact step at bootstrap. Is it in this change, or a follow-up?
2. **A permanent learner** as a read replica or a backup source. Out of scope here; worth its own change?
3. **Catch-up threshold.** 100 entries on two reports in a row is a guess; phase 2's tests should set it.
