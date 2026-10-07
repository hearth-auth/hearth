# Cluster Consistency

Status: **Reference. Cluster mode is incomplete.** The normative promises — the ones Hearth
meets today — are in [`openspec/specs/cluster-consistency/spec.md`](../../openspec/specs/cluster-consistency/spec.md).
The Jepsen harness that tests them is described in [`jepsen/README.md`](../../jepsen/README.md).
This document keeps the target model, the evidence for each status and the open items (G1–G9).
Requirement levels follow RFC 2119 (MUST / SHOULD / MAY).
Scope: what a client of a multi-node Hearth cluster may rely on — for writes, reads,
revocations, clocks and membership. The implementation lives under `src/cluster/`, with the
cluster-facing parts of the identity engine under `src/identity/engine/`.

This document defines the **target** model. Every promise carries a status:

- **Implemented** — the code is built to meet it. A failing test against it is a bug.
- **Not yet implemented (G-n)** — the code does not meet it yet. Section 8 says what is
  missing. A failing test against it is expected and measures progress, not a defect.

Where an **Implemented** promise and the code disagree, that is a bug in one of them — file an
issue. Single-node mode (no `cluster:` section) is outside this document: it has one copy of
the data and every read sees every acknowledged write.

Each promise has an ID (`W1`, `R2`, …). Tests, issues and the Jepsen harness cite these IDs.

---

## 1. Scope and terms

Cluster mode is on when `hearth.yaml` has a `cluster:` section (`src/main.rs:1315`). All
application storage then goes through `ClusterStorageAdapter` (`src/main.rs:1369`) over a
`ClusterEngine` (`src/cluster/engine.rs`), which replicates with `openraft` 0.9.

| Term | Meaning |
|---|---|
| **Committed** | The Raft entry is durable on a majority of voters. |
| **Applied** | A node's state machine has written the entry's effect to its local storage. |
| **Acknowledged** | Hearth answered the HTTP request with success. |
| **Unknown outcome** | Hearth answered `503` with `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN`. The write may or may not have committed. |
| **Unavailable** | Hearth answered `503` with `HEARTH_CLUSTER_UNAVAILABLE`. The write was not proposed, or the read was refused. |
| **Stale read** | A read that does not show a write that was acknowledged before the read began. |
| **In contact** | A node has heard from the current leader of the highest term it knows within `read_lag_threshold_ms`. |
| **Node-local state** | State one node holds for itself. It is not replicated (section 7). |

Both `503` codes carry `Retry-After: 2` (`src/protocol/http.rs:180-198`). Their wire codes are
defined in `src/identity/error/wire_codes.rs:190-197`.

---

## 2. Write promises

| ID | Promise | Status |
|---|---|---|
| **W1** | An acknowledged write is committed. It survives the loss of any minority of voters, including `kill -9`, power loss and restart. | Implemented |
| **W2** | Acknowledged writes are never lost and never reordered. Every node applies committed entries in log order. | Implemented |
| **W3** | A write answered with **unknown outcome** MAY have committed or MAY NOT. Clients MUST treat it as unknown and re-read before retrying. A write answered **unavailable** was not committed. | Implemented |
| **W4** | A single-use claim (`PutIfAbsent`) succeeds at most once across the cluster, for any number of racing nodes. | Implemented |
| **W5** | A counter increment (`IncrementU64`) counts at most once per log entry, also when a snapshot install re-applies entries. | Implemented |
| **W6** | A client can retry an unknown-outcome write safely, because the server recognises the repeat. | Not yet implemented (G7) |
| **W7** | The audit hash chain stays one linear chain when two nodes append at the same time. | Not yet implemented (G4) |

Evidence:

- **W1, W2.** Every replicated write becomes a `RaftCommand` and is proposed with
  `Raft::client_write` (`src/cluster/engine.rs:926`). The leader answers after commit and its
  own apply. A follower forwards the command to the leader (`engine.rs:851-917`) and answers
  only after its own state machine has applied the same index. Each Raft log append is a redb
  commit before openraft is told the I/O completed (`src/cluster/log_store.rs:356-388`). Each
  applied entry is one atomic `write_batch` with its applied index (`state_machine.rs:541-552`).
  The storage engine fsyncs every write in production (`SyncMode::EveryWrite`,
  `src/storage/engine.rs:247-252`).
- **W1 does not hold under `--dev`.** `StorageConfig::dev` uses `SyncMode::None`
  (`src/storage/engine.rs:207-216`). A test of W1 MUST run a production storage config.
- **W3.** A timed-out proposal is not cancelled, so it can still commit (`engine.rs:838-850`).
  A forwarded write is retried only when it provably never entered a log (`engine.rs:826-836`).
  The mapping from cluster errors to the two `503` codes is in `engine.rs:1744-1765`.
- **W4.** Single-use artifacts are claimed with a `consumed:` marker through `put_if_absent`,
  evaluated inside the state machine's apply (`state_machine.rs:573`). The list of artifacts is in
  [ARCHITECTURE.md §16.3](./ARCHITECTURE.md#163-cluster-read-consistency).
- **W5.** The counter keeps a sidecar row with the index of the last entry that moved it
  (`increment_once`, `state_machine.rs:807`).

---

## 3. Read promises

Hearth does **not** promise linearizable reads. Reads are served from the local storage of the
node that receives the request. Sending all traffic to the leader is not a full fix: a leader
that has lost its quorum does not know it is deposed and keeps serving reads.

| ID | Promise | Status |
|---|---|---|
| **R1** | **Read-your-writes on the same node.** After a write is acknowledged by node N, a read on node N shows it. | Implemented |
| **R2** | **Bounded staleness.** A node MUST serve reads only while it is **in contact**. Otherwise it MUST answer **unavailable**. A read served by a node in contact misses no write acknowledged more than `read_lag_threshold_ms` before the read began. | Not yet implemented (G1) |
| **R3** | **Monotonic reads on one node.** Two reads on the same node never go backwards in log order. | Not yet implemented (G2) — holds except during a snapshot install |
| **R4** | **No partial state.** No read observes a partly installed snapshot. | Not yet implemented (G2) |
| **R5** | A client that reads on a different node than the one it wrote to gets R2, not R1. | Implemented (as a statement of scope) |

Evidence:

- **R1.** The follower waits for its own apply before it answers a forwarded write
  (`engine.rs:891-902`, `await_applied` at `:895`). The leader answers after its own apply.
- **R2 today.** A background task sets `reads_allowed` every 50 ms (`run_lag_monitor`, `engine.rs:1511-1528`). It
  estimates lag as `(last_log_index − last_applied) × 5 ms` (`compute_lag_ms`,
  `engine.rs:1545-1553`). That measures only entries the node has received and not applied. A
  node that receives nothing — a partitioned follower, or a deposed leader — shows lag `0` and
  keeps serving reads with no time limit. No read uses `ensure_linearizable`, a read index or a
  leader lease.

---

## 4. Revocation promises

Revocations matter most for an identity server: a session, token or permission that was
revoked must stop working on every node.

| ID | Promise | Status |
|---|---|---|
| **V1** | After a revocation is acknowledged, every node **in contact** rejects the revoked session, token (JTI) or permission within: replication delay + `RELOAD_MIN_SPACING` (200 ms) + `EPOCH_SYNC_INTERVAL_MICROS` (200 ms). | Implemented — bound not yet measured under faults |
| **V2** | A node that is not in contact MUST NOT accept a credential that it cannot prove is still live. It MUST answer unavailable instead (same rule as R2). | Not yet implemented (G1) |
| **V3** | A revocation that cannot bump the control epoch is never forgotten. It is retried until it succeeds, or covered by the next leader's election bump. | Implemented |

Evidence:

- Applied rows reach node-local caches through the Raft observer
  (`src/identity/engine/mod.rs:1072-1160`): RBAC rows, the audit chain head, revoked JTIs,
  the control epoch and realm signing-key epochs.
- Session revoke and user deletion bump the control epoch (`bump_control_epoch`,
  `mod.rs:5401`). On every other node the reloader then drops the session and token-claims
  caches (`src/identity/engine/control.rs:781-786`). Reloads are at least `RELOAD_MIN_SPACING`
  apart (`control.rs:122`).
- An owed bump is retried with backoff. A node that becomes leader bumps the epoch once
  (`control.rs:74-88`).
- Access tokens already issued stay valid until they expire. That is the normal JWT trade-off
  and is outside V1 — see the `rbac-token-claims` spec ([openspec/specs/rbac-token-claims/spec.md](../../openspec/specs/rbac-token-claims/spec.md)) and the [session-version guide](../guides/session-version-revocation.md).

---

## 5. Clock promises

| ID | Promise | Status |
|---|---|---|
| **C1** | Safety does not depend on clocks. W1–W5 and R1 hold under any clock skew. Clocks may only affect liveness (elections) and expiry. | Implemented — not yet tested under skew |
| **C2** | Expiry checks tolerate up to `CLOCK_SKEW_SECS` (60 s) of skew between nodes (`mod.rs:204`, `src/identity/tokens.rs:64`). | Implemented |
| **C3** | Timestamps stored in replicated records come from the leader's clock, so all nodes agree on them. | Not yet implemented (G8) |
| **C4** | A node warns when its clock differs from the leader's by more than 1 s. | Implemented (warn only) |

Evidence:

- Raft timers: heartbeat 500 ms, election timeout 1,500–3,000 ms (`engine.rs:361-370`).
- Every `RaftCommand` carries a `leader_timestamp`, and the leader restamps forwarded commands.
  But the state machine discards it at apply (`leader_timestamp: _`,
  `state_machine.rs:499-531`). Timestamps inside the stored records come from the node that
  built the record.

---

## 6. Membership

Membership is **static**. It is set once, from `cluster.peers`, when the cluster first starts:
the node with the lowest ID calls `initialize` if Raft is not yet initialised
(`engine.rs:445-500`), or an operator calls `POST /admin/cluster/bootstrap`.

- There is no way to add or remove a voter. No code calls `add_learner` or
  `change_membership` (G5).
- Editing `cluster.peers` and restarting does **not** change membership. Membership lives in
  the Raft log, and `initialize` runs only on an uninitialised node.
- A failed node stays a voter. A 3-node cluster with one dead node keeps working, but it now
  tolerates no further failure.
- The documented way to replace a node is to restart it **with the same node ID and address**
  and an empty data directory; the leader sends it a snapshot
  ([backup guide](../guides/backup.md)). That node has forgotten its Raft vote. Raft's safety
  proof assumes a node never forgets its vote (G9).
- `POST /admin/cluster/transfer-leadership` is an untargeted step-down
  (`src/protocol/cluster_admin.rs:186-207`). Shutdown does not call it (G6).

---

## 7. Node-local state

These are **not** replicated. A client MUST NOT expect them to agree between nodes.

| State | Where | Effect for clients |
|---|---|---|
| Attempt trackers: user login, IP login, MFA, magic-link, password-reset, registration | `put_node_local` / `delete_node_local` (`engine.rs:1781-1797`); callers in `src/identity/engine/mod.rs:2427-3202` | Lockout counts are per node. An attacker spread over N nodes gets N budgets. |
| Rate limiters and the KDF admission gate | in memory | Limits are per node. |
| Session-cookie and DPoP nonce secrets, when not configured | generated per process | A cookie or nonce from one node fails on another. Configure them for a cluster. |
| Session, claims, RBAC, realm-status and blocklist caches | in memory | Kept coherent by the observer and the control epoch (V1). |
| Raft applied-state rows (`\0raft:sm:applied`, `\0raft:sm:membership`) | `state_machine.rs:683-701` | Excluded from snapshots. |

Attempt-tracker rows are node-local by design, but snapshots still carry them (G3).

---

## 8. Not yet implemented

Each item names the promise it blocks, what the code does today, and what must be built. These
are build steps for finishing cluster mode, not regressions.

| ID | Blocks | Today | To build |
|---|---|---|---|
| **G1** | R2, V2 | The read gate measures only unapplied backlog (`engine.rs:1545-1553`). A partitioned follower or a deposed leader serves reads with no time limit. openraft 0.9 does not step a leader down on a lost quorum. Partial mitigation (2026-10-06): `/readyz` answers `503` on a node with no known leader, or a leader no quorum has acknowledged for over 3 s, so a load balancer that honours readiness stops routing to it. The node itself still serves those reads. | A contact check: refuse reads when the node has not heard from a current leader (follower) or a quorum (leader) within `read_lag_threshold_ms`. |
| **G2** | R3, R4 | Snapshot install deletes every key, then writes the snapshot, on the live engine (`restore_snapshot_in_place`, `state_machine.rs:920`). Reads are not fenced meanwhile (`read_inline`, `engine.rs:795-805`). | Refuse reads (unavailable) while an install runs. |
| **G3** | Section 7 | The snapshot builder skips only the two applied-state rows (`state_machine.rs:155`). Tracker rows travel to the installing node and replace its own. | Exclude node-local key families from snapshot build and from the install's delete phase. |
| **G4** | W7 | The audit chain head is read and written under a per-node mutex, then written with a plain `write_batch` (`src/audit/engine.rs:682`, `850`, `1166-1199`). Nothing stops two nodes from chaining from the same head. | Make the head advance a conditional Raft command, or append on the leader only. |
| **G5** | Section 6 | No `add_learner` / `change_membership`. | Online membership changes (joint consensus) with an admin API. |
| **G6** | [ARCHITECTURE.md §12.5](./ARCHITECTURE.md#125-graceful-shutdown) | Shutdown calls only `raft.shutdown()` (`src/main.rs:3155` → `engine.rs:546-552`). | Step down before the drain when the node is leader. |
| **G7** | W6 | `RaftCommand` has no request ID. No idempotency key exists. | A client request ID, deduplicated in the state machine. |
| **G8** | C3 | `leader_timestamp` is discarded at apply (`state_machine.rs:499-531`). | Apply the leader's timestamp to replicated records, or drop the C3 promise. |
| **G9** | Section 6 | Replacing a node reuses its ID with an empty data directory, which discards its saved vote. If that node is the lowest ID, it also self-initialises on start (`engine.rs:493-497`). The leader also still records the entries the node had: in a Jepsen `replace` run (2026-10-07) a node replicating to the wiped node aborted on an integer underflow in openraft's progress tracking (`progress/entry/mod.rs:267`; the release profile checks overflow and aborts on panic). | A replacement procedure that does not reuse a voter's identity — needs G5. |

---

## 9. Jepsen test mapping

Each row is one test of the Jepsen suite; "Test" is its name in the catalog
(`jepsen/src/jepsen/hearth/core.clj`) and in `make jepsen TEST=<name>`. "Expected" says how the
suite reads the result: **pass** is required; **xfail** is an expected failure that tracks a
G-item and flips to **pass** when the G-item lands (`jepsen/expectations.edn`).

| Promise | Test | Workload | Faults | Checker | Expected |
|---|---|---|---|---|---|
| W1, W2, W3 | `register` | Write one user attribute per key; every node reads every key after the heal | Partitions, leader isolation, `kill -9` and restart | Knossos per key over the writes and final reads (an `:info` write may or may not have happened); every node reads the same final value | pass |
| W1 | `set` | Add unique users; every node reads the full set after the heal | Partitions, `kill -9` | Every acknowledged add is in every node's final read; no failed add is | pass |
| W4 | `single-use` | Every node redeems the same refresh token | Partitions, `kill -9` | At most one success per token | pass |
| W5 | none | — | — | Unit tests only (see below) | unit tests |
| W7 | `audit` | Audited admin changes on every node at once; every node verifies the audit chain | none | The chain verifies on every node | xfail (G4) |
| R1 | `same-node` | Write, then read back on the same node | Partitions, leader isolation | The read shows the write | pass |
| R2 | `staleness` | One writer writes increasing values; every node reads | Partitions, leader isolation | No read returns less than a write acknowledged more than `read_lag_threshold_ms` before it began | xfail (G1) |
| R3, R4 | `snapshot` | Cut one node off, write past the snapshot point, heal; read the node while it installs the snapshot | Timed partition; `read_lag_threshold_ms` raised for this test only | No read goes backwards or misses data; at least one install logged | xfail (G2) |
| V1 | `revocation` | Revoke a session, then validate it on every node | Delays on the peer links | Rejected on every node within the V1 bound | pass |
| V2 | `revocation-isolated` | Cut one node off, revoke a session elsewhere, validate it on the cut-off node | Timed partition | The cut-off node never accepts the session after the bound | xfail (G1) |
| Section 6 | `replace` | The `set` workload while the lowest Raft ID is replaced: killed, data directory emptied, restarted with the same ID | Partitions, the replacement | The `set` checkers | xfail (G9) |
| — | `noop` | No client operations | none | Setup, faults, log collection and convergence work | pass |

The `snapshot` test raises `cluster.read_lag_threshold_ms`. With the default (500 ms), the lag
monitor happens to refuse reads within 50 ms of a snapshot's arrival, before the restore
deletes a key, so a client cannot see G2. G2 stays open: the install itself does not refuse
reads, and an operator who raises the threshold gets partial reads. Mid-install, the realm
admin's token is refused `401` or `403` because the session, grant or client behind it is
gone; the test counts that as missing data.

C1 has no test. Docker containers share one kernel clock, so a node cannot be given its own
skew; C1 needs VMs.

W5 has no Jepsen test. The only replicated counter is the control epoch, and no API returns
its value; `/metrics` exports only `hearth_control_epoch_bump_failures_total` and
`hearth_control_epoch_bumps_owed`. Every election also bumps it, so a final count could not
separate test bumps from election bumps. The unit tests in `src/cluster/state_machine.rs`
(`increment_command_returns_successive_values`, `a_replayed_increment_is_not_counted_twice`)
cover W5, including a replayed entry. A Jepsen test needs a counter an API can read back.

Membership-change tests (`kill -9` during a membership change) wait for G5.

Node-local state (section 7) is out of scope for these checkers: a test MUST NOT expect lockout
counts or rate limits to agree between nodes.
