## ADDED Requirements

### Requirement: Scope and terms
This capability SHALL apply in cluster mode only. Cluster mode is on when `hearth.yaml` has a `cluster:` section. Single-node mode has one copy of the data, and every read there sees every acknowledged write.

The terms below SHALL have one meaning in this capability:

| Term | Meaning |
|---|---|
| Committed | The Raft entry is durable on a majority of voters. |
| Applied | A node's state machine has written the entry's effect to its local storage. |
| Acknowledged | Hearth answered the HTTP request with success. |
| Unknown outcome | Hearth answered `503` with `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN`. |
| Unavailable | Hearth answered `503` with `HEARTH_CLUSTER_UNAVAILABLE`. |
| In contact | The node has heard from the current leader of the highest term it knows within `read_lag_threshold_ms`. |

Each promise in this capability has an ID (`W1`, `R1`, `V1`, `C1`, …). Tests and issues SHALL cite promises by ID.

#### Scenario: No cluster section
- **WHEN** `hearth.yaml` has no `cluster:` section
- **THEN** the promises in this capability do not apply
- **AND** a read shows every write acknowledged before the read began

### Requirement: W1 Acknowledged writes are committed
An acknowledged write SHALL be committed. It SHALL survive the loss of any minority of voters, including `kill -9`, power loss and restart. This promise SHALL hold for the production storage configuration. It does not hold under `--dev`, because `--dev` storage does not fsync.

#### Scenario: A minority is killed after the acknowledgement
- **WHEN** a write is acknowledged on a 5-node cluster
- **AND** two nodes are killed with `kill -9` and restarted
- **THEN** every node shows the write after it has caught up

#### Scenario: The leader is killed after the acknowledgement
- **WHEN** the leader acknowledges a write and is then killed with `kill -9`
- **THEN** the new leader shows the write

### Requirement: W2 Acknowledged writes keep their order
Acknowledged writes SHALL never be lost and never reordered. Every node SHALL apply committed entries in log order.

#### Scenario: Two writes to the same record
- **WHEN** write A to a record is acknowledged before write B to the same record is sent
- **THEN** after the cluster heals, every node shows the value of write B

### Requirement: W3 Unknown and unavailable write answers
A write answered with **unknown outcome** MAY have committed or MAY NOT. A client MUST treat it as unknown and re-read before it retries. A write answered **unavailable** SHALL NOT have committed. Both answers SHALL carry `Retry-After: 2`.

#### Scenario: The leader dies during a forwarded write
- **WHEN** a follower forwards a write and the leader dies before the follower learns the outcome
- **THEN** the follower answers `503` with `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN` and `Retry-After: 2`
- **AND** the write may or may not be visible after the cluster heals

#### Scenario: An unavailable write never appears
- **WHEN** a write is answered `503` with `HEARTH_CLUSTER_UNAVAILABLE`
- **THEN** no node ever shows that write

### Requirement: W4 A single-use claim succeeds at most once
A single-use artifact SHALL be redeemed successfully at most once across the cluster, for any number of racing nodes and under any network partition.

#### Scenario: Racing redemptions on different nodes
- **WHEN** clients on five nodes redeem the same single-use artifact at the same time
- **THEN** at most one redemption succeeds

### Requirement: W5 A counter increment counts once per log entry
A replicated counter increment SHALL count at most once per log entry. This SHALL also hold when a snapshot install re-applies entries.

#### Scenario: Re-applied entries after a snapshot install
- **WHEN** a node installs a snapshot and then applies log entries that the snapshot already covers
- **THEN** each counter holds the same value as on a node that applied each entry once

### Requirement: R1 Read-your-writes on the same node
After node N acknowledges a write, a read on node N SHALL show that write. This applies when the write was sent to a follower and forwarded to the leader, too.

#### Scenario: A write forwarded by a follower
- **WHEN** a client sends a write to a follower and the follower acknowledges it
- **THEN** the client's next read on that follower shows the write

### Requirement: R5 Reads are local to the receiving node
A node SHALL serve a read from its own local storage. Hearth SHALL NOT promise linearizable reads. A client MUST NOT expect a read on one node to show a write acknowledged by another node.

#### Scenario: A read on a different node
- **WHEN** node A acknowledges a write
- **AND** the client then reads on node B
- **THEN** the read may not show the write yet

### Requirement: V1 Revocations reach every node in contact
After a revocation of a session, a token (JTI) or a permission is acknowledged, every node in contact SHALL reject the revoked item. It SHALL do so within the replication delay plus `400 ms` (the `200 ms` reload spacing plus the `200 ms` epoch sync interval). Access tokens issued before the revocation stay valid until they expire, as the `rbac-token-claims` capability states.

#### Scenario: A session revoked on the leader
- **WHEN** an operator revokes a session on the leader and the revocation is acknowledged
- **THEN** each follower in contact rejects the session within the replication delay plus `400 ms`

### Requirement: V3 An owed revocation epoch bump is never forgotten
A revocation that cannot bump the control epoch at once SHALL be retried until the bump succeeds, or until the next leader's election bump covers it.

#### Scenario: The bump fails during a leader change
- **WHEN** a session revocation commits but the epoch bump that follows it fails
- **THEN** the node retries the bump with backoff
- **AND** if a new leader is elected first, its election bump makes every node drop its session caches

### Requirement: C1 Safety does not depend on clocks
W1–W5 and R1 SHALL hold under any clock skew between nodes. Clocks MAY affect only liveness (elections) and expiry checks.

#### Scenario: A node's clock jumps
- **WHEN** one node's clock jumps forward by an hour during a write workload
- **THEN** no acknowledged write is lost
- **AND** at most one redemption of a single-use artifact succeeds

### Requirement: C2 Expiry checks tolerate clock skew
Expiry checks SHALL tolerate up to `60` seconds of clock skew between nodes.

#### Scenario: A token checked on a node with a slow clock
- **WHEN** a node whose clock is `30` seconds behind the issuing node validates a token
- **THEN** the token is not rejected as not yet valid

### Requirement: C4 A node warns about clock offset from the leader
A node SHALL log a warning when its clock differs from the leader's by more than `1` second. It SHALL estimate the offset from the leader timestamps of the entries it receives that the leader has not yet committed, take the smallest age over a `30`-second window, and warn at most once per window. Replication delay alone SHALL NOT cause the warning. The warning SHALL NOT change how the node answers requests.

#### Scenario: A follower's clock drifts
- **WHEN** a follower's clock is `2` seconds ahead of the leader's
- **AND** the follower receives new entries for `30` seconds
- **THEN** the follower logs one clock-offset warning
- **AND** it keeps serving requests

#### Scenario: A follower catches up after a restart
- **WHEN** a follower whose clock agrees with the leader's receives entries the leader committed while it was down
- **THEN** the follower logs no clock-offset warning

### Requirement: Node-local state is per node
Attempt trackers (user login, IP login, MFA, magic link, password reset, registration), rate limiters and the KDF admission gate SHALL be per node. A client MUST NOT expect lockout counts or rate limits to agree between nodes. When `hearth.yaml` does not configure the session-cookie secret or the DPoP nonce secret, each process SHALL generate its own, so a cookie or nonce from one node fails on another.

#### Scenario: Failed logins spread over two nodes
- **WHEN** a client fails a login three times on node A and three times on node B
- **THEN** each node counts three failures, not six

#### Scenario: A session cookie from another node
- **WHEN** the session-cookie secret is not configured
- **AND** a browser sends a session cookie issued by node A to node B
- **THEN** node B does not accept the cookie
