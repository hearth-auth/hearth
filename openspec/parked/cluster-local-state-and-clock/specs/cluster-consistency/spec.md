## ADDED Requirements

### Requirement: Node-local state stays on its node
A node's attempt-tracker state SHALL NOT leave the node. A snapshot SHALL NOT carry it. When a node installs a snapshot, it SHALL keep its own attempt-tracker state for every realm that the snapshot contains. It SHALL NOT take another node's attempt-tracker state. When a realm is absent from the snapshot, the node SHALL remove all of that realm's data, attempt-tracker state included.

#### Scenario: A follower installs a snapshot
- **WHEN** a client fails a login three times on a follower and five times on the leader
- **AND** the follower falls behind and installs a snapshot from the leader
- **THEN** the follower still counts three failures for that user
- **AND** the follower does not count the leader's five failures

#### Scenario: A follower restarts after a snapshot install
- **WHEN** a follower that counted failed logins installs a snapshot
- **AND** the follower restarts
- **THEN** the follower restores its own failure count, not the leader's

#### Scenario: A realm deleted while a follower was behind
- **WHEN** a follower holds attempt-tracker state for a realm
- **AND** the realm is deleted while the follower is cut off
- **AND** the follower installs a snapshot that does not contain the realm
- **THEN** the follower holds no data for that realm

### Requirement: M1 A leader steps down before a graceful shutdown
When a cluster node that is the leader receives a shutdown signal, it SHALL hand over leadership before it stops its Raft peer connections. From the signal until the handover ends, it SHALL answer a write that it would propose with `503` and `HEARTH_CLUSTER_UNAVAILABLE`. It SHALL NOT answer such a write with `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN`. The handover SHALL end within `operational.shutdown_timeout_secs`. When no other node wins an election in that time, the node SHALL log a warning and continue its shutdown. A follower SHALL shut down without a handover.

#### Scenario: The leader is stopped with SIGTERM
- **WHEN** the leader of a healthy 5-node cluster receives `SIGTERM`
- **THEN** another node becomes leader before the old leader's process exits
- **AND** writes succeed on the remaining nodes after the new leader is elected

#### Scenario: A write reaches the stopping leader
- **WHEN** the leader has received `SIGTERM`
- **AND** a client sends a write to that node before its process exits
- **THEN** the node answers `503` with `HEARTH_CLUSTER_UNAVAILABLE`
- **AND** the write is not applied on any node

#### Scenario: No successor can be elected
- **WHEN** the leader receives `SIGTERM` while a majority of the other voters is down
- **THEN** the node logs a warning that the handover did not complete
- **AND** the process exits within `operational.shutdown_timeout_secs`

### Requirement: C3 Every node stores the same timestamp for a record
A timestamp stored in a replicated record SHALL be identical on every node. It SHALL come from the clock of the node that handled the request. Timestamps of records that different nodes handled MAY be out of order by up to the clock offset between those nodes.

#### Scenario: A user created on a follower with a fast clock
- **WHEN** a follower whose clock is `10` seconds ahead of the leader's creates a user
- **THEN** every node stores the same creation time for that user
- **AND** that creation time is the follower's clock reading

#### Scenario: Records created on two nodes with skewed clocks
- **WHEN** node A, whose clock is `2` seconds behind node B's, creates a user one second after node B creates another
- **THEN** every node stores node A's user with the earlier creation time
