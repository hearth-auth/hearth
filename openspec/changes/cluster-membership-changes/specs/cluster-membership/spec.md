## ADDED Requirements

### Requirement: Membership changes are admin API calls
Hearth SHALL change a running cluster's membership only through the endpoints under `/admin/cluster/members`. A caller SHALL need a system-realm token that holds `hearth.admin`. Any other token SHALL get `403`. Any member SHALL accept a call and forward it to the leader. A node in single-node mode SHALL answer `503`. The leader SHALL record an audit event in the system realm for every committed change.

#### Scenario: A tenant-realm admin tries to add a node
- **WHEN** a token from a tenant realm calls `POST /admin/cluster/members`
- **THEN** Hearth answers `403`
- **AND** the membership does not change

#### Scenario: A call reaches a follower
- **WHEN** a valid system-realm admin calls `POST /admin/cluster/members` on a follower
- **THEN** the follower forwards the call to the leader
- **AND** the answer is the same as on the leader

#### Scenario: A committed change is audited
- **WHEN** a learner is promoted to voter
- **THEN** the system realm's audit trail holds one `ClusterMemberPromoted` event naming the node ID and the caller

### Requirement: A membership call with an unknown outcome says so
When the commit of a membership change is not confirmed within `cluster.write_timeout_ms`, Hearth SHALL answer `503` with `HEARTH_CLUSTER_MEMBERSHIP_OUTCOME_UNKNOWN`. Each membership call SHALL be idempotent on its target state. A repeated call whose target state already holds SHALL answer success and change nothing.

#### Scenario: The leader dies during a promote
- **WHEN** the leader dies after it accepted a promote and before it answered
- **THEN** the caller gets `503` with `HEARTH_CLUSTER_MEMBERSHIP_OUTCOME_UNKNOWN`
- **AND** `GET /admin/cluster/members` later shows the node as a learner or as a voter, never as anything else

#### Scenario: A promote is repeated
- **WHEN** the operator promotes a node that is already a voter
- **THEN** Hearth answers `200`
- **AND** no membership entry is proposed

### Requirement: A new node joins as a learner
A node with `cluster.join_existing: true` SHALL NOT initialise a cluster. It SHALL NOT read `cluster.peers`. It SHALL wait to be added with no start-up deadline. While a node is a learner, its `/readyz` SHALL answer `503` with `"cluster": "learner"`. A learner SHALL NOT count towards any quorum.

#### Scenario: A joining node has the lowest ID in its peers
- **WHEN** a node with `cluster.join_existing: true` starts on an empty data directory
- **AND** its `cluster.peers` names only nodes with higher IDs
- **THEN** it does not initialise a cluster
- **AND** it waits until a leader adds it

#### Scenario: A learner is behind a load balancer
- **WHEN** a node has been added as a learner and has caught up
- **THEN** its `/readyz` answers `503` with `"cluster": "learner"` until it is promoted

### Requirement: A learner is promoted only when it is ready
Hearth SHALL promote a learner to voter only when the learner is caught up with the leader's log. Hearth SHALL also require that the learner reports the cluster's ID, the node ID it was added under, the leader's build version, and that it can unwrap the cluster's stored signing key with its own keys. Otherwise the promote SHALL answer `409` with `HEARTH_CLUSTER_LEARNER_NOT_READY` and the failed check.

#### Scenario: A learner still receiving a snapshot
- **WHEN** the operator promotes a learner that is still receiving its first snapshot
- **THEN** Hearth answers `409` with `HEARTH_CLUSTER_LEARNER_NOT_READY` and reason `not_caught_up`

#### Scenario: A learner with a different key-encryption key
- **WHEN** the operator promotes a caught-up learner whose `security.key_encryption_key` differs from the cluster's
- **THEN** Hearth answers `409` with `HEARTH_CLUSTER_LEARNER_NOT_READY` and reason `kek_mismatch`
- **AND** the learner stays a learner

### Requirement: Voter changes use joint consensus, one at a time
Every change to the set of voters SHALL pass through a joint configuration that needs a majority of the old voters and a majority of the new voters. Hearth SHALL refuse a membership call while a membership entry is uncommitted or the configuration is joint. It SHALL answer `409` with `HEARTH_CLUSTER_MEMBERSHIP_IN_PROGRESS`.

#### Scenario: Two changes at once
- **WHEN** a promote is in its joint phase
- **AND** a second call asks to remove another voter
- **THEN** the second call gets `409` with `HEARTH_CLUSTER_MEMBERSHIP_IN_PROGRESS`

### Requirement: A change never leaves the cluster without a quorum
Hearth SHALL refuse a change whose new voter set has fewer than `3` voters. It SHALL answer `409` with `HEARTH_CLUSTER_TOO_FEW_VOTERS`. Hearth SHALL refuse a change when the new voter set, or the joint configuration, has no majority among the voters that recently acknowledged the leader. It SHALL answer `409` with `HEARTH_CLUSTER_NO_QUORUM_AFTER_CHANGE`.

#### Scenario: Shrinking a 3-voter cluster
- **WHEN** the operator removes a voter from a cluster of `3` voters
- **THEN** Hearth answers `409` with `HEARTH_CLUSTER_TOO_FEW_VOTERS`

#### Scenario: Removing a live voter while another is dead
- **WHEN** a cluster has `5` voters and `2` of them are dead
- **AND** the operator removes one of the `3` live voters
- **THEN** Hearth answers `409` with `HEARTH_CLUSTER_NO_QUORUM_AFTER_CHANGE`

### Requirement: Node IDs and addresses are never shared
Hearth SHALL refuse to add a node ID that is a member or that was ever removed. It SHALL answer `409` with `HEARTH_CLUSTER_NODE_ID_USED`. A removed node ID SHALL stay retired for the life of the cluster. Hearth SHALL refuse to add a node at an address another member has. It SHALL answer `409` with `HEARTH_CLUSTER_ADDRESS_IN_USE`.

#### Scenario: A replacement reuses the dead node's ID
- **WHEN** voter `3` was replaced by node `4`
- **AND** the operator adds a node with ID `3`
- **THEN** Hearth answers `409` with `HEARTH_CLUSTER_NODE_ID_USED`

#### Scenario: A new node at a member's address
- **WHEN** voter `2` has address `10.0.0.2:8421`
- **AND** the operator adds node `6` at `10.0.0.2:8421`
- **THEN** Hearth answers `409` with `HEARTH_CLUSTER_ADDRESS_IN_USE`

### Requirement: The leader is not removed
Hearth SHALL refuse to remove or replace the current leader. It SHALL answer `409` with `HEARTH_CLUSTER_TARGET_IS_LEADER`.

#### Scenario: The operator removes the leader
- **WHEN** the operator removes the node that is the leader
- **THEN** Hearth answers `409` with `HEARTH_CLUSTER_TARGET_IS_LEADER`
- **AND** the membership does not change

### Requirement: A dead voter is replaced in one joint change
`POST /admin/cluster/members/{node_id}/replace` SHALL move the voter set from the current voters to the current voters without `node_id` and with the new node, in one joint change. The new node SHALL already be a ready learner. The replaced node ID SHALL be retired.

#### Scenario: Replacing a dead voter
- **WHEN** a cluster has voters `1`, `2` and `3`, and `3` is dead
- **AND** node `4` is a ready learner
- **AND** the operator replaces `3` with `4`
- **THEN** the voters become `1`, `2` and `4`
- **AND** node ID `3` is retired

### Requirement: An interrupted change is finished
A node that becomes leader while the configuration is joint SHALL propose the newest voter set of that joint configuration. It SHALL NOT propose the older one.

#### Scenario: The leader dies between the two entries
- **WHEN** the joint entry of a replace has committed
- **AND** the leader dies before the final entry commits
- **THEN** the next leader commits the replace's new voter set

### Requirement: A removed node stops serving
A node that learns it is no longer a member SHALL stop voting and stop campaigning. Its `/readyz` SHALL answer `503` with `"cluster": "removed"`. It SHALL stay removed after a restart.

#### Scenario: A removed node is still running
- **WHEN** a running node is removed from the cluster
- **THEN** its `/readyz` answers `503` with `"cluster": "removed"`
- **AND** it starts no election, also after a restart

### Requirement: Peers check each other's identity
Each peer RPC SHALL carry the cluster's ID, the sender's node ID and the intended receiver's node ID. A node SHALL refuse an RPC meant for another node ID. A node SHALL refuse an RPC from another cluster. A node SHALL refuse an RPC from a node that is neither a member nor being added, and SHALL tell a retired node that it was removed. Each peer certificate SHALL name its node ID. A node SHALL refuse a peer whose certificate names a node ID other than the one it claims.

#### Scenario: A new node at a dead node's address
- **WHEN** voter `3` is dead and node `4` now listens at `3`'s address
- **AND** the leader sends an RPC meant for node `3`
- **THEN** node `4` refuses it
- **AND** node `4` writes nothing to its log

#### Scenario: A node from another cluster
- **WHEN** a node initialised its own cluster from a wiped data directory
- **AND** it sends a vote request to a member of the original cluster
- **THEN** the member refuses it
- **AND** the original cluster's term does not change

#### Scenario: A certificate for another node
- **WHEN** a peer presents a certificate that names node `2`
- **AND** its RPC claims to come from node `5`
- **THEN** the receiver refuses the RPC

#### Scenario: A refused RPC is no contact
- **WHEN** a follower refuses an `AppendEntries` because of its identity checks
- **THEN** the follower does not count that request as contact with a leader (`cluster-consistency` R2)

### Requirement: `cluster.peers` seeds the first membership only
After a cluster is initialised, a node SHALL take the membership and every peer address from its Raft state, never from `cluster.peers`. A node whose `cluster.peers` differs from the Raft membership SHALL log a warning naming both sets. `/admin/cluster/status` and `GET /admin/cluster/members` SHALL report `peers_drift: true` on that node. A node SHALL start whether or not its `cluster.peers` is current.

#### Scenario: A node restarts after a replace
- **WHEN** voter `3` was replaced by node `4`
- **AND** node `1` restarts with a `cluster.peers` that still names `3`
- **THEN** node `1` starts and rejoins with voters `1`, `2` and `4`
- **AND** node `1` reports `peers_drift: true`
