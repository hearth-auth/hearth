## ADDED Requirements

### Requirement: R2 Bounded staleness
A node SHALL serve a read only while it is in contact. A node that is not in contact SHALL answer the read with `503` and `HEARTH_CLUSTER_UNAVAILABLE`. A read that a node in contact serves SHALL show every write acknowledged more than `read_lag_threshold_ms` before the read began. A leader SHALL count as in contact only while a quorum of voters acknowledged it within `read_lag_threshold_ms`. `hearth config validate` SHALL refuse a `cluster.read_lag_threshold_ms` below `2 ×` the Raft heartbeat interval.

#### Scenario: A follower is cut off from the leader
- **WHEN** a follower has not heard from the leader for longer than `read_lag_threshold_ms`
- **THEN** every read on that follower answers `503` with `HEARTH_CLUSTER_UNAVAILABLE`

#### Scenario: A leader loses its quorum
- **WHEN** a leader has had no quorum acknowledgement for longer than `read_lag_threshold_ms`
- **THEN** every read on that leader answers `503` with `HEARTH_CLUSTER_UNAVAILABLE`

#### Scenario: A follower in contact
- **WHEN** a write is acknowledged on the leader
- **AND** a read begins on a follower in contact more than `read_lag_threshold_ms` later
- **THEN** the read shows the write

#### Scenario: A threshold below the heartbeat floor
- **WHEN** `cluster.read_lag_threshold_ms` is less than `2 ×` the heartbeat interval
- **THEN** `hearth config validate` exits with `1` and names `cluster.read_lag_threshold_ms`

### Requirement: R3 Monotonic reads on one node
Two reads on the same node SHALL NOT go backwards in log order. A read that begins after another read on the same node completed SHALL show the same state or a later one. This SHALL hold while the node installs a snapshot.

#### Scenario: Reads during a snapshot install
- **WHEN** a node installs a snapshot while a client reads one record on it in a loop
- **THEN** no read returns an older value than a read on that node that completed before it began

### Requirement: R4 No partial state
No read SHALL observe a partly installed snapshot. From the start of a snapshot install until the install and the rebuild of node-local caches finish, the node SHALL answer reads with `503` and `HEARTH_CLUSTER_UNAVAILABLE`. This SHALL hold for any value of `read_lag_threshold_ms`.

#### Scenario: A read arrives mid-install
- **WHEN** a read arrives on a node while it installs a snapshot
- **THEN** the node answers `503` with `HEARTH_CLUSTER_UNAVAILABLE`
- **AND** the node never answers that a record that exists before and after the install is missing

#### Scenario: A credential checked mid-install
- **WHEN** a valid admin token is presented to a node while it installs a snapshot
- **THEN** the node answers `503`, never `401` or `403`

### Requirement: V2 A node out of contact accepts no credential
A node that is not in contact SHALL NOT accept a session, an access token or a refresh token. It SHALL answer `503` with `HEARTH_CLUSTER_UNAVAILABLE` instead. This SHALL apply to token validation served from in-memory caches, too. A node SHALL NOT accept a credential while it installs a snapshot.

#### Scenario: A session revoked while a node is cut off
- **WHEN** a node is cut off from the cluster
- **AND** the rest of the cluster revokes a session
- **THEN** the cut-off node answers `503` to that session after `read_lag_threshold_ms`
- **AND** it never accepts the session again before it learns of the revocation

#### Scenario: Single-node mode
- **WHEN** `hearth.yaml` has no `cluster:` section
- **THEN** token validation never answers `503` for lack of contact
