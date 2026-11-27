## ADDED Requirements

### Requirement: S1 A snapshot holds one point in time
A Raft snapshot that declares last log index N SHALL hold the effects of every entry up to N and of no entry after N. It SHALL hold this while the building node keeps applying entries.

#### Scenario: Entries apply during a build
- **WHEN** a node starts a snapshot build at applied index N
- **AND** the node applies entries N+1 to N+100 before the build ends
- **THEN** the snapshot holds the effects of entries up to N only

#### Scenario: A conditional write after the snapshot point
- **WHEN** entry N+1 is a `PutIfAbsent` that applies while a snapshot of index N is built
- **AND** a follower installs that snapshot and then applies entry N+1
- **THEN** the follower's response for entry N+1 matches the leader's

### Requirement: S2 Snapshot memory is bounded
Building, sending, receiving and installing a snapshot SHALL use memory that does not grow with the size of the store. On a store of 1,000,000 users, a build and an install SHALL each raise the node's anonymous resident memory by less than 512 MiB.

#### Scenario: A 1M-user snapshot
- **WHEN** a node builds a snapshot of a 1,000,000-user store
- **AND** another node installs it
- **THEN** neither node's anonymous resident memory rises by 512 MiB or more

### Requirement: S3 Snapshot files are encrypted at rest
A node SHALL keep snapshots as files under its data directory. Every snapshot file, including a partial one, SHALL be encrypted with a per-file key wrapped by the node's storage key-encryption key, as its SST and WAL files are. No snapshot file SHALL hold a key or value of the store in plaintext.

#### Scenario: A plaintext marker in the store
- **WHEN** a node builds a snapshot of a store that holds a value with a known marker string
- **THEN** no file under the data directory's snapshot directory contains that marker

### Requirement: S4 A received snapshot is checked before it changes the store
A node SHALL check a received snapshot end to end (every encrypted chunk, the record stream, the row and realm counts and the digest) before it deletes or writes any key of its store. A snapshot that fails the check SHALL leave the store unchanged, SHALL NOT stop the node's Raft core, and the leader SHALL be able to send it again.

#### Scenario: A corrupted transfer
- **WHEN** a byte of a snapshot changes between the leader and the receiving node
- **THEN** the receiving node refuses the snapshot
- **AND** its store holds the same keys and values as before the transfer
- **AND** a later transfer of the same snapshot installs

### Requirement: S5 A snapshot survives a restart
A node SHALL make a built or installed snapshot durable before it reports it: the file, its name and its directory SHALL be synced to disk. After a restart the node SHALL serve that snapshot without building a new one. A node SHALL NOT report a snapshot whose last log index is above its applied index. Partial snapshot files left by a crash SHALL be removed when the node starts.

#### Scenario: A restart after a build
- **WHEN** a node builds a snapshot and is then killed with `kill -9` and restarted
- **THEN** the node reports the same snapshot after the restart
- **AND** it does not build a snapshot at start-up

#### Scenario: A crash during a build
- **WHEN** a node is killed during a snapshot build
- **THEN** at the next start the partial file is gone
- **AND** the node reports the snapshot it had before the build, or none
