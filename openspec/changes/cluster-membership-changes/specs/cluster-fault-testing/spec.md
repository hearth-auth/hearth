## MODIFIED Requirements

### Requirement: The harness injects real faults
The harness SHALL be able to inject these faults: a network partition into a majority and a minority, a partition that isolates the current leader, `kill -9` of a minority of nodes, restart of a killed node from its data directory, added delay on the peer links, and membership changes. A membership change fault SHALL add a learner, promote a learner, remove a member, or replace a voter, through the admin API, on a cluster that has spare nodes outside its membership. A replacement node SHALL start on an empty data directory with a node ID that was never used. Each test SHALL name the faults it uses.

#### Scenario: A killed node restarts from disk
- **WHEN** the harness kills a node with `kill -9` and then restarts it
- **THEN** the node starts from its existing data directory, not from an empty one

#### Scenario: A voter is replaced
- **WHEN** the harness replaces a voter
- **THEN** it kills that voter, starts a spare node with a new node ID and `cluster.join_existing: true`, adds it, and replaces the voter with it through the admin API
- **AND** the history records each membership call and its outcome

### Requirement: Client answers map to Jepsen outcomes
The harness client SHALL record each operation's outcome by this mapping:

| Hearth answer | Write | Read |
|---|---|---|
| `2xx` | `:ok` | `:ok` |
| `503` with `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN` | `:info` | not applicable |
| `503` with `HEARTH_CLUSTER_MEMBERSHIP_OUTCOME_UNKNOWN` | `:info` | not applicable |
| `503` with `HEARTH_CLUSTER_UNAVAILABLE` | `:fail` | `:fail` |
| Timeout or connection error | `:info` | `:fail` |
| Any other error | `:fail` | `:fail` |

A membership call SHALL count as a write. The history SHALL keep the HTTP status and the Hearth error code of every failed or unknown operation.

#### Scenario: A write times out
- **WHEN** a write gets no answer before the client timeout
- **THEN** the history records it as `:info`
- **AND** the checker treats it as possibly applied

#### Scenario: An unavailable write is seen later
- **WHEN** a write recorded as `:fail` with `HEARTH_CLUSTER_UNAVAILABLE` is visible in a final read
- **THEN** the checker reports a W3 violation

## ADDED Requirements

### Requirement: The membership checker
A test that injects membership changes SHALL check the final membership. After the heal, every live member SHALL report the same voters and learners. That membership SHALL be one that the history's acknowledged and unknown membership calls can produce. No retired node ID SHALL be a voter. The cluster SHALL have at least `3` voters.

#### Scenario: A retired node is still a voter
- **WHEN** a history acknowledges the replacement of voter `3`
- **AND** a final membership read shows `3` as a voter
- **THEN** the membership checker reports a violation

#### Scenario: Nodes disagree on membership
- **WHEN** after the heal one live member reports voters `1`, `2`, `4` and another reports `1`, `2`, `3`
- **THEN** the membership checker reports a violation
