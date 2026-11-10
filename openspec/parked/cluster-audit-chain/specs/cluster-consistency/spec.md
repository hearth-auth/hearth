## ADDED Requirements

### Requirement: W7 The audit chain stays one linear chain
Each realm's audit hash chain SHALL stay one linear chain when any number of nodes append audit events at the same time. Every node SHALL hold the same chain after it has applied the same log. `POST /admin/audit/verify` SHALL answer `"ok": true` on every node after concurrent appends. This SHALL hold under any clock skew between nodes. An append that cannot join the chain SHALL be refused with `503` and `HEARTH_CLUSTER_UNAVAILABLE`, and SHALL write no event and none of the rows merged with it.

#### Scenario: Concurrent audited changes on different nodes
- **WHEN** admins make audited changes on five nodes at the same time
- **AND** every node has applied the last of those changes
- **THEN** `POST /admin/audit/verify` answers `"ok": true` on every node
- **AND** every node reports the same `event_count`

#### Scenario: A node's clock is behind
- **WHEN** one node's clock is an hour behind the others
- **AND** that node and another node append audit events in turn
- **THEN** the chain verifies on every node

#### Scenario: An append that keeps losing the race
- **WHEN** an append cannot join the chain within its retry bound
- **THEN** the request answers `503` with `HEARTH_CLUSTER_UNAVAILABLE`
- **AND** no node holds the event or the rows merged with it
- **AND** the chain still verifies on every node
