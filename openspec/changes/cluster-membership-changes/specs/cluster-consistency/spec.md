## ADDED Requirements

### Requirement: W6 Acknowledged writes survive a membership change
A membership change SHALL NOT lose an acknowledged write. After a node is added, promoted, removed or replaced, every voter SHALL show every write acknowledged before the change and during it. This SHALL hold when the leader changes, a partition happens or a node is killed with `kill -9` during the change.

#### Scenario: A voter is replaced under load
- **WHEN** clients write to a 3-voter cluster while a dead voter is replaced by a new node
- **THEN** after the cluster converges, every voter, the new one included, shows every acknowledged write

#### Scenario: The leader is killed during a change
- **WHEN** the leader is killed with `kill -9` while a promote is in its joint phase
- **THEN** after the cluster converges, every voter shows every write acknowledged before the kill
