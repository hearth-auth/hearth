## ADDED Requirements

### Requirement: Password-login goodput holds past saturation
In the live load-test `login` journey, the served rate at twice the sustained rate SHALL be at least 90% of the sustained rate. The sustained rate is the highest offered step that the journey serves with no errors. A shed request (`503` from the KDF admission gate) SHALL count as not served. No gate enforces this budget; it is graded from the journey's report.

#### Scenario: A node past saturation
- **WHEN** a node sustains 40 password logins per second with no errors
- **AND** the journey then offers 80 per second
- **THEN** the node serves at least 36 password logins per second

### Requirement: A login flood does not degrade other requests
While the live load-test `login` journey offers twice the sustained rate, a concurrent `refresh` journey at half its own sustained rate SHALL keep its p99 latency within twice its p99 without the flood. Its failure rate SHALL stay at or below 1%. Concurrent `introspect` and `userinfo` journeys SHALL meet the same two conditions. No gate enforces this budget; it is graded from the journeys' reports.

#### Scenario: Refresh during a login flood
- **WHEN** the `refresh` journey runs at half its sustained rate with a p99 of 20 ms and no flood
- **AND** a `login` flood at twice the login sustained rate starts on the same node
- **THEN** the `refresh` journey's p99 stays at or below 40 ms
- **AND** at most 1% of its requests fail
