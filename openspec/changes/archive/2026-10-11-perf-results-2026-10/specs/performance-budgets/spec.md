## MODIFIED Requirements

### Requirement: Durable session creation throughput
The durable session creation target SHALL be more than 30,000 sessions/s in aggregate at T=256 concurrent writers, with fsync-before-ack. The target is ungraded: no gate enforces it, and no reproducible measurement of it exists. [`PUBLISHED_FIGURES.md` §2.1](https://github.com/hearth-auth/hearth/blob/3981837a75422969959d23b4324c81a61e0efc2f/docs/perf/PUBLISHED_FIGURES.md) (removed from the tree on 2026-10-10) retracts the earlier peak figures. Session creation is a write, so it has no cold-path budget.

#### Scenario: Session creation under 256 writers
- **WHEN** 256 concurrent writers create sessions, and each create is acknowledged only after its WAL `fsync`
- **THEN** the target is an aggregate rate above 30,000 sessions/s
