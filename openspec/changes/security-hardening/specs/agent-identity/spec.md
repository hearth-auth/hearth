## MODIFIED Requirements

### Requirement: Agent status transitions
Agent status transitions MUST be `Active → Suspended → Active` (reversible) and `Active|Suspended → Revoked` (terminal). A revoked agent MUST NOT authenticate and MUST NOT be re-activated. Every status transition, and every deletion, MUST be refused on a realm that is not `Active`.

#### Scenario: Suspend and reactivate
- **WHEN** an active agent is suspended and then reactivated
- **THEN** its status is `Suspended` after the first step and `Active` after the second

#### Scenario: Revocation is terminal
- **WHEN** an operator tries to reactivate a revoked agent
- **THEN** the request is refused, and the agent stays `Revoked`

#### Scenario: A transition in an archived realm
- **WHEN** an operator suspends, reactivates, revokes or deletes an agent in a realm that is not `Active`
- **THEN** the operation is refused

#### Scenario: A revoked agent's key does not verify
- **WHEN** an API key that was never revoked itself is verified after its agent is revoked
- **THEN** verification fails
