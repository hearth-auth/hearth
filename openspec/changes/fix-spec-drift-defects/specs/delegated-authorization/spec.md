## MODIFIED Requirements

### Requirement: Every delegation is audited with its chain
Hearth MUST record the delegation chain in the audit log for every token issued through OBO or token exchange. The event SHALL be `AgentDelegation`.

#### Scenario: An exchange is audited
- **WHEN** a client exchanges user U's access token
- **THEN** an `AgentDelegation` event names the actor, user U as `on_behalf_of`, and the issued token's `jti`

#### Scenario: Regression — the event lacks the chain
- **WHEN** a client exchanges a token whose `act` chain already names actor A, for user U
- **THEN** the `AgentDelegation` event records the full chain: user U, actor A, then the new actor

#### Scenario: Regression — a failed audit write still issues a token
- **WHEN** the `AgentDelegation` audit event cannot be written
- **THEN** no token is issued, and the exchange reports failure

