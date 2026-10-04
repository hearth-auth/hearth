## ADDED Requirements

### Requirement: Agent clients register dynamically
Dynamic Client Registration (RFC 7591) MUST support agent clients. A registration request MAY include `agent_id` to associate the OAuth client with a registered agent. When `agent_id` is given, the client MUST inherit the agent's authentication requirements, for example DPoP-required. An agent SHOULD use Dynamic Client Registration to register itself when it connects to a new Hearth instance.

#### Scenario: Register a client for a DPoP-required agent
- **WHEN** a client registers with the `agent_id` of an agent that requires DPoP
- **THEN** the new client requires DPoP-bound tokens

#### Scenario: An unknown agent
- **WHEN** a registration request names an `agent_id` that is not an agent of the realm
- **THEN** the registration is refused
