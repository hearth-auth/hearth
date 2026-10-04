## ADDED Requirements

### Requirement: Agents get DPoP-bound tokens by default
DPoP SHOULD be required for agents by default. A realm MAY make DPoP optional for agents, for backward compatibility. Where the requirement applies, an agent's token request without a valid `DPoP` proof SHALL be refused.

#### Scenario: An agent requests a token without a proof
- **WHEN** an agent in a realm with the default setting sends a token request without a `DPoP` header
- **THEN** the request is refused

#### Scenario: A realm makes DPoP optional for agents
- **WHEN** a realm has made DPoP optional for agents and an agent sends a token request without a `DPoP` header
- **THEN** the agent receives a `Bearer` token

### Requirement: Each delegation hop re-binds the token to the next agent's key
When a DPoP-bound delegated token passes from one agent to the next, each hop SHALL re-bind the token to the next agent's key. Agent A obtains a DPoP-bound token from the user's delegation, then performs a token exchange presenting its DPoP proof. Agent B provides its public key in the exchange request, and the resulting token SHALL be bound to agent B's key. The previous agent SHALL no longer be able to use the token.

#### Scenario: Agent A hands off to agent B
- **WHEN** agent A exchanges its DPoP-bound token with its own proof and agent B's public key
- **THEN** the resulting token's `cnf.jkt` is agent B's key thumbprint
- **AND** agent A cannot use the resulting token
