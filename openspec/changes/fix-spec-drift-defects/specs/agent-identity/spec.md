## MODIFIED Requirements

### Requirement: Agent Cards
An Agent Card MUST be served at `/.well-known/agent.json?agent_id={agent_id}`. A request without `agent_id` SHALL be refused with `400`, and an `agent_id` that names no agent of the caller's realm SHALL answer `404`. The endpoint SHALL require a bearer token with the `hearth.agents.admin` permission. Hearth SHOULD serve an Agent Card for each registered agent, so other agents can discover it per the A2A protocol. The card MUST include `name`, `description`, `url` (the agent endpoint), `authentication` (the supported schemes) and `capabilities` (the skill list). The card MUST NOT expose internal implementation details, credential material, or the agent's full permission set. The card SHOULD include a `version` field for cache busting.

#### Scenario: Fetch a card
- **WHEN** a caller with `hearth.agents.admin` requests `/.well-known/agent.json?agent_id={agent_id}` for an existing agent
- **THEN** the card carries the agent's name, description, authentication schemes, capabilities and a `version`

#### Scenario: No agent named
- **WHEN** a caller requests `/.well-known/agent.json` without `agent_id`
- **THEN** the response is `400`

#### Scenario: The card hides secrets
- **WHEN** a card is served for an agent with API keys and role assignments
- **THEN** it contains no credential hash and no permission list

#### Scenario: An unknown agent
- **WHEN** a caller requests the card for an `agent_id` that names no agent
- **THEN** the response is `404`

#### Scenario: Regression — the card has no endpoint URL
- **WHEN** a caller fetches the Agent Card of an existing agent
- **THEN** the card's `url` is the agent's endpoint URL, not an empty string

### Requirement: Agent audit events carry the delegation context
Every audit event for an agent action MUST include these fields.

| Field | Type | Meaning |
|---|---|---|
| `actor` | String | The immediate actor, for example `agent:A`. |
| `on_behalf_of` | String, optional | The delegating principal, for example `user:U`. |
| `delegation_chain` | Array of strings | The full chain, for example `["user:U", "agent:A", "agent:B"]`. |
| `tool` | String, optional | The tool invoked, if any. |
| `approval_id` | String, optional | The approval request that authorized the action, if any. |
| `token_jti` | String | The `jti` of the token used for the action. |
| `dpop_jkt` | String, optional | The DPoP key thumbprint, if the token was sender-constrained. |

#### Scenario: A DPoP-bound exchange is audited
- **WHEN** a token exchange issues a DPoP-bound delegated token
- **THEN** the `AgentDelegation` event records `actor`, `on_behalf_of`, `token_jti` and `dpop_jkt`

#### Scenario: Regression — the delegation event lacks the chain
- **WHEN** a token exchange issues a token from a subject token whose `act` chain already names actor A
- **THEN** the `AgentDelegation` event's `delegation_chain` lists user U, actor A and the new actor, in order

#### Scenario: Regression — an allowed tool invocation has no context
- **WHEN** `POST /v1/tools/invoke` allows an invocation
- **THEN** the `AgentToolInvocation` event carries `actor`, `tool` and `token_jti`, and `dpop_jkt` when the token is DPoP-bound
