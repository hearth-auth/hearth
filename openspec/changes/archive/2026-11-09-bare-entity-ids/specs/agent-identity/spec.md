## MODIFIED Requirements

### Requirement: An agent is its own entity type
Hearth SHALL model an agent as an entity type separate from users and from OAuth clients. An agent SHALL have its own identity lifecycle, credential set, capability declarations and audit trail. Every agent MUST belong to exactly one realm.

#### Scenario: An agent is created
- **WHEN** an operator creates an agent in a realm
- **THEN** the agent has its own identifier, a UUID, which the agent API returns bare
- **AND** a token whose subject is the agent carries `sub` = `agt_<uuid>`
- **AND** it is not listed as a user or as an OAuth client

### Requirement: The agent record
An agent record MUST contain the fields below, with these limits.

| Field | Type | Rule |
|---|---|---|
| `agent_id` | `AgentId` (UUID) | Unique identifier. The API returns it as a bare UUID, and accepts the `agt_` prefixed form too. As a token `sub` it is `agt_<uuid>`. |
| `realm_id` | `RealmId` | Owning realm. |
| `owner_id` | `UserId` or `OrganizationId` | The human or organization that registered the agent. |
| `display_name` | String | 1–256 characters. |
| `description` | String, optional | At most 2048 characters. |
| `capabilities` | List of capability strings | Declared capabilities. |
| `status` | `Active`, `Suspended` or `Revoked` | Lifecycle state. |
| `max_delegation_depth` | Integer | From `1` to the act-chain ceiling (`security.max_act_chain_depth`, default `3`). Default `1`. The maximum number of hops this agent may delegate further. If the ceiling is later lowered below a stored value, the lower of the two applies. |
| `created_at` | Timestamp (UTC microseconds) | Creation time. |
| `updated_at` | Timestamp (UTC microseconds) | Last modification. |

A create or update that breaks a limit SHALL be refused.

#### Scenario: An empty display name
- **WHEN** an agent is created with an empty `display_name`
- **THEN** the request is refused

#### Scenario: A display name of 257 characters
- **WHEN** an agent is created or updated with a `display_name` longer than 256 characters
- **THEN** the request is refused

#### Scenario: A delegation depth out of range
- **WHEN** the act-chain ceiling is the default `3` and an agent is created with `max_delegation_depth` of `0` or `4`
- **THEN** the request is refused

#### Scenario: The delegation depth is omitted
- **WHEN** an agent is created without `max_delegation_depth`
- **THEN** the agent's `max_delegation_depth` is `1`

#### Scenario: A lowered ceiling caps a stored depth
- **WHEN** an agent has `max_delegation_depth` `5` and the operator lowers `security.max_act_chain_depth` to `3`
- **THEN** a token exchange by that agent is limited to a chain of depth `3`
