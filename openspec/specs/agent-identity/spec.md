# agent-identity Specification

## Purpose
The agent entity: registration, credentials, lifecycle, the agent card, and agent audit events.
## Requirements
### Requirement: An agent is its own entity type
Hearth SHALL model an agent as an entity type separate from users and from OAuth clients. An agent SHALL have its own identity lifecycle, credential set, capability declarations and audit trail. Every agent MUST belong to exactly one realm.

#### Scenario: An agent is created
- **WHEN** an operator creates an agent in a realm
- **THEN** the agent has its own `agt_`-prefixed identifier
- **AND** it is not listed as a user or as an OAuth client

### Requirement: The agent record
An agent record MUST contain the fields below, with these limits.

| Field | Type | Rule |
|---|---|---|
| `agent_id` | `AgentId` (UUID, prefix `agt_`) | Unique identifier. |
| `realm_id` | `RealmId` | Owning realm. |
| `owner_id` | `UserId` or `OrganizationId` | The human or organization that registered the agent. |
| `display_name` | String | 1–256 characters. |
| `description` | String, optional | At most 2048 characters. |
| `capabilities` | List of capability strings | Declared capabilities. |
| `status` | `Active`, `Suspended` or `Revoked` | Lifecycle state. |
| `max_delegation_depth` | Integer | 1–10. Default `1`. The maximum number of hops this agent may delegate further. |
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
- **WHEN** an agent is created with `max_delegation_depth` of `0` or `11`
- **THEN** the request is refused

#### Scenario: The delegation depth is omitted
- **WHEN** an agent is created without `max_delegation_depth`
- **THEN** the agent's `max_delegation_depth` is `1`

### Requirement: An agent's owner exists in the same realm
An agent's `owner_id` MUST reference an existing user or organization in the same realm. Deleting the owning user or organization SHALL delete the agents it owns, so no agent is left without an owner.

#### Scenario: The owner does not exist
- **WHEN** an agent is created with an `owner_id` that names no user in the realm
- **THEN** the request is refused

#### Scenario: The owning user is deleted
- **WHEN** a user who owns agents is deleted
- **THEN** the agents that user owns are deleted too

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

### Requirement: A non-active agent takes no part in issuing tokens
Any agent status other than `Active` MUST block the agent from every token-issuing path. The paths are: AAT issuance, derivation and validation; approval-request creation and approval; transaction tokens; and capability-token validation. `Suspended` MUST block exactly as `Revoked` does, because the abuse monitor applies `Suspended` automatically.

#### Scenario: A suspended agent's AAT
- **WHEN** an AAT is presented for an agent that has been suspended since the AAT was issued
- **THEN** validation fails

#### Scenario: A revoked agent asks for a transaction token
- **WHEN** a revoked agent is the requesting or the target agent of a transaction token
- **THEN** no token is issued

#### Scenario: A suspended agent asks for approval
- **WHEN** an approval request is created for a suspended agent
- **THEN** the request is refused

### Requirement: Deleting an agent cascades
Agent deletion MUST revoke all active tokens of the agent, remove every RBAC role assignment whose subject is the agent, remove the agent from every group, delete every credential of the agent, and emit an audit event. The cascade MUST remove the primary agent record last. The cascade MUST propagate the failure of every step. A partial delete SHALL therefore leave the agent resolvable and the delete retryable.

Token revocation is satisfied by subject resolution, not by enumeration. AAT validation, approval-request approval, transaction-token issuance and capability-token validation SHALL each resolve the agent and refuse a subject that is not an `Active` agent of the realm. A deleted agent's outstanding tokens therefore stop being honoured at their next use. Capability-token validation SHALL resolve the agent before it burns the single-use `jti`, so a token refused this way does not spend its one-shot slot.

#### Scenario: Credentials and grants go with the agent
- **WHEN** an agent with API keys and role assignments is deleted
- **THEN** none of its credentials verify, and it has no role assignments or group memberships

#### Scenario: A capability token outlives its agent
- **WHEN** an unspent capability token is presented after its agent is deleted, suspended or revoked
- **THEN** it is refused
- **AND** its `jti` is not recorded as spent

#### Scenario: A step of the cascade fails
- **WHEN** the RBAC purge fails during an agent delete
- **THEN** the delete reports failure
- **AND** the agent record still resolves, and a second delete can complete the cascade

### Requirement: The agent management API
The protocol layer MUST expose these endpoints for agents.

| Operation | Method | Path |
|---|---|---|
| Create | POST | `/v1/agents` |
| Get | GET | `/v1/agents/{agent_id}` |
| List | GET | `/v1/agents` |
| Update | PATCH | `/v1/agents/{agent_id}` |
| Delete | DELETE | `/v1/agents/{agent_id}` |
| Suspend | POST | `/v1/agents/{agent_id}/suspend` |
| Reactivate | POST | `/v1/agents/{agent_id}/reactivate` |
| Revoke | POST | `/v1/agents/{agent_id}/revoke` |

Every endpoint in the table MUST require the `hearth.agents.admin` permission. The create body SHALL name the owner with `owner_type` (`user` or `organization`) and `owner_id` (a UUID); both are required, and the owner is never taken from the caller. An unknown `owner_type` or a malformed `owner_id` SHALL be refused with `400`. The list endpoint MUST support filtering by `owner_id`, `status` and capability. List pagination MUST follow the cursor pattern of the other list endpoints. Creation SHALL be refused once the realm's `max_agents` quota is reached.

#### Scenario: Create an agent
- **WHEN** a caller with `hearth.agents.admin` posts a valid body with `owner_type` and `owner_id` to `/v1/agents`
- **THEN** the response is `201` with the agent record

#### Scenario: The owner is missing
- **WHEN** a create body leaves out `owner_type` or `owner_id`
- **THEN** the request is refused, and no agent is created

#### Scenario: A caller without the permission
- **WHEN** a caller whose token lacks `hearth.agents.admin` calls any agent endpoint
- **THEN** the request is refused

#### Scenario: List by status
- **WHEN** a caller lists `/v1/agents?status=suspended`
- **THEN** only suspended agents are returned, with a `next_cursor` when more remain

#### Scenario: The realm quota is reached
- **WHEN** an agent is created in a realm that already holds `max_agents` agents
- **THEN** the request is refused

### Requirement: The status-transition endpoints
The suspend, reactivate and revoke endpoints MUST expose the status transitions to operators. They take no request body. Each MUST return the updated agent record. Reactivating a revoked agent MUST be refused with `403`. Revoking an already-revoked agent MUST be idempotent and answer `200`. Each transition MUST emit its audit event: `agent_suspended`, `agent_reactivated` or `agent_revoked`. `agent_revoked` carries the `FailOperation` failure policy: a revocation that cannot be recorded MUST fail the request rather than succeed silently.

#### Scenario: Revoke twice
- **WHEN** an operator revokes an agent that is already revoked
- **THEN** the response is `200` with the agent record

#### Scenario: Reactivate a revoked agent
- **WHEN** an operator posts to `/v1/agents/{agent_id}/reactivate` for a revoked agent
- **THEN** the response is `403`

#### Scenario: The revocation cannot be audited
- **WHEN** the `agent_revoked` audit event cannot be written
- **THEN** the revoke request fails

### Requirement: Capabilities are informational
Agent capabilities SHALL be informational metadata. They SHALL NOT grant anything; RBAC permission grants do the enforcing. Capability strings SHOULD align with the tool names registered in the realm's tool registry. An agent MAY declare zero capabilities; such an agent is governed entirely by its RBAC grants.

#### Scenario: No capabilities
- **WHEN** an agent is created with an empty capability list
- **THEN** the agent is created

#### Scenario: A capability grants nothing
- **WHEN** an agent declares `urn:hearth:capability:email:send` but holds no `tool.send_email.*` permission
- **THEN** the declaration gives it no right to invoke `send_email`

### Requirement: Agent API keys
An agent API key MUST be generated with at least 256 bits of entropy. The key MUST be shown to the caller exactly once, at creation. Only its SHA-256 hash SHALL be stored; the plaintext is never stored. The protocol layer SHALL expose `POST /v1/agents/{agent_id}/credentials/keys` to issue a key (`201`, with the plaintext key), `GET /v1/agents/{agent_id}/credentials` to list credentials without secret material, and `DELETE /v1/agents/{agent_id}/credentials/{cred_id}` to revoke one (`204`). A revoked key MUST NOT verify again. An agent MAY hold several active credentials at once. Credential rotation MUST allow overlapping validity windows: add the new credential, then revoke the old one.

#### Scenario: Issue a key
- **WHEN** an operator issues an API key for an agent
- **THEN** the response carries a 64-hex-character plaintext key once
- **AND** the stored credential holds only its SHA-256 hash

#### Scenario: List credentials
- **WHEN** an operator lists an agent's credentials
- **THEN** every credential is listed with its revocation state, and no key or hash appears

#### Scenario: A wrong or revoked key
- **WHEN** a wrong key, or a key that has been revoked, is verified
- **THEN** verification fails

#### Scenario: Rotation with overlap
- **WHEN** an agent has an old API key, an operator issues a new key, and later revokes the old one
- **THEN** both keys verify until the revocation
- **AND** only the new key verifies after it

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

### Requirement: Agent features are switched on by capability flags
The agent routes SHALL be mounted only when their `agent_auth.capabilities` flag is `true`. All three flags default to `false`.

| Flag | Routes |
|---|---|
| `agent_auth.capabilities.identity` | `/v1/agents/*`, `/.well-known/agent.json` |
| `agent_auth.capabilities.approval` | `/v1/approval-requests/*`, `/v1/tools/invoke` |
| `agent_auth.capabilities.advanced` | `/v1/aats/*`, `/v1/transaction-tokens/*`, `/v1/spiffe-mappings/*`, `/v1/cross-realm-policies/*` |

#### Scenario: The identity flag is off
- **WHEN** Hearth runs with `agent_auth.capabilities.identity: false`
- **THEN** `/v1/agents` is not routed

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

### Requirement: Agent audit actions
The audit action set MUST include these agent actions.

| Action | Trigger |
|---|---|
| `AgentCreated` | Agent registered. |
| `AgentUpdated` | Agent metadata modified. |
| `AgentSuspended` | Agent suspended. |
| `AgentRevoked` | Agent permanently revoked. |
| `AgentDeleted` | Agent deleted (cascade). |
| `AgentDelegation` | Token issued through OBO or token exchange for an agent. |
| `AgentToolInvocation` | Agent invoked a tool. |
| `ApprovalRequested` | Agent requested human approval. |
| `ApprovalGranted` | Human approved an agent action. |
| `ApprovalDenied` | Human denied an agent action. |
| `AgentTokenRevoked` | Agent token revoked, manually or by a CAEP signal. |
| `CrossRealmTrustCreated` | Cross-realm trust policy created. |
| `CrossRealmTrustRevoked` | Cross-realm trust policy revoked. |

#### Scenario: An agent is created
- **WHEN** an operator creates an agent
- **THEN** an `AgentCreated` event is recorded for it

#### Scenario: A delegation token is revoked
- **WHEN** a user revokes a delegation
- **THEN** an `AgentTokenRevoked` event is recorded

### Requirement: Rate anomalies suspend the agent
When Hearth suspends an agent because of its request rate, the agent SHALL enter the `Suspended` status, so every token-issuing path refuses it.

#### Scenario: An agent exceeds its threshold
- **WHEN** an agent exceeds its rate threshold and Hearth suspends it
- **THEN** its status is `Suspended`
- **AND** its next AAT validation or approval request is refused

