## ADDED Requirements

### Requirement: Intent claims bind a token to an operation
Intent-binding claims MUST NOT be used as the sole authorization mechanism. A token issued for an agent operation MAY carry intent-binding claims. They constrain a token to a specific operation or workflow, beyond what scope allows.

| Claim | Type | Meaning |
|---|---|---|
| `agent_intent` | String | The intended action, for example `"send quarterly report to finance team"`. |
| `agent_workflow_id` | String | The multi-step workflow this token belongs to. |
| `agent_step` | Integer | The current step in the workflow. |
| `agent_checksum` | String | SHA-256 hash of the agent's code or configuration at issuance. |
| `tool_binding` | Array of strings | The specific tools this token is valid for. Stricter than scope. |

Intent-binding claims are OPTIONAL defense in depth beyond scope and RBAC permission checks; they supplement permission and scope checks and never replace them. `agent_workflow_id` lets audit logs correlate related uses of tokens.

#### Scenario: An intent claim without a permission
- **WHEN** a token carries `tool_binding: ["send_email"]` but no permission that allows `send_email`
- **THEN** invocation of `send_email` is denied

#### Scenario: Workflow correlation
- **WHEN** two tokens carry the same `agent_workflow_id`
- **THEN** the audit events of their uses can be found by that workflow ID

### Requirement: Resource servers enforce `tool_binding`
When `tool_binding` is present, the resource server MUST reject a request for a tool that is not in the list, even if the scope would otherwise allow it. When `agent_checksum` is present, the runtime environment SHOULD verify that the agent's code integrity matches the recorded checksum.

#### Scenario: A tool outside the binding
- **WHEN** a token with `tool_binding: ["search_files"]` and scope `mcp:tools:invoke` is used to call `delete_file`
- **THEN** the resource server rejects the request

### Requirement: Agents redeem capability tokens
An agent that holds a capability token for its approved request SHALL be able to redeem it once, at `POST /v1/tools/invoke` with the `X-Capability-Token` header, for the approved tool and action.

#### Scenario: Invocation with an approved capability token
- **WHEN** the agent presents the capability token issued for its approved request
- **THEN** the invocation is authorized once

#### Scenario: The token is used twice
- **WHEN** the agent presents the same capability token a second time
- **THEN** it is refused

#### Scenario: Another caller tried first
- **WHEN** another caller presented the agent's capability token and was refused
- **THEN** the agent can still use it once

### Requirement: Hearth emits and consumes risk signals
Risk-signal delivery MUST be best-effort with at-least-once semantics, and consumers MUST handle duplicate signals idempotently. Hearth SHOULD emit and consume these risk signals for continuous access evaluation (CAEP).

| Signal | Source | Effect |
|---|---|---|
| Agent anomalous rate | Rate monitoring | Suspend the agent and revoke its tokens. |
| User session revoked | User action | Revoke all delegated agent tokens. |
| Agent owner deactivated | Admin action | Suspend all agents the owner owns. |
| Realm suspended | Admin action | Revoke all agent tokens of the realm. |
| DPoP key compromise reported | Agent or admin | Revoke tokens bound to the compromised key. |
| Cross-realm trust revoked | Admin action | Revoke all cross-realm agent tokens. |

Risk signals SHOULD be delivered through Hearth's audit event stream; subscribers filter for signal events and act. External consumers MAY receive signals through the Shared Signals Framework (SSF), by Server-Sent Events or webhook push.

#### Scenario: The agent's owner is deactivated
- **WHEN** an administrator deactivates the user who owns two agents
- **THEN** both agents become `Suspended`

#### Scenario: A signal is delivered twice
- **WHEN** a consumer receives the same signal twice
- **THEN** applying it the second time changes nothing

### Requirement: Risk signals revoke the tokens they affect
When a risk signal triggers revocation, all affected tokens MUST be invalidated within the signal propagation window. For a session-based token, the session SHALL be revoked, and the next validation fails at once. For a sessionless token, such as one from `client_credentials`, the `jti` SHALL be added to the revocation blocklist. For a DPoP-bound token, the key thumbprint SHALL be added to a blocklist, which invalidates every token bound to that key.

#### Scenario: A compromised DPoP key is reported
- **WHEN** an agent or an administrator reports a DPoP key as compromised
- **THEN** its thumbprint is blocklisted, and every token whose `cnf.jkt` is that thumbprint fails validation

#### Scenario: A sessionless token
- **WHEN** a signal revokes a `client_credentials` token
- **THEN** its `jti` is blocklisted, and the token fails validation

### Requirement: Risk-signal evaluation stays off the hot path
CAEP signal evaluation MUST NOT add latency to the hot path. Revocation SHALL be applied asynchronously, and the hot path SHALL check only the pre-computed revocation state. Signal evaluation SHOULD be configurable per realm, since some realms may not want aggressive automatic revocation.

#### Scenario: Validation after a signal
- **WHEN** a token is validated after a signal blocklisted it
- **THEN** validation reads the in-memory revocation state and does no signal processing

#### Scenario: A realm turns off automatic revocation
- **WHEN** a realm disables aggressive automatic revocation
- **THEN** a rate signal for one of its agents is recorded but revokes nothing
