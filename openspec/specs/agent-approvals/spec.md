# agent-approvals Specification

## Purpose
Human-in-the-loop approval of agent actions: the approval lifecycle, approvers, capability tokens, and continuous access evaluation.
## Requirements
### Requirement: Approval-required permissions start a human-in-the-loop flow
Hearth MUST support step-up authorization in which a human approves before an agent may proceed. The `tool.{name}.invoke_with_approval` permission SHALL start the flow:

1. The caller's access token carries `tool.X.invoke_with_approval` but not `tool.X.invoke`.
2. The caller tries to invoke tool X. The runtime or SDK sees the approval-required permission and creates an approval request instead of failing.
3. The designated approvers are notified.
4. An approver grants or denies the request.
5. If granted, a time-boxed capability token is issued that carries `tool.X.invoke` for the approved invocation only.

At `POST /v1/tools/invoke`, an invocation that needs approval SHALL be refused unless the `X-Capability-Token` header carries a valid capability token for it.

#### Scenario: Invocation without approval
- **WHEN** a caller whose token carries `tool.delete_email.invoke_with_approval` and not `tool.delete_email.invoke` asks to invoke `delete_email` without an `X-Capability-Token` header
- **THEN** the invocation is refused as approval-required

#### Scenario: The direct grant wins over the approval grant
- **WHEN** a token carries both `tool.delete_email.invoke` and `tool.delete_email.invoke_with_approval`
- **THEN** the invocation is allowed without a capability token

### Requirement: The approval request
An approval request MUST contain these fields.

| Field | Type | Meaning |
|---|---|---|
| `request_id` | UUID | Unique identifier. |
| `agent_id` | `AgentId` | The requesting agent. |
| `tool` | String | The tool requested. |
| `action` | String | The specific action, for example `invoke`. |
| `context` | Object | Agent-provided context: why it needs this and what it will do. |
| `delegation_chain` | Array | The full delegation chain at the time of the request. |
| `requested_at` | Timestamp | When the request was made. |
| `expires_at` | Timestamp | When the request expires if nobody acts. Default: 1 hour after `requested_at`. |
| `status` | `Pending`, `Approved`, `Denied` or `Expired` | Current state. |

#### Scenario: Create a request
- **WHEN** a request is created for an agent and tool without an expiry
- **THEN** it has status `Pending` and `expires_at` one hour after `requested_at`

### Requirement: Approval policies are permissions
Realms MUST be able to configure approval policies per tool and per agent. Each policy SHALL be expressed as a permission in a role.

| Policy | Behavior | Expressed as |
|---|---|---|
| `auto_approve` | Invocation needs no human approval. | `tool.{name}.invoke` |
| `require_approval` | Invocation needs human approval. | `tool.{name}.invoke_with_approval` |
| `deny` | Invocation is never allowed, whatever is approved. | `tool.{name}.deny`, which takes precedence over `invoke` |

Policies SHOULD support risk-based configuration, so different tools get different policies by sensitivity.

#### Scenario: A denied tool cannot be approved into use
- **WHEN** a caller's token carries `tool.wire_funds.deny` and the caller presents a capability token for `wire_funds`
- **THEN** the invocation is denied

### Requirement: An approval issues a scoped capability token
An approved request MUST issue a capability token. Its TTL SHALL be configurable, with a default of 5 minutes and a maximum of 1 hour. The capability token MUST be scoped to the specific tool and action that were approved. It SHALL be single-use. Hearth SHALL check that the presenting caller is the agent it was minted for, and that the agent is still `Active`, before it records the token's `jti` as spent.

#### Scenario: The default TTL
- **WHEN** a request is approved without a TTL
- **THEN** the capability token expires 5 minutes after issuance

#### Scenario: A TTL above the maximum
- **WHEN** a request is approved with a TTL of 2 hours
- **THEN** the capability token expires no later than 1 hour after issuance

#### Scenario: The token is used for another tool
- **WHEN** a capability token approved for `delete_email` is presented to invoke `send_email`
- **THEN** it is refused

#### Scenario: Another caller presents the token
- **WHEN** a caller other than the agent it was minted for presents a capability token
- **THEN** it is refused
- **AND** its `jti` is not recorded as spent

### Requirement: An expired request counts as denied
An expired approval request MUST be treated as denied. To retry, the agent MUST create a new request.

#### Scenario: Approve after expiry
- **WHEN** an approver tries to approve a request after its `expires_at`
- **THEN** no capability token is issued

### Requirement: Approvers hold `hearth.agents.admin`
Creating, listing, reading, approving and denying approval requests SHALL require the `hearth.agents.admin` permission. The routes are `POST /v1/approval-requests`, `GET /v1/approval-requests` (with an optional `?status=` filter), `GET /v1/approval-requests/{id}`, `POST /v1/approval-requests/{id}/approve` and `POST /v1/approval-requests/{id}/deny`. No other permission SHALL make a principal an approver.

#### Scenario: An admin approves
- **WHEN** a caller with `hearth.agents.admin` approves a pending request
- **THEN** the request is `Approved`, and the response carries the capability token

#### Scenario: A caller without the permission
- **WHEN** a caller whose token lacks `hearth.agents.admin` tries to approve a request
- **THEN** the request is refused, and the approval request stays `Pending`

### Requirement: Approval status transitions are atomic
An approval request's status transition MUST be atomic, by compare-and-swap or a conditional write. Only `Pending → Approved` and `Pending → Denied` SHALL be legal.

#### Scenario: Two approvers race
- **WHEN** two approvers approve the same pending request at the same time
- **THEN** exactly one capability token is issued
- **AND** the other approval is refused as not pending

#### Scenario: Deny after approve
- **WHEN** an approver denies a request that is already `Approved`
- **THEN** the denial is refused, and the status stays `Approved`

### Requirement: Approval notifications
An approval webhook payload MUST include the request ID, the agent identity, the tool requested, the delegation chain, and a URL to approve or deny. Webhook endpoints MUST be configured per realm. Hearth SHOULD send a webhook notification when an approval request is created. Hearth SHOULD also notify through the admin UI, by polling or Server-Sent Events.

#### Scenario: A request is created in a realm with a webhook
- **WHEN** an approval request is created in a realm that configures `approval_webhook`
- **THEN** that realm's webhook receives a payload with the request ID, agent ID, tool, delegation chain, and approve and deny URLs

### Requirement: Signal-triggered actions are audited with their signal
Every action triggered by a risk signal MUST be recorded in the audit log, with the triggering signal as context.

#### Scenario: A signal-triggered action is recorded
- **WHEN** Hearth takes an action because of a risk signal
- **THEN** the action's audit event names that signal

