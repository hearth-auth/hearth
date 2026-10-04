## ADDED Requirements

### Requirement: Agents hold tool permissions as principals
An agent SHALL be an RBAC principal like a user. A role assigned to an agent, or to a group the agent belongs to, SHALL appear in the `permissions` claim of the agent's own access token at issuance. An agent's ability to delegate to another agent SHALL be determined by its own permission claims being a superset of what it attempts to delegate.

#### Scenario: A role assigned to an agent
- **WHEN** an admin assigns the role `email.editor` (with `tool.send_email.invoke`) to an agent, and the agent obtains an access token
- **THEN** the agent's token carries `tool.send_email.invoke`
- **AND** the tool check allows the agent to invoke `send_email`

#### Scenario: An agent delegates more than it holds
- **WHEN** an agent without `tool.delete_email.invoke` delegates to another agent and asks for `tool.delete_email.invoke`
- **THEN** the delegated token does not carry `tool.delete_email.invoke`
