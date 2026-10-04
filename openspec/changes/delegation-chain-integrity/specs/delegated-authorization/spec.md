## MODIFIED Requirements

### Requirement: Every delegation hop attenuates
Delegation depth MUST be bounded. A token exchange that would make the `act` chain deeper than the configured act-chain ceiling (`security.max_act_chain_depth`, default `3`), the ceiling that token validation also applies, MUST be refused with `invalid_grant`. When the actor is a registered agent, the bound is the lower of the ceiling and the agent's `max_delegation_depth`. Each hop MUST attenuate scope: the resulting token's scope MUST be a subset of the parent token's scope. Scope can only narrow, never widen. Each hop MUST attenuate lifetime: the resulting token's expiry MUST NOT exceed the parent token's expiry.

#### Scenario: The depth ceiling is reached
- **WHEN** a client exchanges a subject token whose `act` chain is already as deep as the act-chain ceiling
- **THEN** the exchange is refused with `invalid_grant`

#### Scenario: A hop asks for more scope
- **WHEN** a hop requests a scope its parent token does not hold
- **THEN** the issued token does not hold that scope, or the request is refused with `invalid_scope` when nothing is left

#### Scenario: A hop cannot outlive its parent
- **WHEN** a hop exchanges a parent token that expires in 30 seconds
- **THEN** the issued token expires no later than the parent

### Requirement: Users can view and revoke agent delegations
A signed-in user MUST be able to view and revoke their active delegations. Hearth SHALL list them at `GET /ui/consent/delegations` and revoke one with `POST /ui/consent/delegations/{delegation_id}/revoke`. Revoking a delegation MUST immediately invalidate every token issued under it.

#### Scenario: A user lists delegations
- **WHEN** a signed-in user opens `/ui/consent/delegations`
- **THEN** every active delegation is listed with its actor, scopes and expiry

#### Scenario: A user revokes a delegation
- **WHEN** a user revokes a delegation
- **THEN** the access token issued under it fails validation and introspects `active: false` on its next use
- **AND** an `AgentTokenRevoked` event is recorded

#### Scenario: Revoking a delegation revokes onward exchanges
- **WHEN** a delegated token was exchanged onward before the user revokes its delegation
- **THEN** the onward token also fails validation and introspects `active: false`

### Requirement: An AAT is validated along its whole chain
Hearth MUST validate the full attenuation chain when an AAT is presented. Validation MUST verify that each `aat_parent` exists in the chain, that each child's permissions are a subset of its parent's, and that no link of the chain has been revoked. Revoking any token in the chain MUST invalidate all its descendants. Chain validation SHOULD be optimized for the common depth of 1–2.

#### Scenario: The root is revoked
- **WHEN** a root AAT is revoked and a child derived from it is presented
- **THEN** the child fails validation

#### Scenario: Validation checks every chain link
- **WHEN** an AAT signed with the realm key is presented whose `aat_chain` does not contain its `aat_parent`, or whose tools exceed its parent's
- **THEN** validation fails
