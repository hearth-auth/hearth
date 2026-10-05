# delegated-authorization Specification

## Purpose
Token exchange (RFC 8693), scope attenuation across delegation, agent authority tokens (AATs), and the delegation chain.
## Requirements
### Requirement: A delegated token names both principals
A token issued by token exchange MUST encode both the delegating principal and the acting principal. Its `sub` SHALL be the subject token's `sub`. The token MUST carry the `act` (actor) claim of RFC 8693 §4.1. The `act` claim MUST be a JSON object that contains at least `sub`, the acting principal. The `act` claim MAY be nested for multi-hop delegation chains.

#### Scenario: One hop
- **WHEN** a client exchanges user U's access token
- **THEN** the issued token's `sub` is user U's
- **AND** it carries an `act` object with a `sub`

### Requirement: The actor token is the client's own access token
An `actor_token` SHALL be an access token that Hearth issued in the same realm to the exchanging client. A token exchange MAY carry one. When it does:

- its signature SHALL verify with the realm's signing key;
- it SHALL be an access token; a refresh token SHALL be refused;
- it SHALL NOT be expired;
- its `sub` SHALL be the authenticated client's own subject (`client_<uuid>`), so a client can present only its own token;
- it SHALL carry a `jti`, and each actor-token `jti` SHALL be accepted once.

Every failure SHALL be refused with `400 invalid_grant`.

#### Scenario: A reused actor token
- **WHEN** a client presents the same `actor_token` in two token exchanges
- **THEN** the second exchange is refused with `invalid_grant`

#### Scenario: Another client's token
- **WHEN** client A presents, as `actor_token`, an access token issued to client B
- **THEN** the exchange is refused with `invalid_grant`

#### Scenario: A refresh token as actor
- **WHEN** a client presents a refresh token as `actor_token`
- **THEN** the exchange is refused with `invalid_grant`

### Requirement: The token exchange grant
Hearth MUST implement the RFC 8693 token exchange grant, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. The `subject_token` MUST be the user's access token, which proves the user's identity and granted scopes. The `subject_token_type` MUST be `urn:ietf:params:oauth:token-type:access_token`. When an `actor_token` is sent, the `actor_token_type` MUST be `urn:ietf:params:oauth:token-type:jwt`. The resulting token MUST carry the `act` claim that records the delegation. The resulting token's lifetime MUST NOT exceed the subject token's remaining lifetime.

#### Scenario: A wrong subject token type
- **WHEN** an exchange sends `subject_token_type=urn:ietf:params:oauth:token-type:refresh_token`
- **THEN** the exchange is refused with `invalid_request`

#### Scenario: An expired subject token
- **WHEN** an exchange presents an expired `subject_token`
- **THEN** the exchange is refused with `invalid_grant`

#### Scenario: The lifetime is bounded
- **WHEN** an exchange presents a subject token with 60 seconds left
- **THEN** the issued token expires within 60 seconds

#### Scenario: Only the JWT actor token type is accepted
- **WHEN** an exchange sends an `actor_token` with `actor_token_type=urn:ietf:params:oauth:token-type:access_token`, or with no `actor_token_type`
- **THEN** the exchange is refused with `invalid_request`

### Requirement: Token exchange authenticates the client
Both token endpoints, `POST /token` (realm from the `X-Realm-ID` header) and `POST /realms/{realm}/token` (realm from the path), MUST require the caller to authenticate as a registered client before the exchange is processed. The caller MAY authenticate with HTTP Basic (`Authorization: Basic base64(client_id:client_secret)`), with `client_id` and `client_secret` in the form body, or with a `client_assertion`. A request with no client credentials, or with credentials that match no registered client, MUST be refused with `401 invalid_client`.

#### Scenario: No client credentials
- **WHEN** a token-exchange request carries no client credentials
- **THEN** the response is `401` with `invalid_client`

#### Scenario: A wrong client secret
- **WHEN** a token-exchange request carries a wrong `client_secret`
- **THEN** the response is `401`

#### Scenario: The path-realm endpoint
- **WHEN** a token-exchange request to `POST /realms/{realm}/token` carries no client credentials
- **THEN** the response is `401`

#### Scenario: HTTP Basic
- **WHEN** a confidential client posts a token exchange with HTTP Basic credentials
- **THEN** the client is authenticated, and the exchange is processed

### Requirement: Delegated scope is an intersection
The scope of a token issued by token exchange MUST be the intersection of three sets:

- the subject token's scope (what the user granted);
- the actor's ceiling: the `actor_token`'s `scope` claim; when the `actor_token` has no `scope` claim, or no `actor_token` is sent, the subject token's scope;
- the requested `scope`, when one is given.

An `actor_token` whose `scope` claim is empty SHALL allow nothing. If the intersection is empty, the request MUST be refused with `invalid_scope`. The check MUST run at token issuance, not at resource access, so a bad request fails fast. Resource servers SHOULD also check scopes at access time, for defense in depth.

#### Scenario: The request narrows the scope
- **WHEN** the subject token holds `mcp:tools:invoke mcp:tools:list`, the actor token holds both, and the request asks for `mcp:tools:invoke`
- **THEN** the issued token's scope is `mcp:tools:invoke`

#### Scenario: The actor's ceiling narrows the scope
- **WHEN** the subject token holds `mcp:tools:invoke email` and the actor token's `scope` is `mcp:tools:invoke`
- **THEN** the issued token's scope is `mcp:tools:invoke`

#### Scenario: An actor token with an empty scope
- **WHEN** the actor token's `scope` claim is the empty string
- **THEN** the request is refused with `invalid_scope`

#### Scenario: Nothing is left
- **WHEN** the three sets have no scope in common
- **THEN** the request is refused with `invalid_scope`

### Requirement: Delegation chains nest the `act` claim
Hearth MUST support multi-hop delegation, where a delegated token is exchanged again. Each exchange SHALL add one `act` level: the new `act.sub` is the new actor, and the subject token's `act` claim moves inside it. The outermost `act.sub` SHALL be the immediate actor. The inner `act` claims SHALL record the delegation history.

```
{
  "sub": "{user U}",
  "act": {
    "sub": "{actor B}",
    "act": { "sub": "{actor A}" }
  }
}
```

#### Scenario: Two hops
- **WHEN** actor A's delegated token for user U is exchanged again by actor B
- **THEN** the result has `sub` user U, `act.sub` actor B, and `act.act.sub` actor A

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

### Requirement: Every delegation is audited with its chain
Hearth MUST record the delegation chain in the audit log for every token issued through OBO or token exchange. The event SHALL be `AgentDelegation`.

#### Scenario: An exchange is audited
- **WHEN** a client exchanges user U's access token
- **THEN** an `AgentDelegation` event names the actor, user U as `on_behalf_of`, and the issued token's `jti`

### Requirement: Each delegation is recorded
Each token exchange SHALL store a delegation record that names the user, the actor, the granted scope, the time of issuance, and an expiry equal to the issued token's `exp`.

#### Scenario: A delegation record is stored
- **WHEN** a client exchanges user U's access token
- **THEN** user U's active delegations list the actor, the granted scope, the time and the expiry

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

### Requirement: Attenuating Authorization Tokens
An Attenuating Authorization Token (AAT) SHALL be a JWT that Hearth signs with the realm's key, with JOSE `typ` `aat+jwt`, and that can be narrowed but never widened. Hearth SHOULD support AATs per draft-niyikiza-oauth-attenuating-agent-tokens. A root AAT SHALL be issued through `POST /v1/aats` for an `Active` agent only, with a lifetime of at most 1 hour. An AAT SHALL carry these claims.

| Claim | Type | Meaning |
|---|---|---|
| `tools` | Array of tool permission objects | Allowed tool invocations, with argument constraints. |
| `aat_parent` | String (a `jti`) | The parent token this AAT was derived from. |
| `aat_chain` | Array of `jti` strings | The ordered token IDs of the attenuation chain. |

A tool permission object SHALL have these fields.

| Field | Type | Meaning |
|---|---|---|
| `tool` | String (tool URI) | The tool the permission applies to. |
| `actions` | Array of strings | Allowed actions, for example `invoke`, `list`, `describe`. |
| `constraints` | Object, optional | Argument-level constraints, for example `{"max_results": 100}`. |

#### Scenario: A derived AAT records its lineage
- **WHEN** a child AAT is derived from a root AAT
- **THEN** the child's `aat_parent` is the root's `jti`
- **AND** its `aat_chain` lists the root's `jti` and then its own

#### Scenario: A long root lifetime
- **WHEN** a root AAT is requested with a lifetime of 2 hours
- **THEN** the issued AAT expires no later than 1 hour after issuance

### Requirement: An AAT derivation only narrows
A child AAT MUST NOT add tools, widen constraints, extend its lifetime or add scopes. Hearth SHALL derive a child only on request, through `POST /v1/aats/derive`, which requires the `hearth.agents.admin` permission; Hearth signs the child with the realm's key. The child MUST have the same or fewer `tools` entries than the parent, and the same or fewer actions per tool. The child MUST have the same or narrower `constraints` for each tool. The child MUST have the same or a shorter lifetime (`exp`). The child MUST have the same or fewer scopes. A derivation SHALL be refused when the parent's `aat_chain` already holds 5 entries.

#### Scenario: A child adds a tool
- **WHEN** a child AAT lists a tool its parent does not list
- **THEN** the child is refused

#### Scenario: A child loosens a numeric constraint
- **WHEN** the parent allows `{"max_results": 100}` and the child claims `{"max_results": 500}`
- **THEN** the child is refused

#### Scenario: A child adds a scope
- **WHEN** a child AAT lists a scope its parent does not hold
- **THEN** the child is refused

#### Scenario: A child outlives its parent
- **WHEN** a child AAT asks for a lifetime beyond its parent's `exp`
- **THEN** the child's `exp` is no later than the parent's

#### Scenario: The chain is full
- **WHEN** a derivation is requested from an AAT whose `aat_chain` holds 5 entries
- **THEN** the derivation is refused

#### Scenario: A child AAT keeps every parent constraint
- **WHEN** the parent constrains `search_files` with `{"max_results": 100, "folder": "inbox"}`, and a child lists `search_files` with no constraints, or with only `{"max_results": 50}`
- **THEN** the child is refused

### Requirement: An AAT is validated along its whole chain
Hearth MUST validate the full attenuation chain when an AAT is presented. Validation MUST verify that each `aat_parent` exists in the chain, that each child's permissions are a subset of its parent's, and that no link of the chain has been revoked. Revoking any token in the chain MUST invalidate all its descendants. Chain validation SHOULD be optimized for the common depth of 1–2.

#### Scenario: The root is revoked
- **WHEN** a root AAT is revoked and a child derived from it is presented
- **THEN** the child fails validation

#### Scenario: Validation checks every chain link
- **WHEN** an AAT signed with the realm key is presented whose `aat_chain` does not contain its `aat_parent`, or whose tools exceed its parent's
- **THEN** validation fails

### Requirement: Agent discovery
Hearth MUST expose an agent registry API: `GET /v1/agents?capability={uri}&status=active`. Agent Cards SHALL serve as the discovery document for individual agents.

#### Scenario: Find agents by capability
- **WHEN** a caller requests `GET /v1/agents?capability=urn:hearth:capability:email:send&status=active`
- **THEN** only active agents that declare that capability are returned

### Requirement: Cross-realm trust policies
A cross-realm trust policy MUST name a source realm, a target realm and the allowed capabilities. An administrator of the target realm SHALL create it with `POST /v1/cross-realm-policies`, list and read policies with `GET /v1/cross-realm-policies` and `GET /v1/cross-realm-policies/{id}`, and delete one with `DELETE /v1/cross-realm-policies/{id}`. A policy MAY carry an expiry; once the expiry passes, the policy permits nothing. Cross-realm trust policies MUST be auditable: creating a policy SHALL record `CrossRealmTrustCreated`, and deleting one SHALL record `CrossRealmTrustRevoked`.

#### Scenario: Create a policy
- **WHEN** a target-realm administrator creates a policy for a source realm with two capabilities and a 24-hour expiry
- **THEN** the policy records the source realm, the target realm, both capabilities and the expiry
- **AND** a `CrossRealmTrustCreated` event is recorded

#### Scenario: An expired policy
- **WHEN** a cross-realm request arrives after its policy's expiry
- **THEN** the policy does not permit it

### Requirement: Transaction tokens
A transaction token MUST be single-use, bound to one transaction ID. Hearth SHOULD support short-lived, non-replayable transaction tokens for single agent-to-agent transactions, per draft-oauth-transaction-tokens-for-agents. A transaction token MUST expire within 60 seconds. It MUST include `txn` (the transaction ID), `sub` (the requesting agent), `aud` (the target agent) and `act` (the delegation context, when acting for a user). Hearth MUST track the `txn` claim to prevent replay.

#### Scenario: A token is consumed twice
- **WHEN** a transaction token is consumed, and then consumed again
- **THEN** the second consumption is refused

#### Scenario: A transaction ID is reused
- **WHEN** a second transaction token is requested for a `txn` that already has one
- **THEN** the request is refused

#### Scenario: The lifetime
- **WHEN** a transaction token is issued
- **THEN** its `exp` is at most 60 seconds after its `iat`

