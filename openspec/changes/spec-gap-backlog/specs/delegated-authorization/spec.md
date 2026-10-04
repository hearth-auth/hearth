## ADDED Requirements

### Requirement: Agents request delegation with `requested_actor`
Hearth MUST implement the OAuth 2.0 On-Behalf-Of extension of draft-oauth-ai-agents-on-behalf-of-user-02. The authorization request MUST accept a `requested_actor` parameter that identifies the agent that will act for the user: `requested_actor=agent:{agent_id}`. The authorization server MUST verify that the referenced agent exists, is active, and may act for the requesting client's context. The consent screen MUST show which agent asks for delegated access and which scopes it asks for.

#### Scenario: A suspended agent is requested
- **WHEN** an authorization request carries `requested_actor=agent:{agent_id}` for a suspended agent
- **THEN** the request is refused

#### Scenario: The consent screen names the agent
- **WHEN** a user reaches consent for an authorization request with `requested_actor`
- **THEN** the screen shows the agent's name and the scopes it requests

### Requirement: Delegated tokens name the acting agent
When an agent acts on behalf of a user, the resulting token MUST encode both the user's identity and the agent's identity. The `act.sub` of the token MUST name the acting agent. In a multi-hop chain, each `act.sub` MUST name the agent of that hop.

```
{
  "sub": "user:U",
  "act": {
    "sub": "agent:B",
    "act": { "sub": "agent:A" }
  },
  "scope": "read:files send:email",
  "aud": "https://mcp.example.com"
}
```

#### Scenario: One agent hop
- **WHEN** agent A obtains a delegated token for user U
- **THEN** the token's `sub` names user U, and its `act.sub` names agent A

#### Scenario: Two agent hops
- **WHEN** agent A's delegated token for user U is exchanged again by agent B
- **THEN** the result has `act.sub` agent B and `act.act.sub` agent A

### Requirement: An agent's delegation depth bounds the chain
Delegation depth MUST be bounded by the acting agent's `max_delegation_depth`. A token exchange that would exceed this depth MUST be refused.

#### Scenario: The agent's depth limit is reached
- **WHEN** an agent with `max_delegation_depth: 1` exchanges a subject token that already carries one `act` hop
- **THEN** the exchange is refused with `invalid_grant`

### Requirement: Agent delegation needs the user's prior consent
Users MUST explicitly approve which agents may act on their behalf. A first-time delegation MUST require explicit user consent through the authorization flow. A consent record MUST store the user, the agent, the granted scopes, a timestamp and an expiry. Consent SHOULD support time-bounded grants, for example "allow for 24 hours".

#### Scenario: A first delegation without consent
- **WHEN** an agent asks for a delegated token for a user who has never consented to that agent
- **THEN** no token is issued until the user consents through the authorization flow

#### Scenario: A time-bounded consent
- **WHEN** a user consents to an agent for 24 hours
- **THEN** after 24 hours the agent cannot obtain a new delegated token without fresh consent

### Requirement: Users manage agent delegations through the API and the admin UI
Users MUST be able to view and revoke their active agent delegations through the API and through the admin UI, in addition to the self-service pages.

#### Scenario: List delegations through the API
- **WHEN** a user lists their agent delegations through the API
- **THEN** every active delegation is returned with its agent, scopes and expiry

#### Scenario: An administrator revokes a user's delegation
- **WHEN** an administrator revokes a user's agent delegation in the admin UI
- **THEN** every token issued under it fails validation

### Requirement: Agents are discoverable by tag and directory
When Hearth exposes a realm-level agent directory, it SHALL be served at `/.well-known/agents` and list the realm's public agents. Agents SHOULD be discoverable by capability, realm and tag.

#### Scenario: Find agents by tag
- **WHEN** a caller lists agents with a tag filter
- **THEN** only agents with that tag are returned

#### Scenario: The realm directory
- **WHEN** a client requests `/.well-known/agents` in a realm that exposes the directory
- **THEN** the response lists the realm's public agents and no private ones

### Requirement: Agent-to-agent tokens are bound to the target agent
A token that agent A presents to agent B MUST carry an `aud` that matches agent B's identifier or endpoint URL. Agent A SHALL obtain it from Hearth with a `resource` indicator or an `aud` for agent B, and present it with a DPoP proof. Agent B SHALL validate the token against Hearth's JWKS endpoint and verify the DPoP proof. If agent B requires mutual authentication, agent B also presents its identity to agent A, through a reciprocal token or mTLS. Agent-to-agent tokens SHOULD be short-lived, at most 5 minutes, to limit replay windows. mTLS MAY replace DPoP for agent-to-agent authentication, particularly in infrastructure contexts.

#### Scenario: A token for another agent
- **WHEN** agent A presents to agent B a token whose `aud` names agent C
- **THEN** agent B refuses it

### Requirement: Cross-realm trust policies expire and are visible to both realms
Every cross-realm trust policy MUST specify an expiry. A cross-realm trust policy SHALL be readable from both the source realm and the target realm.

#### Scenario: A policy without an expiry
- **WHEN** an administrator creates a cross-realm trust policy without an expiry
- **THEN** the request is refused

#### Scenario: The source realm looks up its policies
- **WHEN** an administrator of the source realm lists cross-realm policies
- **THEN** the policies that name the realm as source are listed

### Requirement: Cross-realm agent tokens name both realms
A token for a cross-realm interaction MUST carry both the issuing realm and the target realm in its claims. Agents from different realms MAY interact when cross-realm trust is configured. Cross-realm requests MUST be rate-limited independently from intra-realm requests.

#### Scenario: A cross-realm token
- **WHEN** an agent in realm A obtains a token to call an agent in realm B under a trust policy
- **THEN** the token's claims name realm A as the issuing realm and realm B as the target realm

#### Scenario: Cross-realm traffic hits its own limit
- **WHEN** cross-realm requests from realm A exceed the cross-realm limit
- **THEN** they are throttled, while realm B's intra-realm requests are not
