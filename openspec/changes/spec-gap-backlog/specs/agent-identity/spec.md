## ADDED Requirements

### Requirement: Agents authenticate with their own credentials
An agent MUST authenticate with one or more of these credential types.

| Credential type | What Hearth stores | Use |
|---|---|---|
| API key | The SHA-256 hash of the key; never the plaintext | Server-to-server integrations |
| Asymmetric key pair (Ed25519 or P-256) | The public key; the agent holds the private key | DPoP-bound tokens, JWT assertions |
| mTLS client certificate | The X.509 certificate chain and the CA fingerprint | Workload identity, SPIFFE SVIDs |

Asymmetric keys MUST use Ed25519 by default. P-256 (ES256) MAY be supported. An agent MAY have several active credentials of different types.

#### Scenario: An agent authenticates with its API key
- **WHEN** an agent presents a valid API key of its own
- **THEN** Hearth authenticates the request as that agent

#### Scenario: An agent registers a public key
- **WHEN** an operator registers an Ed25519 public key for an agent, and the agent signs a JWT assertion with the matching private key
- **THEN** Hearth authenticates the assertion as that agent

#### Scenario: A revoked agent presents a credential
- **WHEN** a revoked agent presents any of its credentials
- **THEN** authentication fails

### Requirement: Capability declarations use the Hearth URI form
Agent capabilities MUST be URIs of the form `urn:hearth:capability:{domain}:{action}`, for example `urn:hearth:capability:email:send` or `urn:hearth:capability:files:read`.

#### Scenario: A malformed capability
- **WHEN** an agent is created or updated with the capability `send-email`
- **THEN** the request is refused

#### Scenario: A well-formed capability
- **WHEN** an agent is created with the capability `urn:hearth:capability:files:read`
- **THEN** the agent is created with that capability

### Requirement: Workload identity is enabled per realm
A realm MUST explicitly enable workload identity before an agent can authenticate with it. Hearth SHOULD support SPIFFE-compatible workload identity for agent authentication. Workload identity is an OPTIONAL authentication method. Trust bundles MUST be configurable per realm, because different realms may use different SPIRE trust domains. Workload identity SHOULD be combinable with DPoP: mTLS for the transport, DPoP for token binding.

#### Scenario: A realm that has not enabled workload identity
- **WHEN** an agent presents an X.509 SVID to a realm that has not enabled workload identity
- **THEN** the SVID does not authenticate the agent

#### Scenario: Two realms, two trust domains
- **WHEN** realm A trusts SPIRE domain `a.example` and realm B trusts `b.example`
- **THEN** an SVID from `b.example` authenticates in realm B and not in realm A

### Requirement: SPIFFE SVIDs identify agents
An agent's SPIFFE ID MUST have the form `spiffe://{trust_domain}/agent/{agent_id}`. An agent MAY authenticate with an X.509 SPIFFE Verifiable Identity Document (SVID). Hearth MAY act as a SPIFFE workload API provider that issues SVIDs to registered agents. An agent MAY instead present an SVID issued by an external SPIRE server, which Hearth validates against the realm's trust bundle. SVID validation MUST check the certificate chain, the expiration and the SPIFFE ID format. An SVID that maps to an agent whose status is not `Active` MUST be refused.

#### Scenario: An expired SVID
- **WHEN** an agent presents an SVID whose `notAfter` is in the past
- **THEN** it is refused

#### Scenario: A malformed SPIFFE ID
- **WHEN** a mapping is registered for `spiffe://example.org/workload/123`
- **THEN** it is refused

#### Scenario: A SPIFFE ID already mapped
- **WHEN** a SPIFFE ID already mapped to one agent is registered for a second agent
- **THEN** the second registration is refused

#### Scenario: An SVID from an untrusted chain
- **WHEN** an agent presents an SVID that does not chain to the realm's trust bundle
- **THEN** it is refused

#### Scenario: The mapped agent is suspended
- **WHEN** a valid SVID maps to an agent that is `Suspended`
- **THEN** it is refused

### Requirement: The TLS layer maps an SVID to an agent
An agent that presents an X.509 SVID MUST authenticate over mTLS. Hearth's TLS termination layer MUST extract the client certificate and map its SPIFFE ID to an `AgentId`. The mapping from SPIFFE ID to `AgentId` MUST be configured per realm.

#### Scenario: A mapped SVID
- **WHEN** an agent completes an mTLS handshake with an SVID whose SPIFFE ID is mapped in the realm
- **THEN** Hearth resolves the connection to that agent's `AgentId`

#### Scenario: An unmapped SVID
- **WHEN** the SPIFFE ID in a valid SVID has no mapping in the realm
- **THEN** the agent is not authenticated

### Requirement: Agents in an act chain must be active
RFC 8693 token exchange MUST refuse an agent whose status is not `Active`, both as the immediate actor and anywhere in the subject token's `act` chain. `Suspended` MUST block exactly as `Revoked` does.

#### Scenario: A suspended agent in the act chain
- **WHEN** a token exchange presents a subject token whose `act` chain names an agent that is now `Suspended`
- **THEN** the exchange is refused with `invalid_grant`

#### Scenario: A revoked agent as the actor
- **WHEN** a revoked agent is the actor of a token exchange
- **THEN** the exchange is refused with `invalid_grant`

### Requirement: The audit API filters by agent, chain and tool
The API MUST support querying audit events by agent ID, by delegation-chain membership, and by the tool invoked. The admin UI SHOULD show a delegation-chain view: given a token or an audit event, it shows the full chain of delegations that led to the action.

#### Scenario: Query by agent
- **WHEN** an operator queries the audit log for one agent ID
- **THEN** only events involving that agent are returned

#### Scenario: Query by chain membership
- **WHEN** an operator queries for events whose delegation chain contains agent A
- **THEN** events where agent A was any hop of the chain are returned

#### Scenario: Query by tool
- **WHEN** an operator queries the audit log for tool `send_email`
- **THEN** only events for that tool are returned

### Requirement: Rate monitoring covers all agent activity
When an agent exceeds its rate threshold, Hearth SHALL respond as this requirement sets out. Hearth SHOULD keep per-agent rate counters for token requests, tool invocations, approval requests and delegation events. Anomaly thresholds SHOULD be configurable per agent or per realm. When an agent exceeds its threshold, Hearth SHOULD emit a risk signal and MAY suspend the agent automatically.

#### Scenario: A realm lowers the threshold
- **WHEN** an operator sets a lower rate threshold for a realm, and an agent of that realm exceeds it with tool invocations
- **THEN** Hearth emits a risk signal for the agent

#### Scenario: Token requests count
- **WHEN** an agent sends token requests above its threshold
- **THEN** the rate monitor counts them toward the threshold
