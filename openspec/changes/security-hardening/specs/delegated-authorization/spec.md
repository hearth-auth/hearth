## MODIFIED Requirements

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
