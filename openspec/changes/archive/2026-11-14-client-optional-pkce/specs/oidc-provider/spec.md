## MODIFIED Requirements

### Requirement: PKCE with S256 is required for every client
Every authorization request SHALL carry `code_challenge` and `code_challenge_method=S256`, for every public client and for every confidential client whose `require_pkce` setting is `true` (RFC 9700 §2.1.1). `require_pkce` SHALL default to `true`. An admin SHALL be able to set it to `false` for one confidential client (a client that authenticates at the token endpoint with a client secret or `private_key_jwt`), through `hearth.yaml` or the admin API, and for no other client; dynamic client registration SHALL NOT set it. A public client SHALL need PKCE whatever its stored setting says. `S256` is the only supported method: a request that carries `code_challenge` SHALL be checked as for every other client. A token request that carries `code_verifier` for a code issued without `code_challenge` SHALL be refused with `invalid_grant` (RFC 9700 §4.8.2). There SHALL be no global or per-realm opt-out: config validation SHALL refuse `oidc.require_pkce_for_confidential_clients: false` as a removed opt-out, so the server does not start with it.

#### Scenario: A public client omits the code challenge
- **WHEN** a public client sends an authorization request without `code_challenge`
- **THEN** the request is refused

#### Scenario: The code verifier is checked on exchange
- **WHEN** a client exchanges a code with a `code_verifier` whose S256 hash does not equal the `code_challenge`
- **THEN** the exchange is refused

#### Scenario: The plain method is requested
- **WHEN** an authorization request carries `code_challenge_method=plain`
- **THEN** the request is refused

#### Scenario: A confidential client omits the code challenge
- **WHEN** a confidential client with `require_pkce: true` (the default) sends an authorization request without `code_challenge`
- **THEN** the request is refused

#### Scenario: A confidential client without the PKCE requirement
- **WHEN** a confidential client with `require_pkce: false` sends an authorization request without `code_challenge`
- **THEN** a code is issued
- **AND** the client exchanges it with its client authentication and no `code_verifier`

#### Scenario: A verifier for a code without a challenge
- **WHEN** a client sends a `code_verifier` to exchange a code that was issued without `code_challenge`
- **THEN** the exchange is refused with `invalid_grant`

#### Scenario: A public client cannot drop the requirement
- **WHEN** an admin creates or updates a public client with `require_pkce: false`, through the admin API or `hearth.yaml`
- **THEN** the write is refused
- **AND** a `hearth.yaml` config validation error names `require_pkce`

#### Scenario: The removed opt-out is configured
- **WHEN** `hearth.yaml` sets `oidc.require_pkce_for_confidential_clients: false`
- **THEN** config validation fails and names `oidc.require_pkce_for_confidential_clients`
