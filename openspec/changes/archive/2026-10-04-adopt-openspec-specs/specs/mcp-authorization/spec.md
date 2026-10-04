## ADDED Requirements

### Requirement: Hearth is an OAuth 2.1 authorization server for MCP
Hearth MUST act as an OAuth 2.1 authorization server for the Model Context Protocol (MCP) ecosystem. MCP clients discover Hearth through Protected Resource Metadata, obtain scoped tokens, and present them to MCP tool servers. PKCE MUST be required for every authorization code flow. The implicit grant MUST NOT be supported. Refresh token rotation MUST be enforced. Bearer tokens SHOULD be sender-constrained with DPoP when the client supports it.

#### Scenario: An authorization request without PKCE
- **WHEN** a client starts an authorization code flow without a `code_challenge`
- **THEN** the request is refused

#### Scenario: An implicit-grant request
- **WHEN** a client sends an authorization request with `response_type=token`
- **THEN** no access token is issued from the authorization endpoint

#### Scenario: A refresh token is used twice
- **WHEN** a client redeems a refresh token, and then redeems the same refresh token again
- **THEN** the second redemption is refused

### Requirement: The `resource` parameter names a registered resource
Authorization requests and token requests MUST accept a `resource` parameter that holds the URI of the target MCP server (RFC 8707). The `resource` value MUST match a protected resource registered in the realm. This SHALL be enforced on every authorization surface: the browser `/authorize` (plain query and JAR), PAR, and `/authorize` over JSON, which takes a resource only through a pushed `request_uri`. Each surface SHALL canonicalize the value and refuse anything that is not a registered resource of the realm with `invalid_target`:

| Surface | Refusal |
|---|---|
| Browser `/authorize`, plain query | Error redirect with `error=invalid_target` to the registered `redirect_uri` |
| Browser `/authorize` with JAR, and PAR | `400` |
| `/authorize` over JSON | `400 {"error":"invalid_target"}` |

A pushed request whose resource is removed before the code is asked for SHALL be refused the same way. The canonical form SHALL be what the code stores, what the consent record for the resource is keyed by, and what the token's `aud` carries, so every spelling of one resource is one resource.

#### Scenario: PAR names an unregistered resource
- **WHEN** a client pushes an authorization request whose `resource` is not registered in the realm
- **THEN** the response is `400` with `invalid_target`

#### Scenario: The browser names an unregistered resource
- **WHEN** a browser request to `/authorize` carries a `resource` that is not registered in the realm
- **THEN** the user agent is redirected to the registered `redirect_uri` with `error=invalid_target`

#### Scenario: The resource is removed after the push
- **WHEN** a client pushes a request for a registered resource, the resource is then removed, and the client asks for the code
- **THEN** the request is refused with `invalid_target`

#### Scenario: Two spellings of one resource
- **WHEN** a client asks for `HTTPS://RS.example.com:443/api/` and the realm registers `https://rs.example.com/api`
- **THEN** the request is accepted, and the token's `aud` carries `https://rs.example.com/api`

### Requirement: A resource-scoped token names the resource in `aud`
An access token issued for a `resource` MUST carry an `aud` claim that matches the requested resource URI. If no `resource` parameter is given, the token MUST be scoped to Hearth itself, the default audience. Hearth MAY accept several `resource` parameters in one request; each SHALL then produce a separate token.

#### Scenario: A token for an MCP server
- **WHEN** a client completes an authorization code flow with `resource=https://mcp.example.com`
- **THEN** the access token's `aud` includes `https://mcp.example.com`

#### Scenario: No resource requested
- **WHEN** a client completes a flow without a `resource` parameter
- **THEN** the access token's `aud` is Hearth's default audience

#### Scenario: The audience survives refresh
- **WHEN** a client refreshes an access token that was issued for a resource
- **THEN** the new access token's `aud` still includes that resource

### Requirement: Protected Resource Metadata
Hearth MUST support the RFC 9728 discovery flow. Hearth MUST publish its own Protected Resource Metadata (PRM) document at `/.well-known/oauth-protected-resource`. The PRM document MUST include `resource` (the server URI), `authorization_servers` (an array that holds Hearth's issuer URL), `scopes_supported` and `bearer_methods_supported`. An MCP server registered with Hearth MUST publish its own metadata at `/.well-known/oauth-protected-resource` on its own origin.

#### Scenario: Fetch Hearth's PRM
- **WHEN** a client requests `GET /.well-known/oauth-protected-resource`
- **THEN** the document's `authorization_servers` contains Hearth's issuer
- **AND** it carries `resource`, `scopes_supported` and `bearer_methods_supported`

### Requirement: Discovery advertises resource indicators
Hearth's OIDC discovery document (`/.well-known/openid-configuration`) MUST include `resource_indicators_supported: true`.

#### Scenario: Fetch discovery
- **WHEN** a client requests `/.well-known/openid-configuration`
- **THEN** the document contains `resource_indicators_supported: true`

### Requirement: Protected resources are declared in realm configuration
A realm SHALL register its MCP tool servers as protected resources in its YAML `protected_resources` block. Reconcile SHALL mirror that block into the realm's protected-resource registry at startup and on every config reload, so the registry is exactly the YAML set. An entry added to YAML SHALL be registered on the next reconcile. An entry removed from YAML, or the removal of the whole `protected_resources` key, SHALL remove the entry from the registry. A changed `display_name` or bundle list SHALL update the entry in place and keep its `resource_id`. Reconcile SHALL validate the whole declared set before it writes anything, so an invalid set changes nothing. There SHALL be no admin write API for the registry. A registry entry holds these fields.

| Field | Type | Meaning |
|---|---|---|
| `resource_id` | UUID | Unique identifier. |
| `resource_uri` | URI | The canonical URI of the MCP server, used as `aud` in tokens. |
| `display_name` | String | Human-readable name. |
| `scopes` | List of strings | The entry's resource-local bundle names. |
| `required_claims` | List of strings | Claims the resource requires. It has no YAML key and is always empty. |
| `introspection_client_id` | Client ID, optional | The client the resource server authenticates as at the RFC 7662 introspection endpoint. YAML key: `introspection_client`, the key of an application in the same realm. |

The registry SHALL also be the allowlist of RFC 8693 token-exchange targets.

#### Scenario: An entry is added on reload
- **WHEN** an operator adds an entry to `protected_resources` and reloads the config
- **THEN** the resource is registered, and `resource` requests and token exchanges may name it

#### Scenario: An entry is removed on reload
- **WHEN** an operator removes an entry from `protected_resources` and reloads the config
- **THEN** the resource is no longer registered

#### Scenario: The whole block is removed
- **WHEN** an operator deletes the `protected_resources` key and reloads the config
- **THEN** the realm has no registered protected resource

#### Scenario: A display name changes
- **WHEN** an operator changes an entry's `display_name` and reloads the config
- **THEN** the registry entry shows the new name and keeps its `resource_id`

### Requirement: Registered resource URIs are unique
The registry SHALL key every protected resource by its `resource_uri` in the canonical form of `oidc-provider`. Registered resource URIs MUST be unique within a realm, compared in that canonical form. This SHALL be enforced at config load.

#### Scenario: Two entries collide after canonicalization
- **WHEN** a realm declares both `https://rs.example.com/api` and `HTTPS://RS.example.com:443/api/`
- **THEN** the config load fails and names the duplicate `resource_uri`

### Requirement: A resource server introspects as its named client
A resource server SHALL introspect as the client its entry names in `introspection_client`. That client MAY introspect any access token whose `aud` names the resource, including a token exchanged with `audience=` only, which carries no Hearth audience and which introspection otherwise refuses for every caller. Any other client SHALL get `active: false` unless the token's own claims name it. An `introspection_client` that is not an application of the realm SHALL be refused at config load. Without an `introspection_client`, an `audience=`-only token can only be verified offline, and it lapses at `exp`.

#### Scenario: The named client introspects an audience-only token
- **WHEN** the resource's `introspection_client` introspects a token exchanged with `audience=` set to the resource
- **THEN** the response is `active: true`

#### Scenario: An unrelated client introspects the same token
- **WHEN** a different client of the realm introspects that token
- **THEN** the response is `active: false`

#### Scenario: The named client does not exist
- **WHEN** a `protected_resources` entry names an `introspection_client` that is not an application of the realm
- **THEN** the config load fails

### Requirement: Removing a protected resource stops its tokens
Deleting a protected resource MUST revoke all outstanding tokens scoped to that resource. Removing a resource, from YAML on the next reconcile, SHALL write an audience cutoff into the revoked-JTI projection. The cutoff SHALL be the removal time plus the longest access-token lifetime of the realm, which is the latest `exp` that a token minted for the resource before the removal can carry. Every token whose `aud` names the resource and whose `exp` is not later than the cutoff SHALL then stop validating and introspect inactive, whether it came from an authorization grant with `resource=` or from a token exchange. The cutoff compares `exp` only, so it also refuses a token minted after the resource is registered again when that token's `exp` is not later than the cutoff. Removal SHALL also revoke every grant family bound to the resource, so its refresh tokens stop rotating. A token that a resource server verifies offline, without asking Hearth, lapses at its `exp`.

#### Scenario: A resource is removed
- **WHEN** an operator removes a resource from `protected_resources` and reloads
- **THEN** an access token whose `aud` names the resource fails validation and introspects `active: false`
- **AND** a refresh token of a grant bound to the resource no longer rotates

#### Scenario: The resource is registered again
- **WHEN** an operator removes a resource and adds it back, and a client then obtains a token for it whose `exp` is later than the cutoff
- **THEN** the new token validates
- **AND** tokens minted before the removal still fail

#### Scenario: A short-lived token after re-registration
- **WHEN** a token for a re-registered resource has an `exp` that is not later than the cutoff
- **THEN** it fails validation for its whole lifetime

### Requirement: MCP scope strings
A scope string MUST follow the pattern `{namespace}:{category}:{action}`. This SHALL be enforced where the vocabulary is declared: registering or updating a protected resource SHALL reject any `mcp:`-prefixed scope that is not exactly three non-empty components of ASCII alphanumerics, `_` or `-`. Non-MCP scopes such as `openid` and `profile` are not subject to the rule. Tokens issued for MCP servers SHOULD use these scope strings:

| Scope | Meaning |
|---|---|
| `mcp:tools:invoke` | Invoke tools on the MCP server |
| `mcp:tools:list` | List available tools |
| `mcp:resources:read` | Read MCP resources |
| `mcp:resources:write` | Write MCP resources |
| `mcp:prompts:read` | Read prompt templates |

Custom scopes MAY be registered per protected resource.

#### Scenario: A two-part MCP scope
- **WHEN** a protected resource declares the scope `mcp:tools`
- **THEN** the declaration is refused

#### Scenario: An empty component
- **WHEN** a protected resource declares the scope `mcp:tools:`
- **THEN** the declaration is refused

#### Scenario: A non-MCP scope
- **WHEN** a protected resource declares the scope `openid`
- **THEN** the scope rule does not apply, and the declaration is accepted
