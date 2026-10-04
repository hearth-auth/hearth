## MODIFIED Requirements

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

#### Scenario: A token request's resource is applied
- **WHEN** a `client_credentials` token request carries `resource` naming a registered protected resource, and a second request carries an unregistered `resource`
- **THEN** the first token's `aud` includes the resource, and the second request is refused with `invalid_target`
