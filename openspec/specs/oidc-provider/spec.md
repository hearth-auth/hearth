# oidc-provider Specification

## Purpose
Hearth's OIDC and OAuth 2.0 authorization-server profile: endpoints, PKCE, JAR, PAR, response modes, discovery, resource indicators, and the request encodings it accepts.
## Requirements
### Requirement: Supported OIDC and OAuth 2.0 specifications
Hearth SHALL implement OpenID Connect Core 1.0 and the related specifications in the table below.

| Specification | Strength |
|---------------|----------|
| OpenID Connect Core 1.0 | MUST |
| OpenID Connect Discovery 1.0 | MUST |
| OpenID Connect Dynamic Client Registration 1.0, registration (RFC 7591) | MUST |
| OAuth 2.0 (RFC 6749) | MUST |
| OAuth 2.0 PKCE (RFC 7636), `S256` only | MUST |
| OAuth 2.0 Token Introspection (RFC 7662) | MUST |
| OAuth 2.0 Token Revocation (RFC 7009) | MUST |
| OAuth 2.0 Device Authorization Grant (RFC 8628) | MUST |
| OAuth 2.0 Authorization Server Issuer Identification (RFC 9207) | MUST |
| JWT-Secured Authorization Requests (JAR, RFC 9101) | MUST |
| Pushed Authorization Requests (PAR, RFC 9126) | MUST |
| JWT Profile for OAuth 2.0 Access Tokens (RFC 9068) | MUST |
| OAuth 2.0 Demonstrating Proof of Possession (DPoP, RFC 9449) | MUST |
| OAuth 2.0 Token Exchange (RFC 8693) | MUST |
| OpenID Connect RP-Initiated Logout 1.0 | MUST |

#### Scenario: Full authorization code flow over HTTP
- **WHEN** a client runs authorize, then exchanges the code at the token endpoint, then validates the tokens
- **THEN** it receives an access token and an ID token, and both validate

#### Scenario: An authorization code is used twice
- **WHEN** a client exchanges the same authorization code a second time
- **THEN** the second exchange is refused

#### Scenario: An expired authorization code
- **WHEN** a client exchanges an authorization code after it expired
- **THEN** the exchange is refused

#### Scenario: An unregistered redirect URI
- **WHEN** an authorization request names a `redirect_uri` that is not registered on the client
- **THEN** the request is refused, and the browser is not redirected to that URI

#### Scenario: A device client polls too fast
- **WHEN** a device client polls the token endpoint faster than the `interval` it was given
- **THEN** the response is the RFC 8628 `slow_down` error

### Requirement: PKCE with S256 is required for every client
Every authorization request SHALL carry `code_challenge` and `code_challenge_method=S256`, for every client, public and confidential (RFC 9700 §2.1.1). `S256` is the only supported method. There SHALL be no opt-out. Config validation SHALL refuse `oidc.require_pkce_for_confidential_clients: false` as a removed opt-out, so the server does not start with it.

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
- **WHEN** a confidential client sends an authorization request without `code_challenge`
- **THEN** the request is refused

#### Scenario: The removed opt-out is configured
- **WHEN** `hearth.yaml` sets `oidc.require_pkce_for_confidential_clients: false`
- **THEN** config validation fails and names `oidc.require_pkce_for_confidential_clients`

### Requirement: Tokens are signed with Ed25519 except RS256 ID tokens
Hearth SHALL sign and validate access, refresh, required-action and logout tokens with `EdDSA` (Ed25519) and the realm's own signing key. The single exception is the ID token of a client that registered `id_token_signed_response_alg: RS256`, which Hearth SHALL sign with `RS256` (OIDC Core §15.1). Hearth SHALL never issue or advertise `HS256` or `alg:none`. Discovery SHALL advertise `id_token_signing_alg_values_supported: ["RS256", "EdDSA"]` on both the global document and the realm-scoped document.

#### Scenario: An unsigned token is presented
- **WHEN** a token with `alg=none` is presented for validation
- **THEN** it is refused, whatever its claims say

#### Scenario: HMAC key confusion
- **WHEN** a token signed with HMAC, using a public key as the secret, is presented
- **THEN** it is refused

#### Scenario: Discovery lists both ID token algorithms
- **WHEN** a client fetches `/.well-known/openid-configuration` or `/realms/{realm}/.well-known/openid-configuration`
- **THEN** `id_token_signing_alg_values_supported` is `["RS256", "EdDSA"]`

### Requirement: Clients choose the ID token algorithm at registration
A client's ID tokens SHALL be signed with the algorithm in its `id_token_signed_response_alg` (OIDC Dynamic Client Registration §2). The only accepted values SHALL be `RS256` and `EdDSA`, matched case-sensitively. Any other value, including `none`, every `HS*`, `ES256` and `PS256`, SHALL be refused at registration and at update: `invalid_client_metadata` on the RFC 7591 endpoints, `400` elsewhere. The value SHALL be resolved at registration and stored explicitly:

| Surface | Value when omitted |
|---------|--------------------|
| Dynamic Client Registration (`POST /register`, `POST /realms/{realm}/register`) | `RS256`; the registration response echoes the resolved value (RFC 7591 §3.2.1) |
| Admin REST `POST /clients`, `POST /admin/applications` | `EdDSA` |
| `PATCH /admin/applications/{id}` | unchanged |
| The console, `hearth.yaml` applications, backup import, migration import | `EdDSA` |

A client record stored before this setting existed carries no value and SHALL read as `EdDSA`.

#### Scenario: DCR without the parameter
- **WHEN** a client registers through `POST /realms/{realm}/register` without `id_token_signed_response_alg`
- **THEN** the client is stored with `RS256`
- **AND** the registration response carries `id_token_signed_response_alg: RS256`

#### Scenario: An HMAC algorithm is requested
- **WHEN** a client registers with `id_token_signed_response_alg: HS256`
- **THEN** registration fails with `invalid_client_metadata`

#### Scenario: Admin creation without the parameter
- **WHEN** an admin creates a client through `POST /admin/applications` without `id_token_signed_response_alg`
- **THEN** the client's ID tokens are signed with `EdDSA`

### Requirement: Each realm has at most one RSA ID-token key
The RSA ID-token key SHALL be per realm, RSA-3072, generated by the `rcgen` `aws_lc_rs` backend and used through `ring` (RSASSA-PKCS1-v1_5 SHA-256). A stored RSA key with a modulus under 2048 bits SHALL be refused on load. The key SHALL be created the first time a client in the realm selects `RS256`, at registration, update or import; issuance provisions it as a fallback. Concurrent provisioning SHALL converge on one key. A realm with no `RS256` client SHALL have no RSA key.

#### Scenario: The first RS256 client creates the key
- **WHEN** the first client in a realm registers with `id_token_signed_response_alg: RS256`
- **THEN** the realm gets an RSA-3072 ID-token key

#### Scenario: Concurrent provisioning
- **WHEN** two RS256 clients in one realm with no RSA key register at the same time
- **THEN** the realm ends with exactly one RSA key

### Requirement: The realm JWKS publishes the RSA ID-token key
The realm JWKS SHALL be published at `/.well-known/jwks.json` relative to the issuer URL. When the realm has an RSA ID-token key, the JWKS SHALL publish it beside the Ed25519 key as `{"kty": "RSA", "alg": "RS256", "use": "sig", "kid", "n", "e", "x-key-role": "id-token-signing"}`, together with any retiring RSA key still inside its grace window. The key SHALL appear as soon as the first `RS256` client is registered, before that client can be issued an ID token.

#### Scenario: JWKS after the first RS256 registration
- **WHEN** a relying party fetches the realm JWKS right after the first RS256 client registers
- **THEN** the JWKS contains the RSA key with `x-key-role: id-token-signing`

#### Scenario: JWKS endpoints differ per realm
- **WHEN** a client fetches the JWKS of two different realms
- **THEN** the two key sets differ

### Requirement: Signing-key rotation rotates the RSA key too
`POST /admin/realms/{id}/rotate-signing-key` SHALL rotate the realm's RSA ID-token key together with its Ed25519 key, with the same grace semantics. The old RSA `kid` SHALL stay published, and SHALL stay accepted as an `id_token_hint`, until the grace deadline. `grace_period_secs: 0` SHALL revoke it immediately. Rotation SHALL never create an RSA key for a realm that has none.

#### Scenario: Rotation with a grace period
- **WHEN** an admin rotates a realm's signing key with a grace period
- **THEN** the JWKS publishes the new and the old RSA key until the deadline
- **AND** an `id_token_hint` signed with the old RSA key is accepted until the deadline

#### Scenario: Rotation of a realm without RS256 clients
- **WHEN** an admin rotates the signing key of a realm that has no RSA key
- **THEN** the realm still has no RSA key

### Requirement: The RSA key signs ID tokens only
The RSA key SHALL sign ID tokens only, and the signer SHALL refuse any other `token_type`. Every path that validates an access, refresh, logout or required-action token (`validate_token`, introspection, `userinfo`, the refresh grant, SDK `verifyToken`) SHALL accept `EdDSA` alone. Hearth SHALL verify `RS256` only where it receives back an ID token it issued: an `id_token_hint` at RP-initiated logout, and an ID token presented to `/revoke`, which ends its session as an `EdDSA` ID token does.

#### Scenario: An RS256 ID token is used as an access token
- **WHEN** an RS256 ID token is presented as a Bearer token to `/userinfo`
- **THEN** it is refused

#### Scenario: An RS256 ID token is revoked
- **WHEN** a client presents its RS256 ID token to `/revoke`
- **THEN** the token's session ends

### Requirement: Backups carry the RSA ID-token key
A backup archive SHALL carry the RSA ID-token key and its retiring predecessors (`id_token_signing_key.json`, `retiring_id_token_signing_keys.json`), re-sealed under the destination's KEK on restore. An archive that has `RS256` clients but no RSA key SHALL refuse to restore unless `--allow-missing-signing-key` is passed.

#### Scenario: Restore across KEKs
- **WHEN** an archive with an RSA ID-token key is restored on a server with a different KEK
- **THEN** ID tokens signed with the key before backup still verify after restore

#### Scenario: Archive with RS256 clients and no RSA key
- **WHEN** an operator restores an archive that has RS256 clients but no RSA key, without `--allow-missing-signing-key`
- **THEN** the restore refuses and writes nothing

### Requirement: JWT authorization requests
Hearth SHALL accept a `request` parameter that holds a signed JWT on an authorization request (RFC 9101). A `request` JWT is optional. It MAY be sent directly to `/authorize` or pushed through PAR. When one is present, Hearth SHALL enforce:

- The `request` JWT MUST be signed with a key from the client's registered JWKS.
- Claims in the `request` JWT override the corresponding query parameters.
- `client_id` in the JWT MUST match the `client_id` query parameter.

The supported signing algorithms (`request_object_signing_alg_values_supported`) SHALL be `EdDSA` (Ed25519), `RS256`, `PS256` and `ES256`.

#### Scenario: A request object overrides a query parameter
- **WHEN** a request object carries a `scope` that differs from the `scope` query parameter
- **THEN** the request object's `scope` is used

#### Scenario: A request object for another client
- **WHEN** the request object's `client_id` differs from the `client_id` query parameter
- **THEN** the request is refused

#### Scenario: A request object with an invalid signature
- **WHEN** the request object is not signed by a key in the client's JWKS
- **THEN** the request is refused

### Requirement: Only the query and fragment response modes are supported
`/authorize` SHALL return its response in one of two modes: `query`, the default for `response_type=code`, or `fragment`. Any other `response_mode`, including `query.jwt`, `fragment.jwt` and `jwt`, SHALL be refused with an error redirect in the default mode, carrying `error=invalid_request` and `error_description=unsupported_response_mode`. A request object's `response_mode` SHALL take precedence over the query parameter (RFC 9101 §4). Every authorization redirect, success and error alike, SHALL carry the RFC 9207 `iss` parameter.

#### Scenario: A JARM response mode is requested
- **WHEN** an authorization request carries `response_mode=query.jwt`
- **THEN** the browser is redirected in `query` mode with `error=invalid_request` and `error_description=unsupported_response_mode`

#### Scenario: Fragment mode
- **WHEN** an authorization request carries `response_mode=fragment` and succeeds
- **THEN** the code, `state` and `iss` are returned in the URI fragment

#### Scenario: An error redirect carries the issuer
- **WHEN** an authorization request fails with an error redirect
- **THEN** the redirect carries the `iss` parameter

### Requirement: Discovery advertises the supported profile
The `/.well-known/openid-configuration` document SHALL advertise, among other fields:

| Field | Value |
|-------|-------|
| `authorization_response_iss_parameter_supported` | `true` |
| `pushed_authorization_request_endpoint` | `{issuer}/as/par` |
| `response_modes_supported` | `["query", "fragment"]` |
| `request_object_signing_alg_values_supported` | `["RS256", "PS256", "ES256", "EdDSA"]` |
| `dpop_signing_alg_values_supported` | `["ES256", "EdDSA"]` |
| `end_session_endpoint` | `{issuer}/end_session` |
| `introspection_endpoint_auth_methods_supported` | `["client_secret_basic", "client_secret_post", "private_key_jwt"]` |
| `revocation_endpoint_auth_methods_supported` | `["none", "client_secret_basic", "client_secret_post", "private_key_jwt"]` |

`introspection_endpoint_auth_methods_supported` SHALL never list `none`. Discovery SHALL NOT advertise `require_pushed_authorization_requests`. The realm-scoped document at `GET /realms/{realm}/.well-known/openid-configuration` and the global document SHALL both include every field, `end_session_endpoint` included.

#### Scenario: A relying party reads the realm document
- **WHEN** a relying party fetches `/realms/{realm}/.well-known/openid-configuration`
- **THEN** the document carries every field in the table, with `{issuer}` the realm issuer

#### Scenario: Introspection never advertises none
- **WHEN** a client reads `introspection_endpoint_auth_methods_supported`
- **THEN** the list does not contain `none`

#### Scenario: PAR is not required
- **WHEN** a client reads the discovery document
- **THEN** it has no `require_pushed_authorization_requests` field

### Requirement: Each realm is its own issuer
Each realm SHALL be its own OIDC issuer, `{oidc.issuer}/realms/{name}`, which is the `issuer` of the realm discovery document (`/realms/{name}/.well-known/openid-configuration`). Every artifact a realm issues SHALL carry that issuer, whichever route (realm-scoped or `X-Realm-ID`) produced it: ID tokens from the code exchange and the device grant, access and refresh tokens, the RFC 9207 `iss` authorization-response parameter, logout tokens and the front-channel `iss` parameter (OIDC Core §3.1.3.7 step 2, Discovery §4.3). The server-level document at `/.well-known/openid-configuration` SHALL describe the host itself, with `issuer` = `oidc.issuer`. Its endpoints need an `X-Realm-ID` header, and no realm token carries its issuer.

#### Scenario: A token issued through the header route
- **WHEN** a client obtains tokens from `POST /token` with `X-Realm-ID`
- **THEN** the tokens' `iss` equals the `issuer` of `/realms/{name}/.well-known/openid-configuration`

#### Scenario: Discovery documents differ per realm
- **WHEN** a client fetches the discovery documents of two realms
- **THEN** each document's `issuer` names its own realm

### Requirement: Pushed authorization requests
PAR SHALL be available to every client and SHALL never be required. A client MAY call `/authorize` directly instead. The pushed request SHALL be stored under the authenticated client. A request object in a pushed request MUST carry that client as `iss`, and, when it has a `client_id` claim, as `client_id` too (RFC 9101 §6.3); otherwise the push SHALL be refused with `400`. Both JSON authorize routes (`POST /authorize` with `X-Realm-ID` and `POST /realms/{realm}/authorize`) SHALL accept a `request_uri` (RFC 9126): the pushed entry is consumed, single-use, and supplies every parameter, and a `client_id` in the body MUST match it.

#### Scenario: A pushed request is used twice
- **WHEN** a client uses the same `request_uri` a second time
- **THEN** the second use is refused

#### Scenario: A request object names another client
- **WHEN** a client pushes a request object whose `iss` is a different client
- **THEN** the push is refused with `400`

### Requirement: The authorization endpoint has a browser path and a machine path
`GET /realms/{realm}/authorize` SHALL answer `303 See Other` to the UI authorize page `/ui/realms/{realm}/oauth/authorize`, preserving every query parameter. `GET /authorize` SHALL do the same to `/ui/oauth/authorize`. `POST /realms/{realm}/authorize` is the machine path for server-to-server flows and SHALL return a JSON authorization code that the caller can exchange at `/token`. `POST /realms/{realm}/authorize` SHALL require a valid Bearer token. The token's `sub` claim SHALL be the user identity, and any `user_id` field in the request body SHALL be ignored.

#### Scenario: A SPA redirects the browser to the advertised endpoint
- **WHEN** a browser sends `GET /realms/{realm}/authorize?client_id=…&state=…`
- **THEN** the response is `303` to `/ui/realms/{realm}/oauth/authorize` with the same query string

#### Scenario: An unauthenticated machine authorize
- **WHEN** a caller posts to `/realms/{realm}/authorize` without a Bearer token
- **THEN** the request is refused and no code is minted

#### Scenario: A body names another user
- **WHEN** a caller posts to `/realms/{realm}/authorize` with a valid Bearer token and a `user_id` that names another user
- **THEN** the code is minted for the token's `sub`

### Requirement: A non-interactive authorize speaks only for its own client
The JSON authorize routes cannot show a consent screen, so they SHALL mint a code only for a client the Bearer token may speak for. A token issued to a client (RFC 9068 `client_id` claim) MAY authorize that client only. A token that names no client, a Hearth first-party session token, MAY authorize a first-party client only. Any other request SHALL be refused with `403` and `error_code: "HEARTH_CLIENT_MISMATCH"` before any side effect. The consent rule (a third-party client needs a recorded consent covering the scopes, `HEARTH_CONSENT_REQUIRED`) and the MFA-use rule SHALL still apply on top. The global and the realm-scoped route SHALL apply the same rule.

#### Scenario: A third-party token targets a first-party client
- **WHEN** a token issued to a third-party client posts to `/realms/{realm}/authorize` naming a first-party public client
- **THEN** the response is `403` with `error_code: "HEARTH_CLIENT_MISMATCH"`
- **AND** no code is minted

#### Scenario: A third-party client without consent
- **WHEN** a third-party client's own token authorizes that client for scopes the user has not consented to
- **THEN** the request is refused with `HEARTH_CONSENT_REQUIRED`

### Requirement: OAuth POST endpoints accept form and JSON bodies
The OAuth 2.0 and OIDC POST endpoints below SHALL accept both `application/x-www-form-urlencoded` and `application/json`. The `Content-Type` header selects the decoder. A form body and the equivalent JSON body SHALL produce identical behaviour, and authentication, DPoP and rate-limit checks SHALL run identically on both. Any other content type SHALL be refused with `415 Unsupported Media Type`.

| Endpoint | Header-routed path | Realm-scoped twin | RFC mandating form |
|----------|--------------------|-------------------|--------------------|
| Token | `POST /token` | `POST /realms/{realm}/token` | RFC 6749 §4.1.3 |
| Revocation | `POST /revoke` | `POST /realms/{realm}/revoke` | RFC 7009 §2.1 |
| Introspection | `POST /introspect` | `POST /realms/{realm}/introspect` | RFC 7662 §2.1 |
| Device Authorization | `POST /device_authorization` | `POST /realms/{realm}/device_authorization` | RFC 8628 §3.1 |
| Pushed Authorization Request | `POST /as/par` | `POST /realms/{realm}/as/par` | RFC 9126 §2.1 |

Client credentials in the request body (`client_id` / `client_secret`, RFC 6749 §2.3.1) SHALL be honoured on the form path as well as the header path. Dynamic client registration (`POST /register`, RFC 7591) and the JSON permission-decision endpoint SHALL remain JSON-only.

#### Scenario: A form-encoded token request
- **WHEN** a client posts a form-encoded body to `/realms/{realm}/token`
- **THEN** the request is not refused with `415`

#### Scenario: A form-encoded request on the global endpoints
- **WHEN** a client posts a form-encoded body with `X-Realm-ID` to `/token`, `/revoke` or `/introspect`
- **THEN** the body is parsed

#### Scenario: An unsupported content type
- **WHEN** a client posts `text/plain` to `/token`
- **THEN** the response is `415 Unsupported Media Type`

### Requirement: The token endpoint refuses unknown grant types
`POST /token` and `POST /realms/{realm}/token` SHALL refuse a `grant_type` they do not support with `400` and `{"error":"unsupported_grant_type"}` (RFC 6749 §5.2). The response SHALL NOT echo the caller's `grant_type` back.

#### Scenario: An unknown grant type
- **WHEN** a client posts `grant_type=urn:example:unknown` to `/realms/{realm}/token`
- **THEN** the response is `400` with `error` `unsupported_grant_type`
- **AND** the body does not contain `urn:example:unknown`

### Requirement: Revocation is restricted to the caller's own tokens
`/revoke` and its realm twin SHALL revoke a token only when it was issued to the authenticated client (RFC 7009 §2.1). The issuing client SHALL be resolved, in order:

| Token shape | Issuing client |
|-------------|----------------|
| Carries `act` (RFC 8693 exchanged, delegated tokens) | the outermost `act.sub`: the client that performed the exchange |
| Carries `azp` (ID tokens) | `azp` |
| Carries `fid` and no `azp` (access and refresh tokens from the `authorization_code` and `device_code` grants, and every rotation of them) | the grant family's `client_id` |
| Sessionless (`sid = "none"`: `client_credentials`, `jwt-bearer`) | `sub`, the client itself |
| Anything else | none |

The magic-link grant, required-action completion, and console, admin and bootstrap logins SHALL record no client on the grant family. Audience membership SHALL NOT confer ownership. A token issued to no client SHALL NOT be revocable through these endpoints by any client. A delegated token (one carrying `act`) SHALL be revoked by its `jti`, leaving the subject's session live. A token issued to another client SHALL be a silent no-op: the response is `200`, identical to the response for an invalid token (RFC 7009 §2.2), and nothing is revoked or audited.

#### Scenario: A client revokes another client's token
- **WHEN** a client posts another client's access token to `/revoke`
- **THEN** the response is `200`
- **AND** the token stays valid and no audit event is written

#### Scenario: A resource server revokes a token naming it in `aud`
- **WHEN** a resource server's client posts a user token whose `aud` names it but which was issued to another client
- **THEN** nothing is revoked

#### Scenario: A delegated token is revoked
- **WHEN** the exchanging client revokes a token it obtained by token exchange
- **THEN** that token stops validating
- **AND** the subject token's session stays live

#### Scenario: A first-party session token is presented
- **WHEN** any client posts a Hearth first-party session token to `/revoke`
- **THEN** nothing is revoked

### Requirement: An exchanged token keeps the subject's introspection audience
Token exchange SHALL record the exchanging client in `act.sub` and SHALL NOT set `azp` on the exchanged token. A resource server that introspects a delegated token SHALL be judged by the same rule as for the subject token: any authenticated client for a user-session token, and the machine subject's own client or an `aud` member for a machine token.

#### Scenario: A resource server introspects an exchanged user token
- **WHEN** a resource server introspects a token exchanged from a user's access token
- **THEN** the response is `active: true`

### Requirement: Token exchange is limited to registered confidential clients
On `POST /token` (realm from `X-Realm-ID`) and `POST /realms/{realm}/token`, the token exchange grant (`urn:ietf:params:oauth:grant-type:token-exchange`) SHALL apply a per-client policy before it reads the subject token:

- The client MUST be a registered client whose status is `active`. An archived or unknown client SHALL be refused with `401 invalid_client`.
- The client MUST be confidential: it has a client secret or `private_key_jwt` keys. A public client SHALL be refused with `400 unauthorized_client`.
- The client's `grant_types` MUST include `urn:ietf:params:oauth:grant-type:token-exchange`, else `400 unauthorized_client`.

A `subject_token` that is expired, revoked, or not an access token SHALL be refused with `400 invalid_grant`.

#### Scenario: A public client exchanges a token
- **WHEN** a public client calls the token exchange grant
- **THEN** the response is `400 unauthorized_client`

#### Scenario: The grant type is not registered
- **WHEN** a confidential client whose `grant_types` lacks the token-exchange grant calls it
- **THEN** the response is `400 unauthorized_client`

#### Scenario: An archived client
- **WHEN** an archived client calls the token exchange grant
- **THEN** the response is `401 invalid_client`

### Requirement: Token exchange targets come from an allowlist
Each `audience` and `resource` value in a token exchange MUST either be an audience the subject token already carries, or equal the `resource_uri` of a protected resource in the realm's identity registry. Any other value SHALL be refused with `400 invalid_target` (RFC 8693 §2.2.2). `audience` SHALL replace the minted `aud`. `resource` SHALL be appended to the subject token's base audience. A value the subject token already carries in `aud` SHALL be kept verbatim. Any other accepted target SHALL be minted into `aud` in canonical form. There SHALL be no admin REST write API for the registry.

#### Scenario: The audience is a registered protected resource
- **WHEN** a client exchanges a token with `audience=https://mcp.acme.example` and the realm's `protected_resources` lists that URI
- **THEN** the exchanged token's `aud` is `https://mcp.acme.example`

#### Scenario: An unregistered audience
- **WHEN** a client exchanges a token with an `audience` that is neither in `protected_resources` nor in the subject token's `aud`
- **THEN** the response is `400 {"error":"invalid_target"}`

### Requirement: Resource indicators have one canonical form
Every resource indicator Hearth handles SHALL be compared in one canonical form: the YAML `protected_resources[].resource_uri` at config load, an exchange's `audience` and `resource`, an authorization grant's `resource`, and RBAC's resource scope lookup. The canonical form SHALL:

- lowercase the scheme and the host, and keep the case of the path and the query;
- drop the scheme's default port (`:443` for `https`, `:80` for `http`);
- drop trailing slashes (`https://mcp.acme.example/` becomes `https://mcp.acme.example`, `/v1/` becomes `/v1`);
- keep the query verbatim;
- refuse fragments, userinfo and a missing host.

Config load SHALL refuse a `resource_uri` that is not a valid resource indicator or has surrounding whitespace, a `resource_uri` declared twice in one realm after canonicalization, an `mcp:`-prefixed bundle name that is not `mcp:{category}:{action}`, and, outside `--dev`, a `resource_uri` that is not `https`, loopback included.

#### Scenario: Two spellings of one resource
- **WHEN** a realm registers `https://mcp.acme.example/api` and a client exchanges with `audience=HTTPS://MCP.Acme.Example:443/api/`
- **THEN** the exchange is accepted as the same resource

#### Scenario: Path case and port are significant
- **WHEN** a client exchanges with `audience=https://mcp.acme.example/API`, `http://mcp.acme.example/api` or `https://mcp.acme.example:8443/api`
- **THEN** each answers `invalid_target`

#### Scenario: A duplicate after canonicalization
- **WHEN** one realm's YAML lists `https://rs.example.com/api` and `HTTPS://RS.example.com:443/api/`
- **THEN** config load fails

### Requirement: Account and realm-feed endpoints take first-party tokens only
Endpoints that act with the user's full authority over their own account, or read realm-wide data, SHALL judge the client the token was issued to (RFC 9068 `client_id`; none means a first-party session token). `GET /oauth/consents`, `POST /webauthn/register/begin`, `POST /webauthn/register/complete`, `GET /webauthn/credentials`, `DELETE /webauthn/credentials/{credential_id}`, `GET /oauth/session-versions`, `GET /oauth/session-versions/snapshot` and the DCR initial access token (`POST /register`, both forms) SHALL refuse a third-party client's token with `403`, whatever permissions the realm's claim profile released to it. `DELETE /oauth/consents/{client_id}` SHALL refuse a third-party client's token unless `client_id` is that client itself.

#### Scenario: A third-party app lists the user's consents
- **WHEN** a third-party client's token calls `GET /oauth/consents`
- **THEN** the response is `403`

#### Scenario: A third-party app registers a passkey
- **WHEN** a third-party client's token calls `POST /webauthn/register/begin`
- **THEN** the response is `403`

#### Scenario: An app disconnects itself
- **WHEN** a third-party client's token calls `DELETE /oauth/consents/{client_id}` with its own `client_id`
- **THEN** the consent is revoked

#### Scenario: An app revokes consent to another app
- **WHEN** a third-party client's token calls `DELETE /oauth/consents/{client_id}` naming another client
- **THEN** the response is `403`

### Requirement: Passkey removal requires a step-up proof
`DELETE /webauthn/credentials/{credential_id}` SHALL require a step-up proof in its JSON body: `password`, `totp_code` or `assertion`, the same proof enrolment takes. Without one it SHALL answer `403 step_up_required`. The browser console's passkey removal (`POST /ui/account/passkeys/{id}/delete`) SHALL require the same proof. A locked-out account (too many wrong passwords or TOTP codes) SHALL get `429 too_many_attempts` (`HEARTH_RATE_LIMITED`) with `Retry-After` on every step-up surface.

#### Scenario: Removal without a proof
- **WHEN** a first-party token calls `DELETE /webauthn/credentials/{credential_id}` with no step-up proof
- **THEN** the response is `403 step_up_required` and the passkey stays

#### Scenario: A locked-out account
- **WHEN** a locked-out account attempts a passkey removal with a step-up proof
- **THEN** the response is `429 too_many_attempts` with `Retry-After`

