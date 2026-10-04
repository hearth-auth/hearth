# client-authentication Specification

## Purpose
How OAuth clients authenticate at the token endpoint and at the other endpoints that take client credentials.
## Requirements
### Requirement: Key-holding clients authenticate with private_key_jwt
A client that registers a JWKS or an assertion key and no secret SHALL authenticate with `private_key_jwt` (RFC 7523). Hearth SHALL verify a `client_assertion` against the client's registered keys:

| Key source | Algorithms | Key selection |
|------------|------------|---------------|
| `assertion_public_key` (raw Ed25519) | `EdDSA` | the key |
| `jwks` (inline) | `PS256`, `ES256`, `EdDSA` | the JWS `kid`, or the only key when there is no `kid` |

`RS256` SHALL NOT be accepted for client assertions. A JWKS key whose `alg` names another algorithm SHALL be refused.

#### Scenario: An assertion signed with a JWKS key
- **WHEN** a client with an inline JWKS presents a `PS256` assertion whose `kid` names one of its keys
- **THEN** the client is authenticated

#### Scenario: An RS256 assertion
- **WHEN** a client presents a client assertion signed with `RS256`
- **THEN** the response is `401 invalid_client`

### Requirement: Hearth does not fetch client key sets
Hearth SHALL NOT fetch a client's `jwks_uri`. A client registered with only a `jwks_uri` SHALL NOT be able to authenticate, and must register its keys inline.

#### Scenario: A client with only a jwks_uri
- **WHEN** a client registered with only a `jwks_uri` presents a client assertion
- **THEN** the response is `401 invalid_client`
- **AND** Hearth makes no request to the `jwks_uri`

### Requirement: Client assertions name the client and the realm issuer
A client assertion SHALL carry `iss` = `sub` = the client, an `aud` that is the realm issuer or an array that contains it (RFC 7523 §3), a single-use `jti`, and a lifetime of at most 5 minutes. An assertion that fails any of these checks SHALL be refused with `401 invalid_client`.

#### Scenario: An assertion is replayed
- **WHEN** a client presents an assertion whose `jti` was already used
- **THEN** the response is `401 invalid_client`

#### Scenario: An assertion lives too long
- **WHEN** a client presents an assertion whose `exp` is more than 5 minutes ahead
- **THEN** the response is `401 invalid_client`

#### Scenario: An array audience
- **WHEN** a client presents an assertion whose `aud` is an array that contains the realm issuer
- **THEN** the `aud` check passes

### Requirement: The client identifier is the issued client_id exactly
"The client" in an assertion SHALL be its `client_id` exactly as registration returned it: the bare UUID it also sends as the `client_id` parameter (RFC 7523 §3, OIDC Core §9). Hearth's internal `client_<uuid>` subject form, and any other spelling of the UUID, SHALL be refused. The same rule SHALL apply to a request object's `iss` and `client_id` claims (RFC 9101 §4) and to the JWT-bearer grant's `iss` and `sub`.

#### Scenario: An assertion uses the internal subject form
- **WHEN** a client presents an assertion with `iss` and `sub` = `client_<uuid>`
- **THEN** the response is `401 invalid_client`

#### Scenario: An uppercase UUID
- **WHEN** a client presents an assertion whose `iss` is its UUID in uppercase
- **THEN** the assertion is refused

### Requirement: Issued fields name the client by its issued client_id
Every field Hearth issues that names a client SHALL carry the same issued `client_id`: an ID token's `aud` and `azp` (OIDC Core §2), an access token's `client_id` claim (RFC 9068 §2.2), the introspection response's `client_id` (RFC 7662 §2.2), a back-channel logout token's `aud`, an exchanged token's `act.sub` (RFC 8693 §4.1), and the pre-token webhook payload's `client_id`. Hearth SHALL parse these back only in that form: in the first-party gate, the non-interactive `/authorize` client match, and revocation and introspection ownership. The one exception SHALL be the `sub` of a sessionless client token (`client_credentials`, JWT-bearer), which stays in Hearth's subject namespace (`client_<uuid>`, beside `user_<uuid>`), so a client subject is never read as a user.

#### Scenario: The ID token names the client
- **WHEN** a client completes an authorization code flow
- **THEN** the ID token's `aud` and `azp` equal the `client_id` registration returned

#### Scenario: A client credentials token
- **WHEN** a client obtains a token with the `client_credentials` grant
- **THEN** the token's `sub` is `client_<uuid>`
- **AND** its `client_id` claim is the bare UUID

### Requirement: A client JWKS holds public signing keys only
A client JWKS SHALL be checked at registration on every surface, on update, by `hearth config validate`, and again before every signature verification, so a set stored before these rules fails closed. The JWKS SHALL satisfy all of:

| Rule | Limit |
|------|-------|
| Size | at most 8 keys and 16 KiB |
| Private or symmetric material | none: no `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`; no `kty: oct` |
| `use` | when present, `sig` |
| `key_ops` | when present, includes `verify` |
| `kty` / `crv` | `OKP`/`Ed25519` (EdDSA), `EC`/`P-256` (ES256), or `RSA` with `n` and `e` (RS256 for request objects only, PS256) |
| `alg` | when present, one its `kty` supports |
| `kid` | unique; required on every key when the set has more than one |

A violation SHALL be refused with `400`, and with `invalid_client_metadata` at dynamic registration.

#### Scenario: A JWKS with a private key
- **WHEN** a client registers a JWKS whose key carries a `d` member
- **THEN** dynamic registration fails with `invalid_client_metadata`

#### Scenario: Too many keys
- **WHEN** an admin registers a client JWKS with 9 keys
- **THEN** the response is `400`

#### Scenario: A stored JWKS that breaks the rules
- **WHEN** a client whose stored JWKS breaks a rule presents an assertion
- **THEN** verification fails closed

### Requirement: A client with keys is never public
A client SHALL be public only when it has no secret, no assertion key and no JWKS. Every other client MUST authenticate. A client that registered a JWKS or an assertion key and no secret, and presents only its `client_id`, SHALL get `401 invalid_client` at `/as/par`, at every `/token` grant (including `authorization_code`, `refresh_token`, `device_code` and token exchange, each of which accepts a `client_assertion`), at `/device_authorization` (which accepts one too), and at `/introspect` and `/revoke`.

#### Scenario: A key-holding client sends only its client_id
- **WHEN** a client with a registered JWKS and no secret calls the `authorization_code` grant with only `client_id`
- **THEN** the response is `401 invalid_client`

#### Scenario: Revocation by client_id alone
- **WHEN** a client with an assertion key and no secret posts to `/revoke` with only `client_id`
- **THEN** the response is `401 invalid_client`

### Requirement: A presented assertion is always a private_key_jwt attempt
On every surface that reads `client_assertion` or `client_assertion_type` (every `/token` grant, `/as/par`, `/introspect`, `/revoke`, `/device_authorization` and their realm twins), a request that carries either field MUST have `client_assertion_type` equal to `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a non-empty `client_assertion`, and that assertion MUST verify for the named client, else the response SHALL be `401 invalid_client`. Such a request SHALL never fall through to the secret check, to `none`, or to "no client authentication". An assertion beside a secret (Basic or body) SHALL be refused with `400 invalid_request` (RFC 6749 §2.3). A blank field counts as absent. Grants that do not otherwise authenticate the client (jwt-bearer, magic link) SHALL still verify a presented assertion.

#### Scenario: A wrong assertion type
- **WHEN** a request carries a `client_assertion` with `client_assertion_type` other than the jwt-bearer URN
- **THEN** the response is `401 invalid_client`

#### Scenario: An assertion type without an assertion
- **WHEN** a public client sends `client_assertion_type` with no `client_assertion`
- **THEN** the response is `401 invalid_client`, not a public-client success

#### Scenario: An assertion and a secret together
- **WHEN** a request carries both a `client_assertion` and a `client_secret`
- **THEN** the response is `400 invalid_request`

#### Scenario: Blank fields
- **WHEN** a public client sends empty `client_assertion` and `client_assertion_type` fields
- **THEN** the fields are treated as absent

### Requirement: Introspection serves confidential clients only
`POST /introspect` and `POST /realms/{realm}/introspect` MUST authenticate the caller as a confidential client (RFC 7662 §2.1, §4) by exactly one of:

| Method | How it is presented |
|--------|---------------------|
| `client_secret_basic` | `Authorization: Basic base64(client_id:client_secret)` |
| `client_secret_post` | `client_id` + `client_secret` body fields |
| `private_key_jwt` | `client_id` + `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` + `client_assertion`, verified as at the token endpoint |

A public client (no stored secret) SHALL be refused with `401` `{"error":"invalid_client"}` and `WWW-Authenticate: Basic` (RFC 6749 §5.2), including when it presents a made-up secret. A `private_key_jwt` client presenting `client_id` without an assertion, a confidential client with a missing or wrong secret, and an unknown client SHALL all receive the same `401 invalid_client`. Combining an assertion with a secret or a Basic header SHALL be `400 invalid_request` (RFC 6749 §2.3, §5.2).

#### Scenario: A public client introspects
- **WHEN** a public client posts to `/introspect` with only its `client_id`
- **THEN** the response is `401 {"error":"invalid_client"}` with `WWW-Authenticate: Basic`

#### Scenario: A public client invents a secret
- **WHEN** a public client posts to `/realms/{realm}/introspect` with a made-up `client_secret`
- **THEN** the response is `401 invalid_client`

#### Scenario: A private_key_jwt client introspects
- **WHEN** a `private_key_jwt` client posts to `/introspect` with a valid assertion
- **THEN** the introspection result is returned

### Requirement: Revocation accepts public clients
`POST /revoke` and its realm twin SHALL authenticate a public client by `client_id` alone (RFC 7009 §2.1), and a secret-bearing confidential client by its secret (`client_secret_basic` or `client_secret_post`). A `private_key_jwt` client, one with an assertion key or JWKS and no secret, is confidential: the routes SHALL accept its `client_assertion`, SHALL answer `400 invalid_request` when the assertion is combined with a secret, and SHALL refuse it with `401 invalid_client` when it presents only its `client_id` or a made-up secret.

#### Scenario: A public client revokes its token
- **WHEN** a public client posts its own refresh token to `/revoke` with only `client_id`
- **THEN** the token is revoked

#### Scenario: A private_key_jwt client sends a made-up secret
- **WHEN** a `private_key_jwt` client posts to `/revoke` with a `client_secret`
- **THEN** the response is `401 invalid_client`

### Requirement: Pushed authorization requests authenticate the client
`POST /as/par` and `POST /realms/{realm}/as/par` MUST authenticate the pushing client with the method it uses at the token endpoint (RFC 9126 §2), by exactly one of the methods discovery lists in `token_endpoint_auth_methods_supported` (RFC 9126 §5):

| Method | Accepted for |
|--------|--------------|
| `client_secret_basic` | a client with a stored secret; body `client_id` may be omitted (RFC 6749 §3.2.1), and when present must equal the Basic username, else `400 invalid_request` |
| `client_secret_post` | a client with a stored secret |
| `private_key_jwt` | a client with an assertion key or a registered JWKS; `iss` and `sub` = the body `client_id`, `aud` = the realm issuer, single-use `jti`, lifetime ≤ 5 min |
| `none` | a public client only: no stored secret, no assertion key and no JWKS |

A confidential client with no credentials or a wrong one, a `private_key_jwt` client presenting only its `client_id` or a made-up secret, a public client presenting a secret it cannot hold, and an unknown client SHALL all receive `401 {"error":"invalid_client"}` with `WWW-Authenticate: Basic` (RFC 6749 §5.2). Combining an assertion with a secret SHALL be `400 invalid_request` (RFC 6749 §2.3). An Argon2id secret verification that the KDF admission gate sheds SHALL be `503` `kdf_overloaded` (`error_code` `HEARTH_RATE_LIMITED`) with `Retry-After`.

#### Scenario: A confidential client pushes without credentials
- **WHEN** a client with a stored secret posts to `/as/par` with only `client_id`
- **THEN** the response is `401 invalid_client` with `WWW-Authenticate: Basic`

#### Scenario: The Basic username and the body disagree
- **WHEN** a client pushes with a Basic header for one client and a body `client_id` naming another
- **THEN** the response is `400 invalid_request`

#### Scenario: A public client pushes by client_id
- **WHEN** a public client posts to `/realms/{realm}/as/par` with only `client_id`
- **THEN** the push is accepted

#### Scenario: The KDF gate is saturated
- **WHEN** a client pushes with a secret while the KDF admission gate sheds work
- **THEN** the response is `503` `kdf_overloaded` with `Retry-After`

### Requirement: Device-grant endpoints authenticate confidential clients like the code grant
On the device authorization request (RFC 8628 §3.1) and the device access token request (RFC 8628 §3.4), a confidential client SHALL be authenticated with the same rule the `authorization_code` grant applies. HTTP Basic SHALL take precedence; a body `client_secret` is the `client_secret_post` fallback. A missing or wrong secret SHALL return `401 invalid_client`. Public clients carry no secret and SHALL be unaffected. A `private_key_jwt` client SHALL present `client_assertion_type` and `client_assertion` on both endpoints, in a form or a JSON body, verified as at the token endpoint.

#### Scenario: A confidential client requests a device code without its secret
- **WHEN** a confidential client posts to `/realms/{realm}/device_authorization` without a secret
- **THEN** the response is `401 invalid_client`

#### Scenario: A private_key_jwt client polls for the device token
- **WHEN** a `private_key_jwt` client polls the token endpoint with the `device_code` grant and a valid assertion
- **THEN** the client is authenticated

