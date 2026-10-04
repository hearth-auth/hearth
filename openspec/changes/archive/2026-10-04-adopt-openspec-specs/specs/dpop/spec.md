## ADDED Requirements

### Requirement: DPoP is supported per RFC 9449
Hearth MUST support DPoP proofs per RFC 9449. DPoP SHALL be optional by default, and is RECOMMENDED for all public clients. Agents operating in untrusted environments SHOULD use DPoP-bound tokens, binding the token to the agent's asymmetric key.

#### Scenario: A client sends no proof
- **WHEN** a client with `dpop_bound_access_tokens: false` sends a token request without a `DPoP` header
- **THEN** it receives a `Bearer` token

#### Scenario: A DPoP-bound issuance flow
- **WHEN** a client sends a token request with a valid `DPoP` proof
- **THEN** it receives a DPoP-bound access token

### Requirement: DPoP proof format
A DPoP proof JWT MUST use `typ: dpop+jwt` in the JOSE header. Its header `jwk` SHALL NOT carry private key material. Its claims MUST include a unique `jti`, `htm` (the HTTP method), `htu` (the target URI) and `iat`. The `ath` (access token hash) claim MUST be included when the proof accompanies a resource request. Ed25519 (`EdDSA`) MUST be supported for DPoP keys, and P-256 (`ES256`) SHOULD be supported. Discovery SHALL advertise `dpop_signing_alg_values_supported: ["ES256", "EdDSA"]`.

#### Scenario: A proof with the wrong type
- **WHEN** a token request carries a DPoP proof whose header `typ` is `JWT`
- **THEN** the request is refused with `invalid_dpop_proof`

#### Scenario: A proof that embeds a private key
- **WHEN** a DPoP proof's header `jwk` carries a `d` member
- **THEN** the proof is refused with `invalid_dpop_proof`

#### Scenario: RFC 9449 test vectors
- **WHEN** the RFC 9449 example proofs are validated
- **THEN** their thumbprints and verdicts match the RFC

### Requirement: DPoP proofs are fresh and single-use
A proof's `iat` MUST be within `DPOP_MAX_AGE_SECS` (120 s) plus `DPOP_MAX_CLOCK_SKEW_SECS` (60 s) of the server's clock. Every proof `jti` MUST be recorded to reject proof replay. The `cnf.jkt` binding check MUST run before the `jti` is recorded, so a proof that fails the binding check cannot spend the legitimate holder's one-shot slot. The same ordering SHALL apply to every single-use artefact: the caller-binding check precedes the burn.

#### Scenario: A proof is reused
- **WHEN** a client presents the same DPoP proof twice
- **THEN** the second presentation is refused as a replay

#### Scenario: A stale proof
- **WHEN** a proof's `iat` is more than 180 seconds in the past
- **THEN** it is refused with `invalid_dpop_proof`

#### Scenario: A proof with the wrong key does not burn the jti
- **WHEN** a proof signed by a key other than the token's `cnf.jkt` key is presented with a given `jti`
- **THEN** it is refused
- **AND** a later proof from the legitimate key with the same `jti` is not refused as a replay

### Requirement: The token endpoint issues DPoP nonces
Hearth MUST include a `DPoP-Nonce` response header at the token endpoint, so the server can provide nonces for tighter replay protection. Clients MUST include the server nonce in subsequent DPoP proofs when one is provided. A DPoP `nonce` SHALL NOT be required at resource endpoints.

#### Scenario: A proof without the server nonce
- **WHEN** a client sends a token request whose DPoP proof carries no current server nonce
- **THEN** the request is refused
- **AND** the response carries a `DPoP-Nonce` header the client can use in its next proof

#### Scenario: A successful token response
- **WHEN** a token request with a valid DPoP proof succeeds
- **THEN** the response carries a `DPoP-Nonce` header

### Requirement: Clients can require DPoP with dpop_bound_access_tokens
`dpop_bound_access_tokens` SHALL be a boolean client metadata value (RFC 9449 §5.2), default `false`. When it is `true`, every token request from that client MUST carry a valid `DPoP` proof, and the issued tokens SHALL be bound to the proof key. Clients with the value `false` MAY still send a proof, and are then bound the same way. The value SHALL be settable on every client-management surface:

| Surface | How |
|---------|-----|
| `hearth.yaml` | `realms.<realm>.applications.<app>.dpop_bound_access_tokens: true`, re-applied on every reconcile |
| Dynamic registration (`POST /register`, `POST /realms/{realm}/register`) | request field; echoed in the registration response when `true` |
| Admin API (`POST /admin/applications`, `POST /clients`, `PATCH /admin/applications/{id}`) | request field; the client JSON always carries `dpop_bound_access_tokens` |

The admin API SHALL refuse to change `dpop_bound_access_tokens` on a `hearth.yaml`-declared application with `409`, as it does for the client's keys.

#### Scenario: DCR echoes the flag
- **WHEN** a client registers through `POST /realms/{realm}/register` with `dpop_bound_access_tokens: true`
- **THEN** the registration response carries `dpop_bound_access_tokens: true`

#### Scenario: An admin changes a YAML-declared application
- **WHEN** an admin sends `PATCH /admin/applications/{id}` with `dpop_bound_access_tokens` for an application declared in `hearth.yaml`
- **THEN** the response is `409`

### Requirement: DPoP-bound access tokens carry cnf.jkt
When a token request includes a `DPoP` proof header, the issued access token SHALL carry a `cnf.jkt` claim containing the SHA-256 JWK thumbprint of the DPoP public key, and the response's `token_type` SHALL be `DPoP`, not `Bearer`. This SHALL hold for every grant: `authorization_code`, `device_code`, `refresh_token`, `client_credentials` and `jwt-bearer` (`urn:ietf:params:oauth:grant-type:jwt-bearer`). Resource servers MUST verify that incoming DPoP proofs are signed by the key whose thumbprint matches `cnf.jkt`.

#### Scenario: A client credentials request with a proof
- **WHEN** a client calls the `client_credentials` grant with a valid DPoP proof
- **THEN** the access token carries `cnf.jkt` equal to the proof key's thumbprint
- **AND** the response's `token_type` is `DPoP`

### Requirement: A DPoP-bound grant family stays bound to its key
When the initial token request (`authorization_code` or `device_code` grant) includes a DPoP proof, Hearth SHALL bind the whole grant family to the JWK thumbprint of the proving key (RFC 9449 §5). The refresh token SHALL be stored against the same `cnf.jkt`. Every later `refresh_token` request on that family MUST include a `DPoP` proof signed by the same key pair. A refresh whose proof thumbprint does not match the stored thumbprint, or that carries no proof, SHALL be refused with `401 invalid_token`. `invalid_dpop_proof` is reserved for a proof that fails to parse or verify on its own terms. The access and refresh tokens a successful bound refresh issues SHALL carry the same `cnf.jkt`; the binding is never relaxed within a family. There SHALL be no mechanism to re-bind an existing refresh token to a new key: a client that rotates its DPoP key pair must revoke the grant family and start a new authorization flow. Clients SHOULD confirm that `cnf.jkt` is present in the issued access token before relying on refresh token continuity.

#### Scenario: Refresh with a different key
- **WHEN** a client refreshes a DPoP-bound grant family with a valid proof from a different key
- **THEN** the refresh is refused with `401 invalid_token`

#### Scenario: Refresh without a proof
- **WHEN** a client with `dpop_bound_access_tokens: false` refreshes a DPoP-bound grant family with no `DPoP` header
- **THEN** the refresh is refused with `401 invalid_token`

#### Scenario: A successful bound refresh
- **WHEN** a client refreshes a DPoP-bound grant family with a proof from the original key
- **THEN** the new access token carries the same `cnf.jkt`

### Requirement: Resource endpoints enforce the DPoP binding
When a validated access token carries a `cnf.jkt` claim, the endpoints below MUST refuse the request unless it also carries a `DPoP` header whose proof validates against that thumbprint (RFC 9449 §7.2). The check SHALL run before any user lookup, permission resolution or side-effecting work, and SHALL fail closed.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/userinfo` | OIDC UserInfo (realm from `X-Realm-ID`) |
| `GET` | `/realms/{realm}/userinfo` | OIDC UserInfo (realm-scoped) |
| `GET` | `/v1/me/permissions` | Live effective-permission resolution |
| `POST` | `/oauth/authorize` (decide-permission) | Agent tool-permission decision; fails closed to `{"allowed":false}` on an invalid proof |
| `GET` | `/oauth/consents` | Self-service consent listing |
| `DELETE` | `/oauth/consents/{client_id}` | Self-service consent revocation |
| `GET` | `/oauth/session-versions` | Session-version delta feed |
| `GET` | `/oauth/session-versions/snapshot` | Session-version snapshot |
| `POST` | `/register`, `/realms/{realm}/register` | Authenticated DCR with an initial access token |
| `POST` | `/webauthn/register/begin` | WebAuthn credential registration |
| `POST` | `/webauthn/register/complete` | WebAuthn credential registration |
| `GET` | `/webauthn/credentials` | WebAuthn credential listing |
| `DELETE` | `/webauthn/credentials/{credential_id}` | WebAuthn credential deletion |

Tokens without `cnf.jkt` SHALL be unaffected: plain Bearer tokens SHALL keep working at every endpoint above with no `DPoP` header.

#### Scenario: A stolen bound token replayed as a plain Bearer
- **WHEN** a `cnf`-bound access token is sent to `GET /userinfo` without a `DPoP` header
- **THEN** the response is `401` and no user data is returned

#### Scenario: An invalid proof at the decision endpoint
- **WHEN** a `cnf`-bound token reaches `POST /oauth/authorize` with an invalid proof
- **THEN** the response is `{"allowed":false}`

#### Scenario: A plain Bearer token
- **WHEN** a token without `cnf.jkt` is sent to `GET /v1/me/permissions` without a `DPoP` header
- **THEN** the request is served

### Requirement: Resource-endpoint proofs bind the method, URI and token
A proof presented at a resource endpoint SHALL satisfy:

| Claim | Value | Notes |
|-------|-------|-------|
| `htm` | the request's HTTP method | compared case-insensitively (RFC 9110) |
| `htu` | `<issuer><request path>` | query string and fragment stripped before comparison |
| `ath` | `BASE64URL(SHA-256(access_token))` | REQUIRED at resource endpoints; compared in constant time |

Hearth SHALL derive the expected `htu` from the configured issuer plus the request path, never from the `Host` header, so a client MUST sign the issuer-relative URL. For `/realms/{realm}/userinfo` the path includes the `/realms/{realm}` prefix.

#### Scenario: The proof signs the dialled origin
- **WHEN** a client signs `htu` with the origin it dialled instead of the configured issuer
- **THEN** the proof is refused with `invalid_dpop_proof`

#### Scenario: A proof without ath
- **WHEN** a proof at `GET /userinfo` omits `ath`
- **THEN** it is refused with `invalid_dpop_proof`

#### Scenario: A lowercase method
- **WHEN** a proof for `GET /userinfo` carries `htm: get`
- **THEN** the `htm` check passes

### Requirement: Bound tokens use the Bearer scheme at resource endpoints
Hearth SHALL accept the access token under the `Bearer` scheme at the DPoP-enforcing resource endpoints, including when the token is DPoP-bound. This deviates from RFC 9449 §7.1. An `Authorization: DPoP ...` header SHALL NOT be recognised and SHALL yield `401 invalid_token`.

#### Scenario: The DPoP scheme
- **WHEN** a client sends `Authorization: DPoP <access_token>` with a valid proof to `GET /userinfo`
- **THEN** the response is `401 invalid_token`

#### Scenario: The Bearer scheme with a proof
- **WHEN** a client sends `Authorization: Bearer <access_token>`, a valid `DPoP` proof and `X-Realm-ID` to `GET /userinfo`
- **THEN** the request is served

### Requirement: Resource-endpoint DPoP errors
The DPoP-enforcing resource endpoints SHALL answer:

| Condition | Status | Body |
|-----------|--------|------|
| `cnf`-bound token, no `DPoP` header | 401 | `{"error":"invalid_token","error_description":"DPoP proof required for cnf-bound access token"}` |
| Proof key thumbprint ≠ token `cnf.jkt` | 401 | `{"error":"invalid_token","error_description":"DPoP proof key does not match token cnf.jkt binding"}` |
| Malformed proof, or `htm` / `htu` / `ath` / `iat` mismatch | 401 | `{"error":"invalid_dpop_proof","error_code":"..."}` |
| `jti` already seen (proof replay) | 401 | `{"error":"use_dpop_nonce","error_code":"..."}` |

The `invalid_dpop_proof` body SHALL omit the specific validation failure. The reason SHALL be recorded server-side only, so the response cannot serve as an oracle.

#### Scenario: A proof from another key
- **WHEN** a `cnf`-bound token is sent with a valid proof from a different key
- **THEN** the response is `401` with `error_description` `DPoP proof key does not match token cnf.jkt binding`

#### Scenario: A malformed proof
- **WHEN** a `cnf`-bound token is sent with a proof whose `htu` names another path
- **THEN** the response is `401` `invalid_dpop_proof`
- **AND** the body does not say which check failed

### Requirement: Token exchange preserves the subject token's DPoP binding
When a token exchange's `subject_token` carries a `cnf.jkt` claim, the request MUST include a `DPoP` proof header whose thumbprint matches that `cnf.jkt`. A sender-constrained subject token presented without a matching proof SHALL be refused with `400 invalid_grant`, both when no proof is sent and when the proof's thumbprint differs. This prevents a stolen DPoP-bound access token from being re-bound to an attacker's key. When a proof is presented, the exchanged token SHALL be bound to the proof's key. A plain Bearer subject token (no `cnf.jkt`) SHALL require no `DPoP` header.

#### Scenario: A bound subject token without a proof
- **WHEN** a client exchanges a `cnf`-bound access token without a `DPoP` header
- **THEN** the response is `400 invalid_grant`

#### Scenario: A bound subject token with another key's proof
- **WHEN** a client exchanges a `cnf`-bound access token with a valid proof from a different key
- **THEN** the response is `400 invalid_grant`

#### Scenario: A bound subject token with the matching proof
- **WHEN** a client exchanges a `cnf`-bound access token with a proof from the key named by its `cnf.jkt`
- **THEN** the exchanged token carries the same `cnf.jkt`

#### Scenario: A plain subject token
- **WHEN** a client exchanges an access token with no `cnf` claim and sends no `DPoP` header
- **THEN** the exchange is processed
