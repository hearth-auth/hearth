## ADDED Requirements

### Requirement: Removed HTTP routes are absent
The server SHALL NOT register any route for a removed feature. A request to a removed route SHALL receive the same response as any unknown path.

#### Scenario: SAML IdP routes are gone
- **WHEN** a client sends `GET /ui/realms/{realm}/saml/metadata`, `GET` or `POST /ui/realms/{realm}/saml/sso`, `GET /ui/realms/{realm}/saml/sso/init`, or `GET` or `POST /ui/realms/{realm}/saml/slo-idp`
- **THEN** the server answers `404`

#### Scenario: SMS routes are gone
- **WHEN** a client sends a request to `/ui/sms-challenge`, `/ui/required-action/ENROLL_PHONE_OTP`, or `/ui/admin/realms/{realm}/users/{id}/remove-phone`
- **THEN** the server answers `404`

#### Scenario: Device-fingerprint admin route is gone
- **WHEN** an authenticated admin sends `GET /admin/users/{id}/device-fingerprints` with a valid `X-Realm-ID`
- **THEN** the server answers `404`

#### Scenario: SAML SP routes still work
- **WHEN** a client requests the SP metadata or posts a valid response to the Assertion Consumer Service under `/ui/realms/{realm}/federation/saml/`
- **THEN** the server serves the request as it did before this change

### Requirement: Every admin operation has a REST route
Before the public gRPC API is removed, every admin operation it offered SHALL be available over REST under `/admin`, with authorization at least as strict as the gRPC handler's: `hearth.realm.admin`, system-realm write refusal, and the admin privilege ceiling on every change that grants or removes authority.

(Added during apply: sixteen operations — organization CRUD, group roles, role members, direct user permissions, extra org roles, the permission registry and audit integrity — existed only over gRPC.)

#### Scenario: Organization CRUD over REST
- **WHEN** a realm administrator calls `POST`, `GET`, `PATCH` and `DELETE` on `/admin/organizations[/{id}]`
- **THEN** each answers like the gRPC operation did, and a caller without `hearth.realm.admin` gets `403`

#### Scenario: Suspension is checked like deletion
- **WHEN** a sub-admin sets `status: suspended` on an organization whose member holds admin authority the sub-admin lacks
- **THEN** the server answers `403` and the organization stays active

#### Scenario: Grants never exceed the caller
- **WHEN** a sub-admin grants a permission, assigns a group role, or gives an extra org role that carries a permission the sub-admin does not hold
- **THEN** the server answers `403` and nothing is granted

### Requirement: No public gRPC listener
The server SHALL NOT open a gRPC listener for clients. The Raft peer listener (`cluster.peer_address`) is internal and stays.

#### Scenario: Single-node server opens only HTTP
- **WHEN** the server starts in single-node mode with a valid configuration
- **THEN** the only listening TCP port is the HTTP port

#### Scenario: Cluster peers still replicate
- **WHEN** a three-node experimental cluster starts
- **THEN** the nodes elect a leader and replicate a write over the peer transport

### Requirement: Removed configuration keys stop startup with a named error
The server SHALL refuse to start when the configuration contains a key of a removed feature. The error SHALL name the key, the feature, and the version that removed it.

#### Scenario: SMS config present
- **WHEN** `hearth.yaml` contains an `sms:` block
- **THEN** startup fails with an error that names `sms`, says SMS OTP was removed in 3.0.0, and the process exits with a non-zero status

#### Scenario: Each removed key is rejected
- **WHEN** `hearth.yaml` contains any of `server.grpc_port`, `server.grpc_bind_address`, `server.grpc_allow_plaintext`, `security.grpc`, `security.risk_scorer`, `realms.<name>.saml_service_providers`, `realms.<name>.fapi_profile`, a client `profile: fapi2`, or an `ip_reputation`, `email_reputation`, `bot_signal` or `tarpit` setting
- **THEN** startup fails with an error that names that key and its removed feature

### Requirement: Discovery advertises only kept features
The OpenID discovery document SHALL NOT advertise JARM, the FAPI profile, or SMS.

#### Scenario: JARM and FAPI fields are absent
- **WHEN** a client fetches `/.well-known/openid-configuration` for a realm
- **THEN** the document has no `fapi_profile` and no `authorization_signing_alg_values_supported` field, and `response_modes_supported` contains no `jwt`, `query.jwt`, `fragment.jwt` or `form_post.jwt`

#### Scenario: Kept features are still advertised
- **WHEN** a client fetches the same document
- **THEN** it still contains `pushed_authorization_request_endpoint`, `dpop_signing_alg_values_supported`, `device_authorization_endpoint`, and `code_challenge_methods_supported` with `S256`

### Requirement: The ROPC grant is not supported
The token endpoint SHALL refuse `grant_type=password` for every client.

#### Scenario: Password grant request
- **WHEN** any client, public or confidential, calls the token endpoint with `grant_type=password`, a username and a password
- **THEN** the server answers `400` with `unsupported_grant_type`, and issues no token

#### Scenario: Discovery does not list it
- **WHEN** a client fetches `/.well-known/openid-configuration`
- **THEN** `grant_types_supported` does not contain `password`

### Requirement: The step-up MFA grant is not supported
The token endpoints SHALL refuse `grant_type=urn:hearth:params:grant-type:step-up-mfa`. A user proves a second factor only in a browser ceremony (browser login, the authorization endpoint, or device approval), where passkeys work; no grant accepts a password at the token endpoint.

#### Scenario: Step-up grant request
- **WHEN** a client calls `/token` or `/realms/{realm}/token` with `grant_type=urn:hearth:params:grant-type:step-up-mfa`, an email, a password and a valid TOTP code
- **THEN** the server answers `400` with `unsupported_grant_type`, and issues no token

### Requirement: DPoP enforcement does not depend on FAPI
A client or agent that requires DPoP SHALL still get DPoP-bound tokens on every grant, with no FAPI profile in place.

#### Scenario: DPoP-required client without DPoP proof
- **WHEN** a client configured to require DPoP (`dpop_bound_access_tokens: true`) calls the token endpoint with the authorization code, client credentials, refresh token, JWT bearer, or device code grant, and sends no `DPoP` header
- **THEN** the server refuses the request with `invalid_dpop_proof` or `invalid_request`, and issues no token

### Requirement: Old backup archives still import
The backup importer SHALL accept an archive that contains `saml_service_providers.ndjson`. It SHALL skip that file and log a warning.

#### Scenario: Restore a v2 archive
- **WHEN** an operator restores a v2.0.x archive that contains `saml_service_providers.ndjson`
- **THEN** the restore succeeds, every other record is restored, and the log has one warning that names the skipped file
