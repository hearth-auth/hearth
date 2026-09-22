## ADDED Requirements

### Requirement: Rotation revokes the retired key
Rotating a signing key SHALL stop that key from minting or validating new credentials. Rotation
is the documented remedy for a compromised key, so it MUST remedy it.

#### Scenario: A retired key forges an admin token
- **WHEN** a token is signed with a retired key after rotation
- **THEN** `GET /admin/users`, `/admin/realms`, `/admin/audit` and `POST /admin/users` all refuse it

#### Scenario: A second node holds a pre-rotation cache
- **WHEN** a key is rotated on one node
- **THEN** every other node stops publishing and trusting the pre-rotation key

### Requirement: The rotation grace period is validated
`token.signing_key_rotation_grace_period` SHALL be validated at start-up. A malformed or negative
value SHALL fail the boot rather than defaulting silently.

#### Scenario: A negative grace period is configured
- **WHEN** the configured grace period is negative or unparseable
- **THEN** the server refuses to start and names the key

### Requirement: Refresh does not re-mint revoked authority
A refresh SHALL re-resolve the subject's current claims. It MUST NOT copy the presented token's
RBAC claims and scope verbatim.

#### Scenario: A role is revoked and the token is refreshed
- **WHEN** a role is revoked and the holder refreshes
- **THEN** the new token does not carry the revoked role

### Requirement: Refresh rotation is atomic
Refresh-token rotation SHALL be a single atomic operation. Two concurrent presentations of one
token SHALL NOT both succeed.

#### Scenario: Two concurrent presentations of one refresh token
- **WHEN** the same refresh token is presented twice concurrently
- **THEN** exactly one presentation succeeds
- **AND** the other is refused as reuse

#### Scenario: A revocation races a rotation
- **WHEN** `POST /revoke` arrives while a rotation is in flight
- **THEN** the grant does not survive the revocation

### Requirement: Every refresh token belongs to a family
Every grant that mints a refresh token SHALL bind it to a grant family, so rotation and reuse
detection apply.

#### Scenario: A non-authorization-code grant mints a refresh token
- **WHEN** a device, step-up-MFA, ROPC or password-reset grant mints a refresh token
- **THEN** the token carries a family identifier
- **AND** it rotates and is subject to reuse detection

### Requirement: Revocation is consulted on every token-accepting path
The JTI blocklist, the DPoP kill-switch and realm status SHALL be consulted by every path that
accepts a token, on every node.

#### Scenario: A revoked delegation is introspected
- **WHEN** a revoked delegation token is presented to `introspect` or `decide`
- **THEN** the response is `active: false` with no permissions

#### Scenario: A sessionless token is revoked in a cluster
- **WHEN** a sessionless token is revoked on one node
- **THEN** every other node refuses it without waiting for a restart

### Requirement: Deleting a client revokes its tokens
Deleting an OAuth client SHALL revoke its outstanding refresh tokens. Revoking consent SHALL stop
that application refreshing.

#### Scenario: A confidential client is deleted
- **WHEN** a confidential client is deleted
- **THEN** its outstanding refresh tokens are revoked, not merely unbound from their auth gates

### Requirement: Every token-accepting path validates the token
Every RPC and handler that accepts a token SHALL call the same validator, and SHALL check the
token species.

#### Scenario: A refresh token is presented to `Decide`
- **WHEN** a refresh token, or a DPoP-bound token replayed as a plain bearer, is presented to the
  gRPC `Decide` RPC
- **THEN** it is refused

#### Scenario: `decide_token_permission` receives a refresh token
- **WHEN** `decide_token_permission` receives a token species the token endpoint refuses
- **THEN** it refuses it too

### Requirement: DPoP binding is enforced everywhere it is claimed
A `cnf`-bound token SHALL be refused as a plain bearer on `/admin/*`, SCIM and the gRPC admin
services.

#### Scenario: A stolen bound admin token is replayed as a bearer
- **WHEN** a `cnf`-bound admin token is replayed without a DPoP proof
- **THEN** both reads and writes are refused

### Requirement: `end_session` verifies its hint
`GET /end_session` SHALL verify the `id_token_hint` signature before acting on it.

#### Scenario: An unsigned `id_token_hint`
- **WHEN** an unauthenticated caller supplies an unverified or unsigned `id_token_hint`
- **THEN** no session is revoked
- **AND** no logout token is minted

### Requirement: `introspect` and `revoke` authenticate their caller
Every `introspect` and `revoke` route SHALL require client authentication and SHALL apply the
RFC 7662 audience restriction, in both the path form and the header form.

#### Scenario: An anonymous caller introspects a token
- **WHEN** an anonymous caller posts to `/realms/{name}/introspect` or `/realms/{name}/revoke`
- **THEN** the request is refused
- **AND** no subject is disclosed and no session is destroyed

#### Scenario: A negative introspection response
- **WHEN** introspection returns a negative result
- **THEN** the response includes `active: false`, per RFC 7662 §2.2

### Requirement: JWKS publishes only keys in use
JWKS SHALL publish only algorithms and keys Hearth signs with.

#### Scenario: A relying party reads JWKS
- **WHEN** a relying party reads the JWKS document
- **THEN** it contains no RS256 or ES256 key Hearth never signs with

### Requirement: `nbf` is enforced
Both hot-path validators SHALL enforce `TokenClaims.nbf`, or the documentation SHALL stop
claiming it.

#### Scenario: A token with a future `nbf`
- **WHEN** a token whose `nbf` is in the future is validated
- **THEN** it is refused

### Requirement: Server-side key material is encrypted at rest
Every private key written to storage SHALL be KEK-wrapped when a KEK is configured, and an
unenveloped key SHALL NOT be accepted.

#### Scenario: A KEK is configured
- **WHEN** a KEK is configured and the server writes the OIDC RSA private key
- **THEN** the key is written enveloped
- **AND** an unenveloped stored key is rejected or re-encrypted, not silently accepted
