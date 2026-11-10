## ADDED Requirements

### Requirement: The realm comes from the caller
Every admin operation SHALL derive the realm it acts on from the caller's authenticated identity.
A realm supplied in a query parameter, a path segment or a body field SHALL be compared to the
caller's realm and rejected on mismatch.

#### Scenario: A tenant admin names a peer realm in a query parameter
- **WHEN** a realm admin calls `POST /admin/backup` or `/admin/backup/restore` with another
  realm's ID in the query string
- **THEN** the request is refused with `403`

#### Scenario: A realm admin lists realms
- **WHEN** a realm admin calls `GET /admin/realms`
- **THEN** only realms that admin may see are returned
- **AND** the REST and gRPC responses match

### Requirement: Every admin handler carries a permission gate
Every authenticated admin handler SHALL enforce a per-handler permission check and the
`scoped_realm` guard.

#### Scenario: A sub-admin calls an ungated handler
- **WHEN** an authenticated sub-admin without the required permission calls any `/admin/*` handler
- **THEN** the request is refused

#### Scenario: The system operator calls a scoped handler
- **WHEN** the nil-UUID system realm identity calls a handler guarded by `scoped_realm`
- **THEN** the operator is not locked out of an operation the system realm is entitled to

### Requirement: An object outside the caller's realm is not found
An admin handler SHALL answer `404` for an object that is absent from the caller's realm.

#### Scenario: A realm admin requests a peer realm's object by ID
- **WHEN** a realm admin requests an object that exists only in another realm
- **THEN** the response is `404`, not `200`

### Requirement: Realm status is enforced on every plane
A suspended or archived realm SHALL be refused on every plane, including sessionless grants,
`introspect`, `decide`, SCIM, and Raft followers.

#### Scenario: A suspended realm's machine-to-machine plane
- **WHEN** a realm is suspended and a client-credentials or delegation grant is presented
- **THEN** no token is minted
- **AND** `introspect` and `decide` report the token as inactive

#### Scenario: A pre-shared SCIM token reads a suspended realm
- **WHEN** a SCIM bearer token reads a suspended or archived realm's user directory
- **THEN** the request is refused

#### Scenario: A follower serves a suspended realm
- **WHEN** a realm is suspended on the leader
- **THEN** every follower refuses that realm on its next request

### Requirement: The reserved system realm is read-only through public APIs
The reserved system realm SHALL reject role and group writes through public APIs, as the README
states.

#### Scenario: A role write targets the system realm
- **WHEN** a role or group write targets the reserved system realm through a public API
- **THEN** the write is refused

### Requirement: Cross-realm trust policy is consulted
A stored cross-realm trust policy SHALL be consulted before a cross-realm operation is permitted.

#### Scenario: A cross-realm operation is attempted
- **WHEN** a cross-realm operation is attempted
- **THEN** `check_cross_realm_policy` is called and its result is enforced

### Requirement: Challenge and ceremony state is realm-bound
A WebAuthn challenge SHALL be redeemable only in the realm that minted it, and only for the
ceremony type it was minted for.

#### Scenario: A challenge minted in realm A is presented in realm B
- **WHEN** a WebAuthn challenge minted in realm A is presented to realm B
- **THEN** the ceremony is refused

### Requirement: Realm routing headers are honoured
The `/realms/{name}/*` routes SHALL honour `X-Realm-ID` consistently with the tenant routing the
deployment guide prescribes.

#### Scenario: A request carries both a path realm and `X-Realm-ID`
- **WHEN** a `/realms/{name}/*` route receives an `X-Realm-ID` header
- **THEN** the header is honoured or the mismatch is refused, never silently ignored
