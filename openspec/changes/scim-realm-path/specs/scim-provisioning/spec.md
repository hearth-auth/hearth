## ADDED Requirements

### Requirement: SCIM under the realm path

Hearth SHALL serve SCIM 2.0 at `/realms/{realm_name}/scim/v2`, where `{realm_name}` is the realm's name. Every SCIM endpoint SHALL be available under this base: `/Users`, `/Users/{id}`, `/Groups`, `/Groups/{id}`, `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas`.

The path SHALL select the realm. A realm-path request SHALL NOT need an `X-Realm-ID` header. When a realm-path request carries `X-Realm-ID`, the header MUST name the same realm as the path. Otherwise Hearth SHALL refuse the request with `400` and the error `realm_mismatch`, before any credential check. When `{realm_name}` names no realm, Hearth SHALL answer `404`.

A realm-path request SHALL authenticate exactly as a `/scim/v2` request for the same realm does. A realm with a SCIM provisioning token SHALL accept that token. A realm without one SHALL accept an admin access token issued by that realm. A credential of one realm SHALL NOT act on another realm through that realm's path: Hearth SHALL answer `401`. A DPoP-bound access token SHALL need a valid DPoP proof for the realm-path URL, as on `/scim/v2`.

The URLs that SCIM writes SHALL use the base path of the request. A resource's `meta.location` and the `Location` header of a create SHALL start with `/realms/{realm_name}/scim/v2` on a realm-path request, and with `/scim/v2` on a `/scim/v2` request.

Hearth SHALL keep serving SCIM at `/scim/v2`, where the `X-Realm-ID` header selects the realm.

#### Scenario: An IdP provisions with the realm's provisioning token

- **WHEN** realm `acme` has a SCIM provisioning token
- **AND** a client sends `POST /realms/acme/scim/v2/Users` with that token and no `X-Realm-ID` header
- **THEN** Hearth answers `201`
- **AND** the user exists in realm `acme`
- **AND** `meta.location` and the `Location` header are `/realms/acme/scim/v2/Users/{id}`
- **AND** a `GET` of that location with the same token answers `200` with the same user

#### Scenario: An admin provisions with an admin access token

- **WHEN** realm `acme` has no SCIM provisioning token
- **AND** a user of `acme` who holds the `realm.admin` role sends `POST /realms/acme/scim/v2/Users` with their access token and no `X-Realm-ID` header
- **THEN** Hearth answers `201`
- **AND** the user exists in realm `acme`

#### Scenario: The header names another realm

- **WHEN** a client sends `POST /realms/acme/scim/v2/Users` with `X-Realm-ID` set to the ID of realm `globex`
- **THEN** Hearth answers `400` with the error `realm_mismatch`
- **AND** no user is created in either realm

#### Scenario: The realm name is unknown

- **WHEN** a client sends `GET /realms/no-such-realm/scim/v2/Users`
- **THEN** Hearth answers `404`

#### Scenario: A provisioning token is used on another realm's path

- **WHEN** a client sends `POST /realms/globex/scim/v2/Users` with the SCIM provisioning token of realm `acme`
- **THEN** Hearth answers `401`
- **AND** no user is created

#### Scenario: An admin token is used on another realm's path

- **WHEN** a client sends `POST /realms/globex/scim/v2/Users` with an admin access token issued by realm `acme`
- **THEN** Hearth answers `401`
- **AND** no user is created

#### Scenario: A DPoP-bound token is replayed as a plain Bearer

- **WHEN** a client sends `GET /realms/acme/scim/v2/Users` with a DPoP-bound access token of `acme` and no DPoP proof
- **THEN** Hearth answers `401`

#### Scenario: The header mount still works

- **WHEN** a client sends `POST /scim/v2/Users` with `X-Realm-ID` set to the ID of realm `acme` and the realm's provisioning token
- **THEN** Hearth answers `201`
- **AND** `meta.location` is `/scim/v2/Users/{id}`
