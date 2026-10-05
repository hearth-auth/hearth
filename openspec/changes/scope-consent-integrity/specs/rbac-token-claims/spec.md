## ADDED Requirements

### Requirement: The organization context comes from the authorization request
`/authorize` SHALL accept an optional `organization` parameter that holds an organization ID or slug of the realm, on every authorization surface: the browser query, JAR, PAR, and `/authorize` over JSON through a pushed `request_uri`. The server SHALL accept it only when the organization is `Active` and the signed-in user holds an active membership in it. Any other case SHALL be refused with one error, `access_denied`, with one fixed `error_description`, so the response does not tell an unknown organization from a missing membership. The authorization code SHALL store the organization ID, and the access token, the refresh token and the ID token SHALL carry it as `oid`. Permission resolution for the token SHALL use that organization. A `refresh_token` grant SHALL keep `oid`, SHALL resolve permissions in that organization, and SHALL fail with `invalid_grant` when the organization is no longer `Active` or the user is no longer a member. Without the parameter, the flow SHALL stay in realm context and the token SHALL carry no `oid`.

#### Scenario: A member signs in to an organization
- **WHEN** a user with an active membership in organization `acme` completes an authorization-code flow with `organization=acme`
- **THEN** the access token and the ID token carry `oid` equal to `acme`'s ID, and the access token carries the user's `acme`-scoped role permissions

#### Scenario: A non-member names an organization
- **WHEN** a user who is not a member of `acme` sends `organization=acme`, and another request names an organization that does not exist
- **THEN** both are refused with `access_denied` and the same `error_description`

#### Scenario: Membership ends before a refresh
- **WHEN** a refresh family was issued with `oid` for `acme`, and the user's membership in `acme` is removed
- **THEN** the next refresh fails with `invalid_grant`
