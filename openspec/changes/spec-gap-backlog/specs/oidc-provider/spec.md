## ADDED Requirements

### Requirement: Rich authorization requests
Hearth SHOULD support OAuth 2.0 Rich Authorization Requests (RAR, RFC 9396). When it does, the authorization endpoint, PAR and the token endpoint SHALL accept the `authorization_details` parameter as RFC 9396 defines it, and discovery SHALL advertise `authorization_details_types_supported`.

#### Scenario: An authorization request with authorization details
- **WHEN** a client sends an authorization request that carries `authorization_details`
- **THEN** the issued access token reflects the granted `authorization_details`

#### Scenario: Discovery lists the supported types
- **WHEN** a client fetches `/.well-known/openid-configuration`
- **THEN** the document carries `authorization_details_types_supported`
