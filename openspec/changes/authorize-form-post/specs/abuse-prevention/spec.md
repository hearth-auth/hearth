## MODIFIED Requirements

### Requirement: A-47 Unknown fields refused on request bodies
Every request-body shape of the admin and authentication APIs SHALL refuse unknown fields, unless a documented forward-compatibility exception is recorded for that shape. The OAuth 2.0 and OIDC protocol endpoints (token, pushed authorization, revocation, introspection, the browser authorization endpoint `GET /authorize` and its form `POST`, and device authorization) are the recorded exceptions: RFC 6749 §3.1 and §3.2 require the server to ignore an unrecognized parameter. The bearer-authenticated JSON `POST /authorize` is a Hearth API, not the RFC 6749 authorization endpoint, so it refuses unknown fields like the other authentication APIs.

#### Scenario: An extension field slips into an admin body
- **WHEN** an admin request body carries a field its shape does not declare
- **THEN** the request is refused rather than the field being silently dropped

#### Scenario: A client update refuses unknown fields
- **WHEN** a `PATCH /admin/applications/{id}` body carries a field its shape does not declare
- **THEN** the request is refused

#### Scenario: A protocol endpoint ignores an unknown parameter
- **WHEN** a token request carries a parameter the token endpoint does not define
- **THEN** the parameter is ignored and the request is processed

#### Scenario: Device authorization ignores an unknown parameter
- **WHEN** a device authorization request carries a parameter RFC 8628 does not define
- **THEN** the parameter is ignored and a device code is issued
