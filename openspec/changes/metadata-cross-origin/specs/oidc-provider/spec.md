## ADDED Requirements

### Requirement: Public metadata answers cross-origin reads
Hearth SHALL send `Access-Control-Allow-Origin: *` on every response of these routes, so that a browser page on any origin can read them:

- `/.well-known/openid-configuration` and `/realms/{realm}/.well-known/openid-configuration`
- `/.well-known/jwks.json`, `/jwks`, `/certs` and `/realms/{realm}/.well-known/jwks.json`
- `/.well-known/oauth-protected-resource`

Hearth SHALL NOT send `Access-Control-Allow-Credentials` on these responses. Hearth SHALL NOT add `Access-Control-Allow-Origin: *` to any other route.

#### Scenario: An SPA on another origin reads the realm JWKS
- **WHEN** a page on `https://app.example.com` sends `GET /realms/acme/.well-known/jwks.json` to Hearth on another origin
- **THEN** the response carries `Access-Control-Allow-Origin: *` and no `Access-Control-Allow-Credentials`

#### Scenario: An SPA on another origin reads discovery
- **WHEN** a page on another origin sends `GET /realms/acme/.well-known/openid-configuration`
- **THEN** the response carries `Access-Control-Allow-Origin: *`

#### Scenario: A credentialed endpoint stays closed
- **WHEN** a page on another origin sends `GET /userinfo` with an `Origin` header
- **THEN** the response carries no `Access-Control-Allow-Origin`
