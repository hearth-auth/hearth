## ADDED Requirements

### Requirement: The `/ui` tree carries the API router's guards
The web router SHALL inherit the `Host` allowlist, the per-IP request-rate cap, the JSON depth
limit, the body limit and the request-duration metric.

#### Scenario: A request arrives with a disallowed `Host`
- **WHEN** a request for a `/ui/*`, admin-login or consent route carries a `Host` outside the
  allowlist
- **THEN** it is refused, as it is on the API surface

#### Scenario: A client floods the HTML surface
- **WHEN** a client exceeds the per-IP rate cap on login, register, reset, consent or admin CRUD
- **THEN** it receives `429`

#### Scenario: A deeply nested JSON body reaches a web-UI endpoint
- **WHEN** a parse-bomb body is posted to a web-UI JSON endpoint
- **THEN** the depth guard refuses it

#### Scenario: Prometheus scrapes request duration
- **WHEN** `/metrics` is scraped after `/ui/*` traffic
- **THEN** `hearth_http_request_duration_seconds` includes those routes

### Requirement: Every state-changing UI route verifies a CSRF token
Every `/ui` mutation and every required-action mutation SHALL verify a CSRF token that an
attacker cannot supply.

#### Scenario: A cross-origin form POST reaches an admin mutation
- **WHEN** a top-level form POST from a sibling host targets an `/ui/admin` mutation
- **THEN** it is refused for a missing or invalid CSRF token

#### Scenario: A sibling host plants a `Domain`-scoped CSRF cookie
- **WHEN** two `hearth_ui_csrf` cookies are present in the request header
- **THEN** the check does not compare an attacker-chosen value to itself

#### Scenario: A password is changed through the required-action route
- **WHEN** `POST /required-action/UPDATE_PASSWORD` is called
- **THEN** a CSRF token is verified
- **AND** the current password is required

### Requirement: Every cookie carries the attributes its content requires
Every cookie carrying authentication or authorization state SHALL be issued with `Secure`,
`HttpOnly` and an appropriate `SameSite` on every code path.

#### Scenario: The MFA-state cookie is issued
- **WHEN** `hearth_ui_sms_mfa` or `hearth_ui_flash` is issued
- **THEN** it carries `Secure`, as the session and CSRF cookies do

### Requirement: Browser-facing HTML carries security headers
Every browser-facing HTML response, on either router, SHALL carry a CSP, `X-Frame-Options` or
`frame-ancestors`, and a `Cache-Control` directive.

#### Scenario: An unauthenticated caller loads `/docs` or `/end_session`
- **WHEN** `GET /docs` or `GET /end_session` returns HTML
- **THEN** the response carries the same header set as the `/ui` tree

#### Scenario: `/docs` loads its assets
- **WHEN** `GET /docs` renders Swagger UI
- **THEN** its assets are served from the same origin, or carry Subresource Integrity

### Requirement: HSTS is emitted or the operator is told to emit it
HSTS SHALL be emitted in every deployment shape where the documentation claims it, including
proxy-terminated TLS. Where Hearth cannot emit it, the hardening guide SHALL tell the operator to
set it at the proxy.

#### Scenario: TLS is terminated by a reverse proxy
- **WHEN** Hearth runs behind a TLS-terminating reverse proxy
- **THEN** HSTS is emitted, or the hardening guide states that the proxy must set it

### Requirement: Hearth's CSP does not break Hearth's own flows
The `/ui` Content-Security-Policy SHALL permit the SAML HTTP-POST binding Hearth emits.

#### Scenario: A SAML HTTP-POST binding is rendered
- **WHEN** Hearth renders its SAML HTTP-POST binding form
- **THEN** the auto-submit runs and a manual submit reaches its destination

### Requirement: A partial config apply is refused
The admin config editor SHALL apply a configuration completely or not at all, and SHALL NOT
report success for a partial apply.

#### Scenario: A posted config omits existing realms
- **WHEN** an operator posts a config that does not re-list every existing realm
- **THEN** no realm is archived as a side effect
- **AND** the response does not report `{"ok":true}` for a partial apply

### Requirement: Unauthenticated surfaces do not enumerate tenants
A pre-auth `/ui/realms/{realm}/*` response SHALL NOT distinguish a real realm from an absent one,
and SHALL be rate-limited.

#### Scenario: An anonymous caller probes realm names
- **WHEN** an anonymous caller requests a real and an absent realm
- **THEN** the status code and body length do not distinguish them
- **AND** the oracle is rate-limited

### Requirement: Operator-pointed and reflected content is validated
Content served from an operator-pointed file, and content reflected from a request header, SHALL
be validated before it reaches an unauthenticated client.

#### Scenario: `/ui/static/theme.css` is requested
- **WHEN** an unauthenticated client requests `/ui/static/theme.css`
- **THEN** the content type and size are validated

#### Scenario: SAML IdP metadata is requested with `X-Forwarded-Host`
- **WHEN** `onboarding.base_url` is unset and metadata is requested with `X-Forwarded-Host`
- **THEN** the `entityID` and endpoint URLs are not derived from the untrusted header
