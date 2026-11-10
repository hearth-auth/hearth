## ADDED Requirements

### Requirement: No request reaches a panic
No request-supplied value SHALL reach a byte-offset slice, an unchecked index, or any other
panicking operation.

#### Scenario: A multi-byte value reaches the audit viewer
- **WHEN** an audit-log pill, a SCIM-injected field, a SAML `NameID` or an upstream `sub`
  contains multi-byte characters at the truncation offset
- **THEN** the value is truncated on a character boundary and the process survives

#### Scenario: An unvalidated phone number is masked
- **WHEN** `mask_phone` receives an unvalidated phone number
- **THEN** it does not panic

#### Scenario: A reversed scan window reaches storage
- **WHEN** a scan is requested with `start > end`, for example through `GET /admin/audit`
- **THEN** the request is refused and the process survives

### Requirement: Parsing is bounded
Every parser reachable from a request SHALL bound its recursion depth and its input size.

#### Scenario: A deeply nested SCIM filter
- **WHEN** a deeply nested filter is posted to `/Users` or `/Groups`
- **THEN** it is refused without exhausting the stack

### Requirement: Documented request limits are enforced
`operational.request_timeout_secs`, `max_connections` and `queue_depth` SHALL be enforced.

#### Scenario: A slow request exceeds the configured timeout
- **WHEN** a request runs past `operational.request_timeout_secs`
- **THEN** it is terminated at that limit

#### Scenario: Connections exceed `max_connections`
- **WHEN** more connections arrive than `max_connections` permits
- **THEN** the excess is refused

### Requirement: HTTP/2 caps apply to every listener
The `security.http2.*` rapid-reset caps SHALL be read and applied to the plaintext listener as
well as the TLS listener.

#### Scenario: A rapid-reset pattern arrives on the plaintext listener
- **WHEN** a rapid-reset stream pattern arrives on plaintext HTTP/2
- **THEN** the configured cap applies

### Requirement: Outbound fetches are guarded
Every server-side fetch of a URL that a client or realm admin can influence SHALL apply the SSRF
guard on every hop, cap redirects, and set a timeout.

#### Scenario: A registered URL redirects to a link-local address
- **WHEN** a federation JWKS, token or userinfo fetch, an OIDC back-channel logout, or a webhook
  delivery is redirected toward an internal or metadata address
- **THEN** the request is refused

#### Scenario: An upstream never responds
- **WHEN** an outbound fetch receives no response
- **THEN** it times out

### Requirement: URL-bearing client fields are validated on every write
`redirect_uris`, `frontchannel_logout_uri` and `backchannel_logout_uri` SHALL be validated on
registration and on every update, with the same rules.

#### Scenario: A client is registered and then patched
- **WHEN** a client is updated with a scheme, fragment, wildcard or loopback URI the register-time
  allowlist refuses
- **THEN** the update is refused

#### Scenario: A `javascript:` front-channel logout URI is rendered
- **WHEN** a front-channel logout URI is rendered into an `<iframe src>`
- **THEN** only an allowlisted scheme is emitted

### Requirement: Client authentication is required where it is advertised
Every grant and endpoint that discovery advertises as client-authenticated SHALL authenticate the
client, and SHALL accept the advertised authentication methods.

#### Scenario: The device grant is used
- **WHEN** either device-grant endpoint is called
- **THEN** the client is authenticated, per RFC 8628 §3.4

#### Scenario: `client_secret_basic` is used on `client_credentials`
- **WHEN** a client authenticates with `client_secret_basic` on the `client_credentials` grant
- **THEN** the credentials are read from the `Authorization` header

### Requirement: Advertised capabilities are reachable
Every capability advertised in discovery metadata, documentation or the admin UI SHALL be
reachable, or SHALL be withdrawn from that surface.

#### Scenario: An integrator builds against `private_key_jwt`
- **WHEN** discovery advertises `private_key_jwt`, the `jwt-bearer` grant or FAPI 2.0 Advanced
- **THEN** a configuration surface exists to write the `assertion_public_key` they read

#### Scenario: An admin opens the Identity Providers list
- **WHEN** an admin clicks a link on the Identity Providers list
- **THEN** the page loads

#### Scenario: A realm registers a client dynamically
- **WHEN** `POST /realms/{realm}/register` issues a `client_id`
- **THEN** the token endpoint can parse it
- **AND** the requested grant types are honoured or refused explicitly

### Requirement: Federation binds to the realm it started in
A federation flow SHALL resolve the realm the login started in, and SHALL send a realm-scoped
`redirect_uri` matching the callback URL the admin UI publishes.

#### Scenario: A confirm-to-link flow completes in a non-default realm
- **WHEN** a federation login starts in a non-default realm and reaches confirm-to-link
- **THEN** the flow resolves that realm

### Requirement: Upstream tokens are validated per OIDC Core
An upstream ID token with a multi-valued `aud` SHALL be checked for `azp`, per OIDC Core 3.1.3.7.

#### Scenario: A multi-valued `aud` arrives
- **WHEN** an upstream ID token carries multiple audiences
- **THEN** `azp` is verified

### Requirement: Account linking respects policy
`validate_magic_link` and every automatic linking path SHALL consult `RegistrationPolicy`, and
`link_existing_accounts: auto` SHALL disclose its takeover risk where the operator sets it.

#### Scenario: A magic link resolves to an unknown address
- **WHEN** `validate_magic_link` receives an address with no account
- **THEN** the registration policy decides whether an account is created

### Requirement: Secrets are drawn without bias and at full strength
Every secret-shaped value SHALL be drawn without modulo bias and SHALL carry at least 128 bits of
entropy.

#### Scenario: A device user code is generated
- **WHEN** a device user code is drawn
- **THEN** the draw is unbiased
- **AND** the approval endpoint enforces an attempt limit and is rate-shaped

#### Scenario: A PAR request_uri or a ticket value is generated
- **WHEN** a PAR `request_uri`, consent ticket, federation ticket, `RelayState` or session ID is
  generated
- **THEN** it carries at least 128 bits of entropy

### Requirement: Secret comparisons are constant time
Every comparison of a secret-shaped value SHALL be constant time.

#### Scenario: A client secret or token is compared
- **WHEN** a secret-shaped value is compared
- **THEN** a constant-time comparison is used

#### Scenario: Client authentication is attempted for an unregistered client
- **WHEN** authentication is attempted for a client that is not a registered confidential client
- **THEN** equivalent work is performed, so client existence and type do not leak by timing

### Requirement: Unbounded key spaces are reclaimed
Every key space a request can grow SHALL have a reclamation path and a bound.

#### Scenario: An unauthenticated caller writes to a growable key space
- **WHEN** an unauthenticated or unrate-limited request writes to a SAML, nonce, advisory-lock,
  session-family or revoked-JTI key space
- **THEN** the space is bounded and reclaimed

### Requirement: Webhook deliveries are replay-resistant and bounded
A webhook signature SHALL carry a timestamp and a replay window, and deliveries SHALL have a
global concurrency bound.

#### Scenario: A delivery is replayed
- **WHEN** a signed webhook delivery is replayed outside the window
- **THEN** the receiver can reject it
