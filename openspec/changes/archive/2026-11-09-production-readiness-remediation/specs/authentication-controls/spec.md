## ADDED Requirements

### Requirement: The verified assertion is the consumed assertion
The SAML assertion consumer SHALL consume exactly the element whose signature it verified.

#### Scenario: A wrapped assertion is submitted
- **WHEN** a response contains a signed assertion and a second attacker-supplied assertion
- **THEN** the identity used is the one inside the signed element
- **AND** the response is rejected if the two do not agree

#### Scenario: An unsigned assertion is submitted
- **WHEN** a response carries an unsigned assertion
- **THEN** it is refused

### Requirement: SAML signed bindings are checked
The signed `<SubjectConfirmationData>` bindings SHALL be parsed and enforced: `Recipient`, the
bearer `NotOnOrAfter`, and `InResponseTo`.

#### Scenario: An assertion is replayed to the wrong recipient
- **WHEN** an assertion whose `Recipient` names a different service provider is submitted
- **THEN** it is refused

### Requirement: SAML endpoints are not signing oracles
No unauthenticated endpoint SHALL sign attacker-supplied content with a realm key.

#### Scenario: An anonymous caller reaches the SLO endpoint
- **WHEN** an anonymous caller posts to `/ui/realms/{realm}/saml/slo-idp`
- **THEN** no realm-signed response is produced for attacker-supplied content

### Requirement: SP-initiated SAML SSO issues a session
An assertion that validates SHALL produce a session, or SHALL be reported as unimplemented.

#### Scenario: A valid assertion reaches the SP consumer
- **WHEN** the SP assertion consumer validates a signed assertion
- **THEN** it creates a session
- **AND** it does not audit a completed login while creating none

### Requirement: A passkey satisfies MFA only when it proves user verification
A credential SHALL satisfy `mfa_required` only when it performed the user verification the realm
policy requires.

#### Scenario: A passkey with no user verification
- **WHEN** a passkey that did not prove user verification is presented and `mfa_required` is set
- **THEN** no session is issued
- **AND** the response directs the user to the MFA challenge

#### Scenario: A realm sets the user-verification policy
- **WHEN** an operator sets the WebAuthn user-verification policy on a realm
- **THEN** the value is enforced on every ceremony

### Requirement: MFA gates factor use, not factor enrolment
The `mfa_required` gate SHALL check that a second factor was used in this authentication, on
every login path including federation, ROPC and the direct browser login.

#### Scenario: A federated or ROPC login for an MFA-required user
- **WHEN** a user with `mfa_required` logs in through federation or ROPC
- **THEN** the second factor is demanded

#### Scenario: A user's only factor is SMS-OTP or email-OTP
- **WHEN** the enrolled factor is SMS-OTP or email-OTP
- **THEN** `create_session` and the direct browser login both see it and demand it

### Requirement: Enrolling a factor requires step-up
Enrolling a passkey or any second factor SHALL require a step-up authentication.

#### Scenario: A stolen session enrols a passkey
- **WHEN** a session that did not step up attempts passkey enrolment
- **THEN** the enrolment is refused

### Requirement: A one-time code is redeemable once
A TOTP, recovery, SMS-OTP or email-OTP code SHALL be redeemable exactly once, including under
concurrency.

#### Scenario: One code is submitted twice concurrently
- **WHEN** the same code is submitted twice at the same instant
- **THEN** exactly one submission succeeds

### Requirement: `mfa_methods` restricts factors
`mfa_methods` SHALL restrict which factors a user may enrol and present.

#### Scenario: A factor outside `mfa_methods` is enrolled
- **WHEN** a user attempts to enrol a factor the realm's `mfa_methods` excludes
- **THEN** the enrolment is refused

### Requirement: A password-reset token is invalidated by what supersedes it
A reset token SHALL stop working when the account's email changes, when the password changes out
of band, or when a newer reset token is issued.

#### Scenario: The account email changes after a reset is requested
- **WHEN** a reset is requested and the account's email is then changed
- **THEN** the earlier reset token is refused

#### Scenario: The new password fails validation
- **WHEN** a reset is submitted with a password that fails the policy
- **THEN** the token is not consumed and the link still works

### Requirement: Password recovery completes
Every advertised recovery flow SHALL complete, or SHALL be withdrawn from the product surface.

#### Scenario: A user requests a magic link
- **WHEN** a user requests a magic link and the SDKs post the documented grant
- **THEN** the mail is sent and a redemption route accepts it

#### Scenario: An admin requests a password reset
- **WHEN** an admin password reset is emailed
- **THEN** the link points at a route that exists

#### Scenario: An admin action reports a reset was sent
- **WHEN** an admin action reports "Reset email sent"
- **THEN** an email was sent

### Requirement: A password-only realm cannot silently discard reset mail
Production validation SHALL refuse a configuration in which a password-only realm can send no
reset email.

#### Scenario: `email.transport: log` on a password-only realm
- **WHEN** a password-only realm is configured with `email.transport: log` in production
- **THEN** validation refuses the configuration

### Requirement: Recovery credentials never reach the log
The setup token, reset links and verification tokens SHALL NOT be written to the operator log in
cleartext.

#### Scenario: First boot in production mode
- **WHEN** the server boots for the first time in production mode
- **THEN** the setup token is not written to the log at any level
- **AND** the startup banner's redaction claim is true

#### Scenario: A realm-admin onboarding invitation is sent
- **WHEN** an onboarding invitation is created
- **THEN** the password-reset URL is not written to the log

### Requirement: The client IP is derived from a trusted chain
`X-Forwarded-For` SHALL be parsed across every field line, SHALL tolerate port suffixes and IPv6
brackets, and SHALL be trusted only from a configured proxy.

#### Scenario: A client supplies its own `X-Forwarded-For` field line
- **WHEN** a client sends an `X-Forwarded-For` line and an append-style proxy adds another
- **THEN** the client-supplied line does not determine the client IP

#### Scenario: A hop carries a port suffix or IPv6 brackets
- **WHEN** a forwarded hop is `203.0.113.7:443` or `[2001:db8::1]:443`
- **THEN** it parses, and the client is not collapsed into the proxy's rate-limit bucket

### Requirement: Pre-auth hashing work is bounded
The login form SHALL be rate-shaped so an unauthenticated caller cannot drive unbounded Argon2id
work.

#### Scenario: A login flood from forged client IPs
- **WHEN** a caller floods the login form with per-request forged client IPs
- **THEN** the server sheds load and reports it, rather than degrading with green health checks

### Requirement: Argon2 parameters have a floor
Argon2id memory and time cost SHALL NOT be settable below the OWASP floor, from YAML or over the
wire. The documented global keys SHALL take effect.

#### Scenario: A sub-OWASP cost is configured
- **WHEN** a cost below the OWASP floor is set in YAML or over the wire
- **THEN** it is refused
- **AND** `auth.password_memory_cost` and `auth.password_time_cost` reach the base config

### Requirement: Account existence is not disclosed by timing
The login, registration and forgot-password paths SHALL do equivalent work whether or not the
account exists.

#### Scenario: An absent user attempts login in a realm with tuned Argon2
- **WHEN** login is attempted for an absent user in a realm that tuned its Argon2 parameters
- **THEN** the dummy hash uses that realm's parameters

#### Scenario: A locked account attempts login
- **WHEN** a locked account attempts login
- **THEN** it does not answer measurably faster than a nonexistent one

#### Scenario: A registered address is submitted to register or forgot-password
- **WHEN** a registered address is submitted
- **THEN** the response time does not distinguish it from an unregistered one

### Requirement: Failed authentication is audited
A failed second-factor verification, and a failed login for an unknown user, SHALL be audited.

#### Scenario: A second factor fails
- **WHEN** a second-factor verification fails
- **THEN** an audit event is written
