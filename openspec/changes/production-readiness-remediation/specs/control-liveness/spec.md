## ADDED Requirements

### Requirement: Every parsed security key reaches a consumer
The server SHALL assert at start-up that every parsed security configuration key is read by a
consumer, and SHALL refuse to start when one is not.

#### Scenario: A security key has no consumer
- **WHEN** the server starts and a parsed security key is never read
- **THEN** the server refuses to start and names the key

#### Scenario: A new security key is added without a consumer
- **WHEN** a developer adds a security key with no consumer
- **THEN** a test fails

### Requirement: The known dead controls become live
Every control the audit found dead SHALL be enforced, or removed from the product and its
documentation. The list is `want_authn_requests_signed`, `sp_certificate_pem`,
`security.backup.verify_key`, `security.http2.*`, the WebAuthn user-verification knob, the three
documented WebAuthn realm policies, `storage.fsync`, `auth.token.magic_link_ttl`,
`auth.password_memory_cost` and `auth.password_time_cost`.

#### Scenario: An operator sets a documented security flag
- **WHEN** an operator sets any of the named keys
- **THEN** the value changes the server's behaviour
- **OR** the server refuses the key as unsupported

### Requirement: Documented abuse-prevention guards are constructed
Every abuse-prevention guard documented as "Shipped" SHALL be constructed on a production code
path, and its documented config keys SHALL parse.

#### Scenario: A documented guard's config key is set
- **WHEN** an operator sets a documented abuse-prevention config key
- **THEN** the server boots
- **AND** the guard runs on the request path

### Requirement: An unset environment reference fails closed
A `${VAR}` reference to an unset environment variable SHALL NOT become an accepted credential.

#### Scenario: A credential resolves to the empty string
- **WHEN** `${VAR}` is unset and the value is used as a credential
- **THEN** the server refuses to start, or refuses the credential
- **AND** `/metrics` does not open, and no client authenticates with an empty secret

### Requirement: Zero has one meaning per limiter
A rate-limit sentinel SHALL have one documented meaning across the whole configuration.

#### Scenario: A limiter is set to zero
- **WHEN** a rate limiter is configured with `0`
- **THEN** the meaning matches the documented meaning for every limiter in the file

#### Scenario: The `security:` block is omitted
- **WHEN** an operator writes a minimal config with no `security:` block
- **THEN** JWKS and discovery serve normally
- **AND** `reserved_slugs` and `slug_cooldown_days` keep their documented defaults

### Requirement: Misspelled keys are refused
A configuration or API payload containing an unrecognised key SHALL be refused, not silently
discarded.

#### Scenario: A misspelled claim release gate
- **WHEN** a claim release gate is misspelled
- **THEN** the configuration is refused
- **AND** the claim is not emitted to third-party clients

#### Scenario: `PATCH /ui/admin/realms/{realm}/config` omits a field
- **WHEN** the payload contains a misspelled key, or omits `default_required_actions`
- **THEN** the request is refused, and no field is silently cleared

### Requirement: `dev_mode` cannot be enabled from a config file
Development affordances SHALL be reachable only through an explicit, documented and loudly
announced path. `dev_mode` MUST NOT be settable from `hearth.yaml`.

#### Scenario: `dev_mode: true` appears in `hearth.yaml`
- **WHEN** a release binary loads a config file containing `dev_mode: true`
- **THEN** the server refuses to start, or ignores the key and warns loudly
- **AND** the production fail-closed gates stay armed

#### Scenario: The embedded library path is used
- **WHEN** Hearth is used as an embedded library
- **THEN** dev routes and hardcoded dev credentials are unreachable

### Requirement: `hearth config validate` matches the server
`hearth config validate` SHALL accept exactly the configurations the server starts with.

#### Scenario: A config the server refuses
- **WHEN** `hearth config validate` is run on a config the server refuses to start with
- **THEN** it reports the configuration invalid

#### Scenario: The admin UI writes `hearth.yaml`
- **WHEN** the admin UI writes a configuration
- **THEN** it is validated by the same validator the server uses

### Requirement: Documented configuration parses
Every configuration snippet in the reference documentation and the shipped example SHALL parse,
and every documented default SHALL match the code.

#### Scenario: An operator copies a documented snippet
- **WHEN** any snippet from `docs/specs/CONFIGURATION.md` or `hearth.example.yaml` is used
- **THEN** it parses

### Requirement: Public claims match the code
Every claim in the README, the CHANGELOG, `docs/STATUS.md` and the normative specs SHALL be true
of the code, or SHALL be withdrawn.

#### Scenario: A normative document describes a security property
- **WHEN** a document states a security property, such as per-realm encryption at rest
- **THEN** the code implements it
- **OR** the statement is corrected
