## ADDED Requirements

### Requirement: SDKs validate tokens with a standard JOSE library
Each SDK SHALL verify token signatures, JWKS keys and claims through a widely used JOSE library that supports EdDSA/Ed25519. An SDK SHALL NOT contain its own signature-verification code.

#### Scenario: Ed25519 token validates
- **WHEN** an SDK validates a Hearth access token signed with Ed25519
- **THEN** the library verifies the signature, and the SDK returns the claims

#### Scenario: Tampered token fails
- **WHEN** an SDK validates a token whose payload was changed after signing
- **THEN** the SDK returns a validation error, and no claims

#### Scenario: Unsigned token fails
- **WHEN** an SDK validates a token whose header says `alg: none`
- **THEN** the SDK returns a validation error, and no claims

#### Scenario: No handwritten signature check remains
- **WHEN** the SDK source is searched for a direct Ed25519 verify call (`ed25519.Verify`, `Ed25519PublicKey.verify`, `sodium_crypto_sign_verify_detached`)
- **THEN** no call is found outside the JOSE library

### Requirement: Admin clients are generated from OpenAPI
Each SDK's admin API client SHALL be generated from `docs/api/openapi.json`. Handwritten code SHALL wrap it, not duplicate it.

#### Scenario: OpenAPI change reaches every SDK
- **WHEN** an admin endpoint is added to `docs/api/openapi.json` and the generators run
- **THEN** each SDK's generated client contains the new call, and CI fails if a committed client is stale

### Requirement: One shared conformance harness tests every SDK
One end-to-end harness SHALL run the same scenarios against every supported SDK, against a live Hearth server.

#### Scenario: Shared scenario fails in one SDK
- **WHEN** one SDK gives a different result from the others for a harness scenario
- **THEN** that SDK's CI job fails and names the scenario

#### Scenario: Server-issued token in every SDK
- **WHEN** the harness mints an access token from a live `--dev` server and gives it to each SDK
- **THEN** all four SDKs return the same subject, scopes and permissions
