## ADDED Requirements

### Requirement: Supported SDK set
The project SHALL publish and test exactly four SDKs: TypeScript (`@hearth-auth/sdk`), Go, Python and PHP. The Kotlin, Rust and Node (`@hearth-auth/node`) SDKs SHALL NOT be published or tested in CI.

#### Scenario: CI runs the supported set
- **WHEN** CI runs on a pull request that touches `sdks/`
- **THEN** the TypeScript, Go, Python and PHP SDK jobs run, and no Kotlin, Rust or Node SDK job exists

#### Scenario: Node features live in the TypeScript SDK
- **WHEN** a developer uses the Express/Fastify middleware, Next.js helpers, or discovery from `@hearth-auth/sdk`
- **THEN** each of these is available there, with the behaviour the Node SDK had

### Requirement: SDKs validate tokens with a standard JOSE library
Each SDK SHALL verify token signatures, JWKS keys and claims through a widely used JOSE library that supports EdDSA/Ed25519. An SDK SHALL NOT contain its own signature-verification code.

#### Scenario: Ed25519 token validates
- **WHEN** an SDK validates a Hearth access token signed with Ed25519
- **THEN** the library verifies the signature, and the SDK returns the claims

#### Scenario: Tampered token fails
- **WHEN** an SDK validates a token whose payload was changed after signing
- **THEN** the SDK returns a validation error, and no claims

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
