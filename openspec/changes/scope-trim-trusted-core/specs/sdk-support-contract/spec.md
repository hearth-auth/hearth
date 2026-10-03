## ADDED Requirements

### Requirement: Supported SDK set
The project SHALL publish and test exactly four SDKs: TypeScript (`@hearth-auth/sdk`), Go, Python and PHP. The Kotlin, Rust and Node (`@hearth-auth/node`) SDKs SHALL NOT be published or tested in CI.

#### Scenario: CI runs the supported set
- **WHEN** CI runs on a pull request that touches `sdks/`
- **THEN** the TypeScript, Go, Python and PHP SDK jobs run, and no Kotlin, Rust or Node SDK job exists

#### Scenario: Node features live in the TypeScript SDK
- **WHEN** a developer uses the Express/Fastify middleware, Next.js helpers, or discovery from `@hearth-auth/sdk`
- **THEN** each of these is available there, with the behaviour the Node SDK had
