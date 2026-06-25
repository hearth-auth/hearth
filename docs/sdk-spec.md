# Hearth SDK Specification

> This file is a redirect stub. The canonical SDK specification is at
> [`docs/specs/SDK.md`](specs/SDK.md).

See [`docs/specs/SDK.md`](specs/SDK.md) for the board-approved common contract all
Hearth client SDKs must satisfy (configuration, token verification, JWKS caching,
error types, session-version revocation, admin helpers).

## Available SDKs

All C1–C8 surface gaps have been closed. Every SDK now ships `verifyToken()`, `clientCredentials()`, `startDeviceFlow()`/`pollDeviceToken()`, and `requestMagicLink()` (or the language-idiomatic equivalent — see [§2.5 per-SDK symbol mapping](specs/SDK.md#25-per-sdk-symbol-name-mapping)).

| Language | Path | Status | C-series surface |
|----------|------|--------|-----------------|
| TypeScript / browser | [`sdks/typescript/`](../sdks/typescript/) | **Stable** | C2 complete |
| Node.js (server) | [`sdks/node/`](../sdks/node/) | **Stable** | C3 complete |
| Go | [`sdks/go/`](../sdks/go/) | **Stable** | C4 complete |
| PHP | [`sdks/php/`](../sdks/php/) | **Stable** | C5 complete |
| Python | [`sdks/python/`](../sdks/python/) | **Stable** | C6 complete |
| Rust | [`sdks/rust/`](../sdks/rust/) | **Stable** (git-only; crates.io pending) | C7 complete |
| Kotlin / JVM | [`sdks/kotlin/`](../sdks/kotlin/) | **Stable** | C8 complete |

Each SDK directory contains its own `README.md` with installation, configuration, and usage examples.
