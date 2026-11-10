## MODIFIED Requirements

### Requirement: SDK packages and entry points
Each supported SDK SHALL ship under the package name and primary entry point below.

| SDK | Package | Role | Primary entry point |
|---|---|---|---|
| TypeScript | `@hearth-auth/sdk` | Browser SPA, Node.js server, Next.js | `HearthClient` |
| Go | module `github.com/hearth-auth/hearth/sdks/go/vN`, package `hearth` at `…/vN/hearth` | Server, service | `NewClient()` returning `*Client` |
| PHP | `hearth-auth/php-sdk` | Server (PSR-18) | `HearthClient` |
| Python | `hearth-sdk` | Server (sync HTTP) | `HearthClient` |

The TypeScript package SHALL serve browser and Node.js code. `HearthApiClient` is its lower-level client, kept for backwards compatibility.

In the Go module path, `N` SHALL be the major version of the release, as Go's module rules require for a major version of 2 or higher. A Go SDK release whose major version does not match the module path SHALL fail before it creates its tag.

#### Scenario: One TypeScript package for browser and server
- **WHEN** a developer installs `@hearth-auth/sdk`
- **THEN** `HearthClient` works in browser code and in Node.js code

#### Scenario: Go resolves the current major version
- **WHEN** the latest Go SDK tag is `sdks/go/v3.x.y`, and a developer runs `go get github.com/hearth-auth/hearth/sdks/go/v3@latest`
- **THEN** Go resolves that tag

#### Scenario: A major bump without a module path change
- **WHEN** the Go SDK's next release is `4.0.0`, and its module path still ends in `/v3`
- **THEN** the release fails before it creates the `sdks/go/v4.0.0` tag
