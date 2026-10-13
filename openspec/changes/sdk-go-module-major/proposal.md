## Why

`go get github.com/hearth-auth/hearth/sdks/go@latest` resolves to v1.6.11, not to the current v3 release. Go's module rules require a module whose major version is 2 or higher to end its path in `/vN`. The Go SDK's `go.mod` declares `github.com/hearth-auth/hearth/sdks/go` with no suffix, but its tags are `sdks/go/v3.x.y`. So Go ignores every v2 and v3 tag, and a Go user cannot install a current SDK. The first real-world integration hit this.

Nothing stops it from happening again: semantic-release bumps the major version from the commit messages, and nobody changes `go.mod` with it.

## What Changes

- The Go module path becomes `github.com/hearth-auth/hearth/sdks/go/v3`. The SDK's own imports, the examples and the docs use it.
- A new guard, `scripts/check-go-module-major.sh <version>`, refuses a version whose major does not match the module path: `/vN` for a major of 2 or higher, no suffix for 0 and 1. The Go SDK's semantic-release runs it as `verifyReleaseCmd`, so a release that would tag an uninstallable version fails before it tags. A self-test in CI proves that the guard can fail.
- **BREAKING** for Go importers: the import path changes. Go users could install only v1.6.11 before, so no user of a v2 or v3 Go SDK exists.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `sdk-support-contract`: the Go package name carries the `/vN` major suffix, and a Go SDK release whose major does not match the module path is refused.

## Impact

- `sdks/go/go.mod`, every `.go` file that imports the SDK, `examples/go-gin`, `examples/full-stack-demo/backend`.
- `sdks/go/.releaserc.json`, `scripts/check-go-module-major.sh`, `scripts/tests/check-go-module-major.test.sh`, `.github/workflows/ci.yml`, `.github/workflows/sdk-publish-go.yml`.
- Docs: `README.md`, `sdks/go/README.md`, `docs/guides/getting-started.mdx`, `docs/guides/sdks/*`, `docs/guides/permission-delivery.mdx`, `docs/guides/rbac.mdx`, `docs-site/src/pages/index.js`.
- Not in this change: the proto `go_package` options still name `github.com/hearthdb/...`, and `sdks/go/generated/hearth/authz/` has no proto source. No code imports those packages. `buf breaking` (`FILE_SAME_GO_PACKAGE`) refuses a `go_package` change, so they move with the next major version, which changes the module path again.
