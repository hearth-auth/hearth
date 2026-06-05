# Changelog

All notable changes to `@hearth/browser` and `@hearth/node` are documented here.

## [Unreleased]

### Added
- **`useClaims()` React hook** — returns the typed `Claims` object from the current access
  token, or `null` when unauthenticated. Subscribes to token-change events so silent refresh
  causes an automatic re-render (HEA-1301).
- **`useUser()` React hook** — convenience hook returning `{ sub, name, email, emailVerified,
  picture }` from the current access token, or `null` when unauthenticated (HEA-1301).
- **`HearthFacade.getClaims()`** — synchronous accessor returning a typed `Claims` instance
  decoded from the current token, or `null` when absent/malformed.
- **`HearthFacade.subscribe(callback)`** — wires up token-change notifications for React
  re-renders. Opt-in: pass `subscribe` to `createHearth()` options; existing integrations
  without it continue to work unchanged (HEA-1301).
- **`UserProfile` type** — exported interface for the object returned by `useUser()`.

### Changed
- SDK brought into conformance with the [Hearth SDK Common Specification](../../docs/sdk-spec.md).
- All 9 required error types from spec §5 are now exported.
- Full Claims API (spec §4) implemented on verified token objects.
- JWKS caching follows the 5-rule contract from spec §2.
- README updated with installation, quickstart, and troubleshooting sections (spec §10).
