# Changelog

All notable changes to `@hearth-auth/browser` and `@hearth-auth/node` are documented here.

## [Unreleased]

### Removed
- **`admin.createRealm()` and the `CreateRealmParams` type** — realms are
  provisioned via `hearth.yaml` and reconciled at startup, not through the admin
  API. The server returns `405 Method Not Allowed` for `POST /admin/realms`, so
  this method never worked against a real server. Manage realms in `hearth.yaml`
  and restart Hearth to apply changes; read them with `getRealm`/`listRealms`
  (HEA-2171).

### Changed
- SDK brought into conformance with the [Hearth SDK Common Specification](../../docs/specs/SDK.md).
- All 9 required error types from spec §5 are now exported.
- Full Claims API (spec §4) implemented on verified token objects.
- JWKS caching follows the 5-rule contract from spec §2.
- README updated with installation, quickstart, and troubleshooting sections (spec §10).
