# Changelog

All notable changes to `@hearth-auth/node` are documented here.

## [Unreleased]

### Removed
- **`AdminClient.createRealm()`** — realms are provisioned via `hearth.yaml` and
  reconciled at startup, not through the admin API. The server returns
  `405 Method Not Allowed` for `POST /admin/realms`, so this method never worked
  against a real server. Manage realms in `hearth.yaml` and restart Hearth to
  apply changes; read them with `getRealm()`/`listRealms()` (HEA-2171).
