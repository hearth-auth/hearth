## Why

A resource server that introspects user tokens needs a client in `introspection` or `decision` mode (`rbac-token-claims`, "Introspection is restricted to the token's audience"). Today only the admin API sets that mode. An operator who declares the resource server's client in `hearth.yaml` must also call `PATCH /admin/applications/{id}` after every fresh start, with an admin token of that realm. A realm declared in `hearth.yaml` has no such token at startup: the bootstrap token belongs to `dev-realm` or to the system realm, and the admin API checks the token against the realm in `X-Realm-ID`.

The full-stack demo shows the defect. Its Go backend introspects the SPA's tokens as the confidential client `notes-api`. The client is in `embedded` mode, so every introspection answers `{"active": false}` and the backend refuses every request. A first real-world integration copies this demo.

## What Changes

- An application in `hearth.yaml` takes a new key, `access_token_authorization`: `embedded` (default), `introspection` or `decision`. The spelling is the same as `trust_level` (`first_party`).
- `hearth.yaml` owns the mode of a YAML-declared application, as it owns `dpop_bound_access_tokens` and `jwks`. Every reconcile (startup and SIGHUP) applies the declared mode. An omitted key means `embedded`, so removing the key also removes the client's right to introspect every user token of the realm.
- The REST admin API (`PATCH /admin/applications/{id}`, through the engine gate in `update_client`) refuses a change to the mode of a YAML-declared application with `409`. A request that names the mode the client already has still succeeds, so a client that sends the whole application record can still change other fields. The admin console already refuses every edit of a YAML-declared application.
- **Breaking for a YAML-declared application whose mode an admin set through the API:** the first reconcile after the upgrade sets it back to `embedded`. Declare the mode in `hearth.yaml` instead.
- `examples/full-stack-demo/hearth.yaml` declares `notes-api` in `introspection` mode (in the demo-repair PR, after this one merges).

## Capabilities

### New Capabilities

### Modified Capabilities
- `rbac-token-claims`: "Every OAuth client has an access-token authorization mode" adds the `hearth.yaml` key, the YAML ownership rule and the `409` refusal.

## Impact

- `src/config/types.rs` (`ApplicationYamlConfig`), `src/identity/reconcile.rs` (`reconcile_applications`), `src/identity/engine/mod.rs` (`update_client` gate).
- `docs/guides/configuration-reference.md`, `hearth.maximal.yaml`, `docs/guides/rbac.mdx` (token authorization modes), `CHANGELOG.md`.
- No proto, storage-format or SDK change.
