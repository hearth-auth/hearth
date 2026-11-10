## 1. Tests first (red)

- [x] 1.1 `tests/yaml_access_token_authorization.rs`: a YAML application with `access_token_authorization: introspection` is created in `introspection` mode and introspects another client's user token (`active: true`); the same application without the key does not (`active: false`).
- [x] 1.2 Same file: reconcile applies a changed mode (`introspection` → `decision`), and an omitted key sets `embedded` again.
- [x] 1.3 Same file: config load refuses `access_token_authorization: INTROSPECTION` and an unknown value.
- [x] 1.4 Same file: `PATCH /admin/applications/{id}` with a different mode on a YAML-declared application is `409` and names `hearth.yaml`; the mode does not change. The same mode is `200`. The engine's `update_client` refuses a different mode with `YamlManagedResource`.
- [x] 1.5 Run the file: it fails to compile or fails (red).

## 2. Implementation

- [x] 2.1 `ApplicationYamlConfig.access_token_authorization: Option<AccessTokenAuthorization>`, documented.
- [x] 2.2 `reconcile_applications`: pass the mode (default `embedded`) to `import_client`, and to `update_client_from_config` when it changed.
- [x] 2.3 `update_client`: refuse a changed mode on a YAML-managed client with `YamlManagedResource`.
- [x] 2.4 Run the new tests and `tests/yaml_managed_client_credentials.rs`, `tests/ga_introspection_audience.rs` and `tests/realm_reconciliation.rs` (green).

## 3. Docs and close-out

- [x] 3.1 `docs/guides/configuration-reference.md` row, `hearth.maximal.yaml` entry (`tests/config_maximal_coverage.rs`), `docs/guides/rbac.mdx` token-authorization-mode text.
- [x] 3.2 Update the doc comments that say only an admin sets the mode (`may_introspect_unbound_user_token`, `tests/ga_introspection_audience.rs` header).
- [x] 3.3 `CHANGELOG.md`: `Added` (the YAML key) and `Changed` (YAML owns the mode; the admin API refuses a change with `409`).
- [x] 3.4 `make check` and `make test-detached`.
