## ADDED Requirements

### Requirement: Scope mappings accept prefix globs
A scope-to-permission mapping SHALL accept globs as well as exact permission names. A glob SHALL be a literal string prefix plus dot followed by `*` (for example `docs.*`), or an exact match; never a regular expression. A glob SHALL admit every permission that starts with its prefix and a dot. Realm YAML SHALL let an operator map a scope name to a list of globs, for example `scopes: { docs: [docs.*] }`.

#### Scenario: A glob mapping narrows a token
- **WHEN** a realm maps scope `docs` to `docs.*`, a user holds `docs.view`, `docs.edit` and `billing.view`, and a token is requested with `scope=docs`
- **THEN** the token's permissions are `["docs.edit", "docs.view"]`

#### Scenario: A glob is not a regular expression
- **WHEN** a realm maps a scope to `docs.*`
- **THEN** the scope does not admit `docsx.view` or `docs`
