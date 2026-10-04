## MODIFIED Requirements

### Requirement: Non-reserved claim names are validated by tier
The validator SHALL accept a non-Tier-1 mapping target only when it is a Tier 2 name or a valid Tier 3 name, and SHALL refuse any other name at config load.

- **Tier 2 (overridable):** `roles`, `groups`, and the OIDC profile and contact claims `email`, `name`, `given_name`, `family_name`, `preferred_username`, `nickname`, `picture`, `website`, `gender`, `birthdate`, `locale`, `zoneinfo`, `updated_at`, `phone_number`, `address`. A mapping for one of these names overrides the default emission.
- **Tier 3 (custom):** either the short form `^[a-z][a-z0-9_]*$`, at most 64 characters, or the HTTPS-namespaced form `^https://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$`, at most 256 characters. An `http://` name SHALL be rejected. URN names (`urn:…`) are not supported.

#### Scenario: A short custom name
- **WHEN** a realm maps the claim `employee_id`
- **THEN** config load accepts it

#### Scenario: An HTTP namespace
- **WHEN** a realm maps the claim `http://acme.com/department`
- **THEN** config load fails and names the claim

#### Scenario: An HTTPS namespace
- **WHEN** a realm maps the claim `https://acme.com/department`
- **THEN** config load accepts it, and the token carries the claim under that exact name

#### Scenario: Regression — an HTTPS claim name with a space
- **WHEN** a realm maps the claim `https://acme.com/dept name`
- **THEN** config load fails and names the claim

### Requirement: Additional organization roles are validated when added
An organization membership MAY carry additional roles, served over REST as `GET` and `POST /admin/organizations/{id}/members/{user_id}/roles` and `DELETE /admin/organizations/{id}/members/{user_id}/roles/{role_name}`. When an additional role is added, the server SHALL check, at call time and not at config load, that the name resolves to a role in the realm. Adding one SHALL emit `OrgMemberAdditionalRoleAdded`, and removing one SHALL emit `OrgMemberAdditionalRoleRemoved`, each with the actor, organization, user and role name. An additional role SHALL contribute its permissions only when the token's `oid` names that organization.

#### Scenario: An unknown role name
- **WHEN** an admin adds `no_such_role` as an additional role of a membership
- **THEN** the request is refused with `404`

#### Scenario: An additional role outside its organization
- **WHEN** a member of organization X holds the additional role `auditor`, and a token is issued with `oid=Y`
- **THEN** the token carries none of `auditor`'s permissions

#### Scenario: Regression — adding an additional role is not audited
- **WHEN** an admin adds a role through `POST /admin/organizations/{id}/members/{user_id}/roles`
- **THEN** the audit log records `OrgMemberAdditionalRoleAdded` with the actor, organization, user and role name

### Requirement: Maintenance commands manage the registry and its orphans
The CLI SHALL provide:

| Command | Effect |
|---|---|
| `hearth config validate [file]` | pre-flight validation: name grammar, claim-name tiers, cross-references |
| `hearth rbac orphans list [--realm <id>]` | list orphaned runtime data |
| `hearth rbac orphans purge [--realm <id>] [--dry-run]` | delete orphaned assignments and extras, with audit events |

#### Scenario: A dry-run purge
- **WHEN** an operator runs `hearth rbac orphans purge --realm <id> --dry-run`
- **THEN** the command reports what it would delete, and deletes nothing

#### Scenario: Regression — purge does not find orphans
- **WHEN** a user in realm R holds the extra permissions `docs.archive`, which `hearth.yaml` no longer declares, and `docs.read`, which it declares, and the operator runs `hearth rbac orphans purge --realm <R>`
- **THEN** the `docs.archive` grant is deleted with an audit event, and the `docs.read` grant remains

### Requirement: Requested scopes must be declared by the client
When a client's `declared_scopes` is not empty, a requested scope that is not an OIDC standard scope and is not in `declared_scopes` SHALL fail with `invalid_scope`. OIDC standard scopes SHALL NOT need a declaration. A client with an empty `declared_scopes` MAY request any scope. The check SHALL run at the authorization endpoint and at the client-credentials, JWT-bearer and device-authorization grants. `declared_scopes` holds permission names, bundle names and OIDC standard scopes. Managed clients and clients created by Dynamic Client Registration follow the same rules for the same trust level.

#### Scenario: An undeclared bundle
- **WHEN** a client whose `declared_scopes` is `[read:docs, openid]` requests `write:docs`
- **THEN** the request fails with `invalid_scope`

#### Scenario: An undeclared OIDC scope
- **WHEN** a client whose `declared_scopes` is `[read:docs]` requests `openid read:docs`
- **THEN** `openid` is not refused for being undeclared

#### Scenario: A client with no declared scopes
- **WHEN** a client whose `declared_scopes` is empty requests `write:docs`
- **THEN** the scope is not refused for being undeclared

#### Scenario: Regression — an undeclared scope answers with the `invalid_scope` wire code
- **WHEN** a client whose `declared_scopes` is `[read:docs]` requests `write:docs` at the token endpoint
- **THEN** the response is `400` with `error` set to `invalid_scope`, not the generic `invalid input`

