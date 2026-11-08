## MODIFIED Requirements

### Requirement: Seed roles
On realm creation Hearth SHALL write these roles:

| Role | Own permissions | Parent | Effective permissions | Notes |
|------|-----------------|--------|-----------------------|-------|
| `realm.admin` | every seed permission: `hearth.admin`, `hearth.users.admin`, `hearth.clients.admin`, `hearth.realm.admin`, `hearth.agents.admin`, `hearth.export`, `hearth.sv_feed`, `realm.read`, `realm.write`, `realm.admin`, `org.read`, `org.write`, `org.admin`, `org.billing`, `user.read`, `user.write`, `user.impersonate` | — | the same | Full realm admin. Realm-scoped. |
| `realm.member` | none | — | none | Application-customizable. Hearth never assigns it automatically. Realm-scoped. |
| `hearth.users.admin` | `hearth.users.admin` | — | the same | Sub-admin for users, credentials, sessions and consents. Realm-scoped. |
| `hearth.clients.admin` | `hearth.clients.admin` | — | the same | Sub-admin for OAuth clients and application registrations. Realm-scoped. |
| `hearth.realm.admin` | `hearth.realm.admin` | — | the same | Sub-admin for realm settings, roles, groups, webhooks and audit logs. Realm-scoped. |
| `hearth.agents.admin` | `hearth.agents.admin` | — | the same | Sub-admin for agent identities and credentials. Realm-scoped. |
| `hearth.export` | `hearth.export` | — | the same | Adds export rights to a sub-admin. Alone it grants nothing, because every export endpoint also requires an admin permission. Realm-scoped. |
| `org.member` | `org.read` | — | `org.read` | Organization-scoped: one organization per assignment. |
| `org.admin` | `org.write`, `org.admin` | `org.member` | `org.read`, `org.write`, `org.admin` | Organization-scoped: one organization per assignment. |
| `org.owner` | `org.billing` | `org.admin` | `org.read`, `org.write`, `org.admin`, `org.billing` | Organization-scoped: one organization per assignment. |

The parent links SHALL be explicit in the seed data, so operators can see the full chain. Seeding SHALL be idempotent: re-running it on a realm that already holds seed state adds nothing and changes nothing, except that it restores a seed role's assignment scope (realm or organization) when that has drifted. Operators assign one of the `hearth.*.admin` roles instead of `realm.admin` to limit a service account or an operator to the endpoints it needs. A custom role SHALL NOT hold a permission in the reserved `hearth.*` namespace, through the admin API, the admin UI, a migration or any other path. The seed roles are the only roles that hold one.

#### Scenario: Seeding twice
- **WHEN** the seed runs again on a realm that already has its seed roles
- **THEN** no role, permission or scope is duplicated or changed

#### Scenario: The organization role chain
- **WHEN** a user is assigned `org.owner` in an organization
- **THEN** the user resolves `org.read`, `org.write`, `org.admin` and `org.billing` in that organization

#### Scenario: A sub-admin gets export rights
- **WHEN** an operator assigns `hearth.users.admin` and `hearth.export` to a user
- **THEN** the user resolves exactly `hearth.users.admin` and `hearth.export`, and does not resolve `hearth.admin`

#### Scenario: A custom role asks for a reserved permission
- **WHEN** a caller creates or updates a custom role with a `hearth.*` permission
- **THEN** the request is refused, and no role is written or changed
