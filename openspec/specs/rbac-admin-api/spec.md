# rbac-admin-api Specification

## Purpose
The admin HTTP API for permissions, roles, groups and assignments, its authorization, and the bootstrap seed data of a realm.
## Requirements
### Requirement: RBAC admin endpoints require an admin permission
Every RBAC admin endpoint SHALL require, in the caller's access token, either the endpoint's sub-admin permission or `hearth.admin`. The role, group, membership, assignment, role-member and direct-permission endpoints SHALL require `hearth.realm.admin`. `GET /admin/groups/{id}` and `GET /admin/groups/{id}/members` SHALL also accept `hearth.users.admin`. `GET /admin/users/{user_id}/effective-permissions` SHALL require `hearth.users.admin`. A caller without the required permission SHALL receive `403` with `{"error": "forbidden", "error_description": "<permission> or hearth.admin permission required"}` and no data.

#### Scenario: A non-admin calls an admin endpoint
- **WHEN** a user whose token lacks the required admin permission calls `GET /admin/roles`
- **THEN** the response is `403`
- **AND** the body discloses no role data

#### Scenario: A realm sub-admin manages roles
- **WHEN** a caller whose token holds `hearth.realm.admin` but not `hearth.admin` calls `GET /admin/roles`
- **THEN** the realm's roles are returned

#### Scenario: A user sub-admin reads a group
- **WHEN** a caller holding only `hearth.users.admin` calls `GET /admin/groups/{id}/members`
- **THEN** the members are returned
- **AND** the same caller gets `403` from `POST /admin/groups`

### Requirement: Every RBAC endpoint has a realm context
Every RBAC endpoint SHALL take its realm from the `X-Realm-ID` header. A request to `/admin/*` without `X-Realm-ID` SHALL be answered `400` with `{"error": "missing X-Realm-ID header"}`, before any authentication result. The bearer token SHALL belong to the realm the header names.

#### Scenario: An admin call without the header
- **WHEN** an admin calls `GET /admin/roles` with a valid token and no `X-Realm-ID`
- **THEN** the response is `400` with `missing X-Realm-ID header`

#### Scenario: An admin targets another realm
- **WHEN** an admin manages a realm other than the one its token was issued in
- **THEN** the request names the target realm in `X-Realm-ID`, and Hearth acts only on that realm

### Requirement: Role endpoints
Hearth SHALL serve role administration over HTTP:

| Method and path | Effect |
|-----------------|--------|
| `GET /admin/roles?cursor=...&limit=...` | List the realm's roles, cursor-paginated. |
| `POST /admin/roles` | Create a role from `name`, `description`, `permissions` and `parent_roles`. |
| `GET /admin/roles/{id}` | Fetch a role. |
| `PATCH /admin/roles/{id}` | Update the name, description, permissions or parents. |
| `DELETE /admin/roles/{id}` | Delete a role. |

#### Scenario: Create a role
- **WHEN** an admin posts `{ "name": "docs.editor", "description": "Edit docs.", "permissions": ["docs.view", "docs.edit"], "parent_roles": ["docs.viewer"] }` to `POST /admin/roles`
- **THEN** the role is created in the caller's realm

#### Scenario: Paginate roles
- **WHEN** an admin lists roles with a `limit` smaller than the number of roles
- **THEN** the response holds one page and a cursor for the next

### Requirement: A role in use is not deleted without cascade
`DELETE /admin/roles/{id}` SHALL fail with `409` `role_in_use` while the role has assignments (user or group, realm- or organization-scoped), is a parent of another role, or is held as an extra organization role. With `?cascade=true`, Hearth SHALL remove the assignments, the parent links and the extra organization-role rows in the same atomic batch as the role. The web console SHALL always cascade. The demotion ceiling SHALL cover everything a cascade removes.

#### Scenario: Delete an assigned role
- **WHEN** an admin deletes a role that is assigned to a user, without `cascade`
- **THEN** the response is `409` with `role_in_use`, and the role still exists

#### Scenario: Cascade delete
- **WHEN** an admin deletes the same role with `?cascade=true`
- **THEN** the role, its assignments and its parent links are removed together

### Requirement: Group endpoints
Hearth SHALL serve group administration over HTTP:

| Method and path | Effect |
|-----------------|--------|
| `GET /admin/groups?cursor=...&limit=...` | List the realm's groups, cursor-paginated. |
| `POST /admin/groups` | Create a group from `name`, `slug` and `description`. |
| `GET /admin/groups/{id}` | Fetch a group. |
| `PATCH /admin/groups/{id}` | Update the group's fields. |
| `DELETE /admin/groups/{id}` | Delete the group, cascading its memberships and its role assignments. |

A role name SHALL be unique in its realm. A group slug SHALL be URL-safe and unique in its realm.

#### Scenario: Create a group
- **WHEN** an admin posts `{ "name": "Engineering Leads", "slug": "leads", "description": "..." }` to `POST /admin/groups`
- **THEN** the group is created in the caller's realm

#### Scenario: A duplicate slug
- **WHEN** an admin creates a second group with slug `leads` in the same realm
- **THEN** the request is refused as a conflict

#### Scenario: Delete a group
- **WHEN** an admin deletes a group that has members and role assignments
- **THEN** its memberships and its assignments are removed with it

### Requirement: Group membership endpoints
Hearth SHALL serve group membership over HTTP:

| Method and path | Effect |
|-----------------|--------|
| `GET /admin/groups/{id}/members?cursor=...&limit=...` | List members: users and nested groups. |
| `POST /admin/groups/{id}/members` | Add a member. The body is `{"type": "user", "id": "user_..."}` or `{"type": "group", "id": "group_..."}`. |
| `DELETE /admin/groups/{id}/members/{member_id}?type=user` or `?type=group` | Remove a member. Without `type`, the member is a user. |

#### Scenario: Nest a group
- **WHEN** an admin posts `{"type": "group", "id": "group_..."}` to another group's members
- **THEN** the listed members of the outer group include the nested group

#### Scenario: Remove a nested group
- **WHEN** an admin sends `DELETE /admin/groups/{id}/members/{member_id}?type=group` for a nested group
- **THEN** the nested group is no longer a member

#### Scenario: Remove a user without a type
- **WHEN** an admin sends `DELETE /admin/groups/{id}/members/{member_id}` with no `type`
- **THEN** `member_id` is read as a user, and that user is removed

### Requirement: Role assignment endpoints
Hearth SHALL serve role assignment over HTTP:

| Method and path | Effect |
|-----------------|--------|
| `POST /admin/users/{user_id}/roles` | Assign a role to a user. |
| `GET /admin/users/{user_id}/roles` | List the user's assignments. |
| `POST /admin/groups/{group_id}/roles` | Assign a role to a group, with the same body as the user variant. |
| `DELETE /admin/assignments/{assignment_id}` | Remove an assignment, whether its subject is a user or a group. |
| `GET /admin/roles/{role_id}/members?cursor=...&limit=...` | List the subjects (users and groups) assigned the role. |

The assignment body SHALL be `{ "role_id": "role_..." }` for a realm-scoped assignment, or `{ "role_id": "role_...", "org_id": "<org_uuid>" }` for an organization-scoped one. A successful assignment SHALL answer `201`. A body with any other field SHALL be refused with `422`, and no assignment SHALL be created.

#### Scenario: An organization-scoped assignment
- **WHEN** an admin posts `{ "role_id": "role_...", "org_id": "<org_uuid>" }` to `POST /admin/users/{user_id}/roles`
- **THEN** the response is `201`
- **AND** the assignment applies only to tokens issued with that organization as `oid`

#### Scenario: Remove a group's assignment
- **WHEN** an admin sends `DELETE /admin/assignments/{assignment_id}` for an assignment whose subject is a group
- **THEN** the assignment is removed

#### Scenario: Who holds a role
- **WHEN** an admin calls `GET /admin/roles/{role_id}/members` for a role assigned to one user and one group
- **THEN** both subjects are listed

#### Scenario: An unknown body field is refused
- **WHEN** an admin posts `{ "role_id": "role_...", "scope": { "type": "org", "org_id": "org_..." } }` to `POST /admin/users/{user_id}/roles` or `POST /admin/groups/{group_id}/roles`
- **THEN** the response is `422`
- **AND** no assignment is created, realm-scoped or otherwise

### Requirement: Effective-permissions debug endpoint
`GET /admin/users/{user_id}/effective-permissions?org_id=...&scope=...` SHALL resolve and return what the user would receive in a token issued with those parameters. It is a support and debug aid.

#### Scenario: Preview an organization token
- **WHEN** an admin calls the endpoint with `org_id` naming an organization where the user holds an organization-scoped role
- **THEN** the response includes that role's permissions

### Requirement: Live permissions of the bearer token
`GET /v1/me/permissions` SHALL return the freshly resolved roles, groups and permissions of the bearer token: the token's live authority, not the user's. A third-party client's token SHALL read only what the claim profile releases to that client (by default no roles, groups or permissions). A scoped or delegated token SHALL read no more than it carries. An optional `scope` query parameter SHALL narrow the result further. The organization context SHALL be the token's `oid`; a token without `oid` resolves realm-scoped assignments only. An `org_id` query parameter that names an organization the user is not a member of SHALL be refused with `403`. A suspended or archived organization SHALL grant nothing. The request SHALL carry `Authorization: Bearer <access_token>` and `X-Realm-ID: <realm_uuid>`. The `200` response SHALL hold `roles`, `groups`, `permissions` and `scope`. A missing, invalid or expired token, a token that is not a user's token, and a token whose realm does not match `X-Realm-ID` SHALL get `401`. A missing `X-Realm-ID` SHALL get `400`.

#### Scenario: The endpoint matches the latest token
- **WHEN** a first-party user token issued without an organization context is used on `GET /v1/me/permissions` with no role change since issuance
- **THEN** the returned `permissions` equal the token's `permissions` claim

#### Scenario: No token
- **WHEN** the request has no `Authorization` header
- **THEN** the response is `401`

#### Scenario: A token from another realm
- **WHEN** a token issued in realm A is sent with `X-Realm-ID` naming realm B
- **THEN** the response is `401`

#### Scenario: The organization comes from the token
- **WHEN** a user holds a role scoped to organization O and calls the endpoint with a token whose `oid` is O
- **THEN** the response includes that role's permissions
- **AND** the same call with a token that has no `oid` does not include them

#### Scenario: A caller-chosen organization is refused
- **WHEN** a user who is not a member of organization O, but holds a role assignment scoped to O, calls `GET /v1/me/permissions?org_id=<O>`
- **THEN** the response is `403`
- **AND** no permission of that role is returned

### Requirement: Sub-admin grants never exceed the caller
A sub-admin, a caller that holds realm-scoped admin permissions but not `hearth.admin`, SHALL grant only permissions held in its own token's `permissions` claim. A sub-admin SHALL create or update only roles whose permission sets are subsets of its own permissions. A grant or a role definition that carries a permission the caller does not hold SHALL be refused with `403 Forbidden`. A caller that holds `hearth.admin` SHALL bypass this check. The ceiling SHALL apply to:

- `POST /admin/roles` and `PATCH /admin/roles/{id}`: the role's permission set MUST be a subset of the caller's permissions;
- `POST /admin/users/{id}/permissions`: the granted permission MUST be held by the caller;
- `POST /admin/organizations/{id}/members/{user_id}/roles` (an extra organization role): the role's permissions MUST be a subset of the caller's permissions, and the user MUST be a member of the organization (otherwise `409` with `not_a_member`).

#### Scenario: Indirect self-escalation
- **WHEN** a sub-admin holding `docs.edit` creates a role that contains `billing.admin`
- **THEN** the response is `403` and no role is created

#### Scenario: A superuser defines any role
- **WHEN** a caller holding `hearth.admin` creates a role that contains `billing.admin`
- **THEN** the role is created

#### Scenario: An extra organization role for a non-member
- **WHEN** an admin posts an extra organization role for a user who is not a member of that organization
- **THEN** the response is `409` with `not_a_member`, and no role is added

### Requirement: Sub-admins cannot demote a user who outranks them
A sub-admin MUST NOT demote, modify or sign out a user who holds an admin-grade permission (`hearth.admin`, `hearth.users.admin`, `hearth.clients.admin`, `hearth.realm.admin`, `hearth.agents.admin`) that the sub-admin lacks. The user's permissions SHALL count at realm level and in each of the user's organizations. Organization-scoped permissions SHALL count for every organization the user belongs to and for every organization named by one of the user's organization-scoped role assignments (direct or through a group) or direct grants. Operations that affect several users SHALL apply the check to each of them. The check SHALL cover:

- role unassignment, permission revocation, extra-role removal, group-member removal and group deletion;
- organization member removal (SCIM `PUT`/`PATCH /Groups`) and organization deletion (`DELETE /admin/organizations/{id}`, SCIM `DELETE /Groups`), for every affected member;
- a role update or deletion (`PATCH`/`DELETE /admin/roles/{id}`) that removes an admin permission from the role's transitive set, including a rename, for every holder of the role or of a role inheriting from it: directly, through a group, or as an extra organization role.

A caller holding `hearth.admin` SHALL bypass the check. The web console SHALL admit only `hearth.admin`. `hearth.yaml` reconciliation is operator-authoritative and SHALL be exempt.

#### Scenario: A user-admin removes a realm-admin's role
- **WHEN** a caller holding only `hearth.users.admin` unassigns a role from a user who holds `hearth.realm.admin`
- **THEN** the response is `403` and the assignment remains

#### Scenario: An organization-scoped admin permission counts
- **WHEN** a user holds `hearth.clients.admin` through an organization-scoped assignment and a sub-admin without it deletes that organization
- **THEN** the deletion is refused

### Requirement: Multi-user ceiling checks are bounded and fail closed
A ceiling check that affects several users SHALL resolve only the affected users who are among the realm's admin holders. An admin holder is every user reachable from a role whose transitive permissions include an admin-grade permission (by direct or group assignment at any scope, or as an extra organization role), plus every direct grantee of an admin-grade permission. Other affected users hold no admin permission and SHALL pass without resolution. The check SHALL fail closed with `503` past 100 000 affected users, 10 000 admin holders, or 50 000 permission resolutions.

#### Scenario: A group too large to check
- **WHEN** a sub-admin deletes a group whose transitive membership exceeds 100 000 users
- **THEN** the response is `503` and the group remains

### Requirement: RBAC errors use the shared envelope
Every RBAC endpoint SHALL return errors as `{ "error": "<code>", "error_description": "<human message>", ...extra }`. Extra fields MAY include `limit`, `limit_value`, `actual_value` and `remediation` for size errors, and `entity` and `path` for cycle errors.

#### Scenario: A cycle error
- **WHEN** an admin's role update would create a parent cycle
- **THEN** the response body carries `error` and `error_description`

### Requirement: Seed permissions
Every fresh realm SHALL have these permissions registered:

| Permission | Meaning |
|------------|---------|
| `hearth.admin` | Realm-level admin authority. Reserved; granted only through seed roles. |
| `hearth.users.admin` | Manage users, credentials, sessions and consents; sub-admin delegation for user management. |
| `hearth.clients.admin` | Manage OAuth clients and application registrations; sub-admin delegation for application management. |
| `hearth.realm.admin` | Manage realm settings, roles, groups, webhooks and audit logs; sub-admin delegation for realm configuration. |
| `hearth.agents.admin` | Manage agent identities, API keys and credential lifecycle. |
| `hearth.export` | Export and restore realm data; required in addition to an admin permission on every data-export and backup-restore endpoint. |
| `hearth.sv_feed` | Subscribe to the session-version delta feed. |
| `realm.read`, `realm.write`, `realm.admin` | Realm configuration read and write. |
| `org.read`, `org.write`, `org.admin`, `org.billing` | Organization-scoped administration. |
| `user.read`, `user.write`, `user.impersonate` | User administration. |

Operators extend this set through config or the admin API.

#### Scenario: A new realm's permission registry
- **WHEN** a realm is created
- **THEN** each permission in the table is registered in it

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
| `org.member` | `org.read` | — | `org.read` | Organization-scoped: one organization per assignment. |
| `org.admin` | `org.write`, `org.admin` | `org.member` | `org.read`, `org.write`, `org.admin` | Organization-scoped: one organization per assignment. |
| `org.owner` | `org.billing` | `org.admin` | `org.read`, `org.write`, `org.admin`, `org.billing` | Organization-scoped: one organization per assignment. |

The parent links SHALL be explicit in the seed data, so operators can see the full chain. Seeding SHALL be idempotent: re-running it on a realm that already holds seed state adds nothing and changes nothing, except that it restores a seed role's assignment scope (realm or organization) when that has drifted. Operators assign one of the `hearth.*.admin` roles instead of `realm.admin` to limit a service account or an operator to the endpoints it needs.

#### Scenario: Seeding twice
- **WHEN** the seed runs again on a realm that already has its seed roles
- **THEN** no role, permission or scope is duplicated or changed

#### Scenario: The organization role chain
- **WHEN** a user is assigned `org.owner` in an organization
- **THEN** the user resolves `org.read`, `org.write`, `org.admin` and `org.billing` in that organization

### Requirement: Default scope-to-permission mapping
Every fresh realm SHALL map OAuth scopes to permissions as follows:

| OAuth scope | Permissions admitted |
|-------------|----------------------|
| `openid` | no permission filter; identifier only |
| `profile` | no permission filter |
| `email` | no permission filter |
| `admin` | exactly `hearth.admin`, `realm.read`, `realm.write`, `realm.admin`, `user.read`, `user.write`, `user.impersonate` |
| `org` | exactly `org.read`, `org.write`, `org.admin`, `org.billing` |
| any other value | operator-defined in realm config |

A mapping SHALL be an exact list of permissions. `admin` does not admit the other `hearth.*` sub-admin permissions.

#### Scenario: The `admin` scope excludes sub-admin permissions
- **WHEN** a user holding `hearth.admin` and `hearth.users.admin` requests a token with `scope=admin`
- **THEN** the token's permissions include `hearth.admin` and not `hearth.users.admin`

#### Scenario: The `org` scope
- **WHEN** a user holding `org.read` and `docs.view` requests a token with `scope=org`
- **THEN** the token's permissions are `["org.read"]`

### Requirement: The first user of a realm becomes its admin
When the first user is created in a fresh realm, through onboarding, admin bootstrap or the migration importer, Hearth SHALL create a realm-scoped `realm.admin` assignment for that user. Later users SHALL get no default assignment; application flows such as invitation acceptance and self-registration decide their roles.

#### Scenario: First and second users
- **WHEN** two users are created in a fresh realm
- **THEN** the first holds `realm.admin` and the second holds no role assignment

### Requirement: Declarative RBAC configuration
Operators MAY declare roles, permissions, groups and scope mappings in realm YAML. Hearth SHALL reconcile the declaration at startup: a declared role or group is created when missing and updated when it has drifted, idempotently. A YAML-managed entity MUST NOT be edited through the admin API; the admin API SHALL refuse a mutation of one with a clear error that names the YAML source of truth.

#### Scenario: A declared role drifted
- **WHEN** a role in `hearth.yaml` differs from the stored role at startup
- **THEN** the stored role is updated to match the YAML

#### Scenario: An admin edits a YAML-managed role
- **WHEN** an admin sends `PATCH /admin/roles/{id}` for a role declared in `hearth.yaml`
- **THEN** the request is refused with an error that points to `hearth.yaml`

#### Scenario: A YAML-managed role cannot be deleted at runtime
- **WHEN** an admin sends `DELETE /admin/roles/{id}?cascade=true` for a role declared in `hearth.yaml`
- **THEN** the request is refused with an error that points to `hearth.yaml`
- **AND** the role and its assignments remain

#### Scenario: A YAML-managed group cannot be changed at runtime
- **WHEN** an admin updates or deletes, through the admin API or the console, a group declared in `hearth.yaml`
- **THEN** the request is refused with an error that points to `hearth.yaml`
- **AND** the group and its members remain

