## MODIFIED Requirements

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
