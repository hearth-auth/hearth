## MODIFIED Requirements

### Requirement: Admin users, realms, clients, roles and groups
Every `AdminClient` SHALL provide at least these operations:

| Entity | Methods | Routes |
|---|---|---|
| Users | `createUser(params)`, `getUser(id)`, `updateUser(id, params)`, `deleteUser(id)`, `listUsers(options)`, `sendPasswordEmail(id)` | `POST /admin/users`, `GET /admin/users/{id}`, `PATCH /admin/users/{id}`, `DELETE /admin/users/{id}`, `GET /admin/users?limit=N&cursor=C`, `POST /admin/users/{id}/password-email` |
| Realms | `getRealm(id)`, `deleteRealm(id)` (archived realms only), `listRealms(options)` | `GET /admin/realms/{id}`, `DELETE /admin/realms/{id}`, `GET /admin/realms?limit=N&cursor=C` |
| OAuth clients | create, get, update, delete, list | `/admin/applications` |
| Roles | create, get, update, delete, list | `/admin/roles` |
| Groups | create, get, update, delete, list | `/admin/groups` |

- Realms are provisioned in `hearth.yaml` and reconciled at startup, not through the admin API. SDKs MUST NOT expose a `createRealm` method: the server answers `405 Method Not Allowed` for `POST /admin/realms` and `PATCH /admin/realms/{id}`.
- OAuth clients live at `/admin/applications`. The server has never served `/admin/clients`. The update verb is `PATCH`, not `PUT`.
- `POST /admin/applications` takes the proto `RegisterClientRequest`, the same body as `POST /clients`: `client_name`, and proto enum names for `trust_level` and `access_token_authorization`. An unknown key such as `name` is a `422`.
- `PATCH /admin/applications/{id}` takes `client_name`, with `trust_level` (`first_party`, `third_party`) and `access_token_authorization` (`embedded`, `introspection`, `decision`) as snake_case strings. It ignores unknown keys, so an SDK that sends `name` gets `200` and the client is not renamed.
- Every client route answers with the proto `OAuthClient`: `client_id`, `client_name`, `redirect_uris`, `grant_types`, `created_at`, and `access_token_authorization` as a proto enum name, omitted when it is `EMBEDDED`.
- No client route sends or reads `id` or `name`.
- `sendPasswordEmail(id)` returns the email `kind` that the server reports: `PASSWORD_EMAIL_KIND_SETUP` or `PASSWORD_EMAIL_KIND_RESET`.
- Role assignment is not CRUD-shaped: `POST /admin/users/{id}/roles` with a `{ "role_id": ..., "org_id"?: ... }` body creates an assignment, `GET /admin/users/{id}/roles` lists them, and `DELETE /admin/assignments/{id}` removes one.

#### Scenario: Users CRUD
- **WHEN** an application creates, reads, updates and deletes a user through `AdminClient`
- **THEN** each call succeeds against a live Hearth server

#### Scenario: No realm creation
- **WHEN** a developer looks for `createRealm` on any SDK's `AdminClient`
- **THEN** no such method exists

#### Scenario: Rename a client
- **WHEN** an application renames an OAuth client through `AdminClient`
- **THEN** the SDK sends `PATCH /admin/applications/{id}` with `client_name`, and the client is renamed
