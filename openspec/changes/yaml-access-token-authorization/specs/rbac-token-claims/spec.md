## MODIFIED Requirements

### Requirement: Every OAuth client has an access-token authorization mode
Every OAuth client SHALL carry an `access_token_authorization` field that decides which RBAC claims the issued token embeds and how resource servers obtain RBAC data:

| Mode | Enum value | RBAC claims in the JWT | Live RBAC call |
|------|------------|------------------------|----------------|
| `embedded` | `EMBEDDED` (default) | `roles`, `groups`, `permissions` | none |
| `introspection` | `INTROSPECTION` | none | `POST /realms/{realm}/introspect` |
| `decision` | `DECISION` | none | `POST /oauth/authorize` |

`embedded` MUST be the mode of every client whose `access_token_authorization` is omitted. An admin SHALL set the mode of a client registered at runtime through the admin API, at registration (`POST /admin/applications`) or later (`PATCH /admin/applications/{id}`).

An operator SHALL set the mode of an application declared in `hearth.yaml` with the application's `access_token_authorization` key: `embedded`, `introspection` or `decision`. `hearth.yaml` SHALL own that mode. Every reconcile SHALL apply the declared mode, and SHALL apply `embedded` when the key is omitted. Config load SHALL refuse any other value. The admin API SHALL refuse a request that changes the mode of a `hearth.yaml`-declared application with `409`, and SHALL leave the client unchanged. A request that names the mode the client already has SHALL NOT be refused for that field.

#### Scenario: A client registered without the field
- **WHEN** an admin registers a client and omits `access_token_authorization`
- **THEN** the client's mode is `embedded`

#### Scenario: A client switched to introspection
- **WHEN** an admin sends `PATCH /admin/applications/{id}` with `{ "access_token_authorization": "introspection" }`
- **THEN** later tokens for that client carry no `roles`, `groups` or `permissions` claims

#### Scenario: A resource server declared in hearth.yaml
- **WHEN** `hearth.yaml` declares an application with `access_token_authorization: introspection`
- **THEN** after reconcile the client's mode is `introspection`
- **AND** the client can introspect a user-session token with no `azp` that another client of the realm obtained

#### Scenario: The key is removed from hearth.yaml
- **WHEN** the operator removes `access_token_authorization` from a YAML-declared application and Hearth reconciles again
- **THEN** the client's mode is `embedded`

#### Scenario: An admin changes the mode of a hearth.yaml application
- **WHEN** an admin sends `PATCH /admin/applications/{id}` with a mode that differs from the mode `hearth.yaml` declares for that application
- **THEN** the response is `409`, the message names `hearth.yaml`, and the client's mode does not change
