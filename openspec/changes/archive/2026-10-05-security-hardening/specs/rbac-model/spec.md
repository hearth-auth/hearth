## MODIFIED Requirements

### Requirement: The `hearth.*` namespace is reserved
Permissions under `hearth.*` SHALL be grantable only by Hearth itself or by the roles seeded at realm bootstrap. An operator-defined role MUST NOT include a `hearth.*` permission; Hearth SHALL refuse such a role at creation and at update.

#### Scenario: An operator role claims a reserved permission
- **WHEN** an admin creates a role that lists `hearth.admin`
- **THEN** the API rejects the request with a reserved-namespace error

#### Scenario: Reserved permissions are not granted directly
- **WHEN** a caller holding `hearth.admin` sends `POST /admin/users/{id}/permissions` with `{"permission": "hearth.admin"}`
- **THEN** the request is refused with a reserved-namespace error
- **AND** the user holds no direct grant of `hearth.admin`
