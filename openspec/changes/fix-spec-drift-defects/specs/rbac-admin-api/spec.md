## MODIFIED Requirements

### Requirement: Effective-permissions debug endpoint
`GET /admin/users/{user_id}/effective-permissions?org_id=...&scope=...` SHALL resolve and return what the user would receive in a token issued with those parameters. It is a support and debug aid.

#### Scenario: Preview an organization token
- **WHEN** an admin calls the endpoint with `org_id` naming an organization where the user holds an organization-scoped role
- **THEN** the response includes that role's permissions

#### Scenario: Regression — the preview matches the issued token
- **WHEN** the realm registers the scope `docs:read` with `docs.view`, the user holds `docs.view` and `docs.delete`, and an admin calls the endpoint with `scope=openid docs:read`
- **THEN** the returned `permissions` are `["docs.view"]`, the same set a token granted `openid docs:read` carries

