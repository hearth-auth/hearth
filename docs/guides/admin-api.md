# Admin REST API Reference

The Admin REST API is a bearer-token-authenticated HTTP API served at the root `/admin` prefix. It is distinct from the admin UI at `/ui/admin/` — the REST API is intended for automation, provisioning scripts, and SIEM integrations.

**Authentication:** All admin endpoints require an `Authorization: Bearer <token>` header. The token must belong to a user with the `hearth.admin` permission in the target realm. Pass the realm in the `X-Realm-ID` header (UUID or slug).

---

## Users

### List users

`GET /admin/users`

Returns a paginated list of users. Accepts optional filters; when a filter is active, cursor pagination is disabled (`next_cursor` is always `null`) and a full scan is performed (up to 10 000 users).

**Query parameters:**

| Parameter | Description |
|---|---|
| `cursor` | Opaque pagination cursor from a previous response (not available with field filters) |
| `limit` | Page size, 1–100 (default 20) |
| `search` | Search across email and display name using the [admin search grammar](admin-table-search.md) (substring by default; exact with `"…"`; glob with `*`/`?`; min 2 characters) |
| `email` | Exact email match (case-insensitive) |
| `username` | Substring match on `display_name` (case-insensitive) |
| `status` | Status filter: `active`, `disabled`, or `pending_verification` |
| `attr` | Attribute filter — see below |

**Response:**

```json
{
  "items": [
    {
      "id": "<uuid>",
      "email": "alice@example.com",
      "display_name": "Alice Example",
      "status": "active",
      "attributes": { "department": "engineering", "employee_id": "E-1234" }
    }
  ],
  "next_cursor": "<opaque-string-or-null>"
}
```

#### `?attr=key:value` — attribute filter

Filters users to those whose custom `attributes` map contains an exact match on a single key-value pair.

**Format:** `?attr=<key>:<value>`

- The split is performed on the **first colon only** — values may contain colons (e.g., ISO timestamps, URLs, URNs).
- Matching is **exact and case-sensitive**.
- Returns `400 Bad Request` if the parameter contains no colon separator.
- Only one attribute filter is supported per request.
- When `attr` is present, cursor pagination is disabled.

**Examples:**

```bash
# Find users in the engineering department
GET /admin/users?attr=department:engineering

# Find users with a specific employee ID
GET /admin/users?attr=employee_id:E-1234

# Values can contain colons (split on first colon only)
GET /admin/users?attr=last_login:2026-05-20T00:00:00Z

# 400 Bad Request — no colon
GET /admin/users?attr=department
# → {"error": "invalid attr filter; expected key:value format"}
```

**Combining with other filters:**

`attr` can be combined with `email`, `username`, and `status` — all active filters are applied as AND conditions:

```bash
# Active engineering users
GET /admin/users?attr=department:engineering&status=active
```

**Performance note:** Attribute filters trigger a full scan of up to 10 000 user records. For realms with large user populations, consider keeping attribute cardinality low or batching lookups using `email` + `attr` together to narrow the scan early.

---

### Get user

`GET /admin/users/{id}`

Returns a single user record by UUID.

```json
{
  "id": "<uuid>",
  "email": "alice@example.com",
  "display_name": "Alice Example",
  "first_name": "Alice",
  "last_name": "Example",
  "status": "active",
  "email_verified": true,
  "required_actions": ["UPDATE_PASSWORD"],
  "attributes": { "department": "engineering" },
  "created_at": 1715000000000000,
  "updated_at": 1715000100000000
}
```

`required_actions` is omitted from the response when the array is empty. Possible values: `VERIFY_EMAIL`, `UPDATE_PASSWORD`, `ENROLL_MFA`, `ENROLL_PHONE_OTP`.

---

### Create user

`POST /admin/users`

Creates a new user. Body fields: `email` (required), `display_name`, `first_name`, `last_name`, `password`, `status`, `attributes`.

---

### Update user

`PATCH /admin/users/{id}`

Partially updates a user. All body fields are optional; omitted fields are unchanged.

To update custom attributes, pass the full replacement map:

```json
{
  "attributes": {
    "department": "platform",
    "employee_id": "E-1234"
  }
}
```

Attributes are replaced atomically — the entire map is overwritten with the provided value. To clear all attributes, pass `"attributes": {}`.

---

### Delete user

`DELETE /admin/users/{id}`

Permanently deletes the user and cascades to their sessions, credentials, organization memberships, and email indexes.

---

### Bulk import

`POST /admin/users/import`

Accepts an array of user objects (same schema as create). Returns a summary of created, skipped, and failed records.

---

### Export

`GET /admin/users/export`

Downloads all users as NDJSON (`Content-Disposition: attachment`). Accepts the same filter parameters as list users.

---

### Required actions

`PATCH /admin/realms/{realm_id}/users/{user_id}/required-actions`

Adds or removes required actions on a specific user. The body uses a diff model — only the listed actions are changed; omitted ones are left as-is.

**Body:**

```json
{
  "add": ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
  "remove": []
}
```

Both `add` and `remove` accept any combination of `VERIFY_EMAIL`, `UPDATE_PASSWORD`, `ENROLL_MFA`, and `ENROLL_PHONE_OTP`. Unknown action strings return `400`. Duplicates in `add` are silently ignored.

**Response (200 OK):** The updated user object (same shape as `GET /admin/users/{id}`).

**Error responses:**

| Status | Cause |
|---|---|
| `400` | Unknown action string or malformed body |
| `401` | Missing or invalid admin token |
| `404` | User or realm not found |

Each change emits an audit event. Assignments are logged as `RequiredActionAssigned`; removals as `RequiredActionRemoved`.

→ See [Required actions guide](required-actions.md) for realm-level defaults, the OIDC interception flow, and Keycloak migration notes.

---

---

## Organizations

### List organizations

`GET /admin/orgs`

Returns a paginated list of organizations.

**Query parameters:**

| Parameter | Description |
|---|---|
| `cursor` | Opaque pagination cursor from a previous response |
| `limit` | Page size, 1–100 (default 20) |

**Response:**

```json
{
  "items": [
    {
      "id": "<uuid>",
      "slug": "acme-corp",
      "name": "Acme Corporation",
      "description": "Main enterprise customer",
      "status": "active",
      "config": { "max_members": 500 },
      "attributes": { "crm_id": "SF-00123", "contract_tier": "enterprise" }
    }
  ],
  "next_cursor": "<opaque-string-or-null>"
}
```

---

### Get organization

`GET /admin/orgs/{id}`

Returns a single organization by UUID.

---

### Create organization

`POST /admin/orgs`

Body fields:

| Field | Required | Description |
|---|---|---|
| `slug` | ✅ | URL-safe identifier, 3–63 lowercase alphanumeric/hyphen chars |
| `name` | ✅ | Human-readable display name |
| `description` | — | Optional description |
| `config.max_members` | — | Member limit (omit for unlimited) |
| `attributes` | — | Key-value metadata map |

```json
{
  "slug": "acme-corp",
  "name": "Acme Corporation",
  "attributes": {
    "crm_id": "SF-00123",
    "contract_tier": "enterprise"
  }
}
```

Returns the created organization object.

---

### Update organization

`PATCH /admin/orgs/{id}`

Partially updates an organization. All fields are optional; omitted fields are unchanged.

To replace the attribute map:

```json
{
  "attributes": {
    "crm_id": "SF-00456",
    "contract_tier": "growth"
  }
}
```

Attributes are replaced atomically — the entire map is overwritten. To clear all attributes, pass `"attributes": {}`.

---

### Delete organization

`DELETE /admin/orgs/{id}`

Permanently deletes the organization and cascades to all membership records, pending invitations, and SCIM `externalId` mappings. Members themselves are not deleted.

---

## Custom attributes

Custom attributes are arbitrary key-value string pairs stored on user and organization records. Use them for tenant-specific metadata (department, employee ID, CRM ID, contract tier, etc.) that Hearth's standard schema does not cover.

### Free-form mode (default)

When no `attribute_definitions` are configured for the realm, any well-formed key-value pair is accepted. Constraints apply to both users and organizations:

| Constraint | Limit |
|---|---|
| Keys per record | max 50 |
| Key length | max 64 bytes, non-empty |
| Key characters | ASCII alphanumeric, `.`, `_`, `-` only |
| Value length | max 1 024 bytes |
| Total map size | max 16 KiB (sum of all keys + values) |

### Schema-enforced mode

When `attribute_definitions.users` or `attribute_definitions.organizations` is declared in the realm YAML, the identity engine enforces additional rules:

- **Unknown keys rejected** — any key not listed in `attribute_definitions` returns `400 Invalid attribute`.
- **Required keys enforced on create** — attributes with `required: true` must be present when creating the record; omitting them returns `400`.
- **Enum values validated** — `type: enum` attributes reject values not in `enum_values`.
- **Update semantics** — on update, omitting a required key leaves the existing value unchanged (required enforcement only applies at create time).

### Configuring attribute schemas

Declare schemas in `hearth.yaml` under each realm:

```yaml
realms:
  my-realm:
    attribute_definitions:
      users:
        - key: department
          label: Department
          type: string             # string | number | boolean | enum
          required: false
          description: "User's business unit"

        - key: employee_id
          label: Employee ID
          type: string
          required: true           # must be present on user create

        - key: tier
          label: Subscription Tier
          type: enum
          required: false
          enum_values:
            - free
            - pro
            - enterprise

      organizations:
        - key: crm_id
          label: CRM ID
          type: string
          required: false
          description: "Salesforce account ID"

        - key: contract_tier
          label: Contract Tier
          type: enum
          required: false
          enum_values:
            - starter
            - growth
            - enterprise
```

See `hearth.example.yaml` for a commented full example with all four type variants.

### Type hints

All values are stored as UTF-8 strings. The `type` field controls how the Admin UI renders the input and performs lightweight validation:

| Type | Admin UI input | Extra validation |
|---|---|---|
| `string` | `<input type="text">` | None beyond length limit |
| `number` | `<input type="number">` | None (value stored as string) |
| `boolean` | Checkbox | None (stored as `"true"` or `"false"`) |
| `enum` | `<select>` | Value must be in `enum_values` |

---

## OAuth Applications

OAuth clients (applications) are managed under the `/admin/applications` prefix. Clients declared in `hearth.yaml` (via `realms.<name>.applications`) are also reflected here but MUST be edited in YAML — the API refuses mutations on YAML-managed clients.

### List applications

`GET /admin/applications`

Returns a paginated list of clients.

**Query parameters:**

| Parameter | Description |
|---|---|
| `cursor` | Opaque pagination cursor |
| `limit` | Page size, 1–100 (default 20) |

---

### Register application

`POST /admin/applications`

Creates a new OAuth client. Body fields:

| Field | Required | Description |
|---|---|---|
| `client_name` | ✅ | Human-readable name |
| `redirect_uris` | — | Allowed redirect URIs (required for `authorization_code` clients) |
| `grant_types` | — | Array: `authorization_code`, `client_credentials`, `refresh_token`, `device_code` |
| `client_secret` | — | Client secret (omit for public clients). Argon2id-hashed before storage. |
| `access_token_authorization` | — | Authorization mode: `"EMBEDDED"` (default), `"INTROSPECTION"`, `"DECISION"` |
| `trust_level` | — | `"first_party"` or `"third_party"` (default). `first_party` clients receive full roles, permissions, and groups claims in issued JWTs. `third_party` clients receive a minimal claim set and trigger the OAuth consent screen. |

The `access_token_authorization` field controls how resource servers resolve permissions for tokens issued to this client. See [Token Authorization Modes](rbac.md#token-authorization-modes) for semantics.

> **Security note:** Dynamic Client Registration (`POST /register`) ignores any `trust_level` supplied by the caller and always stores `"third_party"`. Only an admin token can grant `"first_party"` trust via this endpoint.

```bash
curl -X POST https://auth.example.com/admin/applications \
  -H "Authorization: Bearer <admin_token>" \
  -H "X-Realm-ID: <realm_uuid>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Billing Service",
    "grant_types": ["client_credentials"],
    "client_secret": "long-random-secret",
    "access_token_authorization": "DECISION"
  }'
```

Returns the created client object with a generated `client_id`.

---

### Get application

`GET /admin/applications/{id}`

Returns a single client by UUID.

---

### Update application

`PUT /admin/applications/{id}`

Updates a client. All fields are optional; omitted fields are unchanged.

| Field | Description |
|---|---|
| `client_name` | New display name |
| `redirect_uris` | Replacement redirect URI list |
| `grant_types` | Replacement grant-type list |
| `backchannel_logout_uri` | Back-channel logout URI; `null` clears it |
| `frontchannel_logout_uri` | Front-channel logout URI; `null` clears it |
| `post_logout_redirect_uris` | Replacement post-logout redirect list |
| `require_consent` | Whether to show the OAuth consent screen |
| `access_token_authorization` | `"embedded"`, `"introspection"`, or `"decision"` |
| `trust_level` | `"first_party"` or `"third_party"`. `first_party` clients receive full roles, permissions, and groups claims in issued JWTs. `third_party` clients receive a minimal claim set and trigger the OAuth consent screen. |

```bash
# Switch a client to decision mode
curl -X PUT https://auth.example.com/admin/applications/<client_uuid> \
  -H "Authorization: Bearer <admin_token>" \
  -H "X-Realm-ID: <realm_uuid>" \
  -H "Content-Type: application/json" \
  -d '{"access_token_authorization": "decision"}'
```

---

### Delete application

`DELETE /admin/applications/{id}`

Permanently deletes the client. Active sessions for this client are not immediately revoked; tokens expire at their natural TTL.

---

### POST /oauth/authorize — per-request permission decision

`POST /oauth/authorize`

Per-request binary authorization decision for clients configured with `access_token_authorization: decision`. Resource servers call this endpoint to determine whether the bearer-token holder has a specific permission, resolved live against current RBAC state.

**Headers:**

| Header | Description |
|---|---|
| `Authorization: Bearer <access_token>` | Token issued to the end-user or service account |
| `X-Realm-ID: <realm_uuid>` | Realm to resolve permissions in |

**Request body (JSON):**

| Field | Required | Description |
|---|---|---|
| `permission` | ✅ | Permission string to check (e.g. `"docs.edit"`) |
| `organization_id` | — | Org UUID for org-scoped permission checks |
| `resource` | — | RFC 8707 resource URI for audience-scoped checks |

**Response 200:**
```json
{ "allowed": true }
```
or
```json
{ "allowed": false }
```

**Fail-closed:** Every failure path — missing bearer token, expired token, revoked session, resolution error — returns `{"allowed": false}` with HTTP 200. Only a valid, non-revoked token where the subject holds `permission` returns `{"allowed": true}`.

**Error:** Missing `permission` field returns `400 Bad Request`.

> This endpoint is intended for internal service-to-service calls. Do not expose it to public internet or browser clients.

---

## Identity Providers (Federation)

Federation connectors (Google, GitHub, Microsoft, Apple, generic OIDC, SAML) are **not managed through the Admin API or Admin UI**. They are declared in `hearth.yaml` and reconciled at startup.

The Admin UI's **Identity Providers** page is a read-only inspection surface — it shows which connectors are active but does not allow adding, editing, or deleting them.

To manage federation providers:

1. Edit `realms.<name>.federation.providers` in `hearth.yaml`.
2. Reload: restart the server, or send `SIGHUP` for a hot reload.

→ See [Federation examples](hearth-yaml-examples/federation.md) for YAML configuration for Google, GitHub, Microsoft, Apple, SAML, and generic OIDC.
→ See [Configuration reference](../specs/CONFIGURATION.md#realmsnamedfederation) for the full field reference.
