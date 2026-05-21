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
| `search` | Full-text search across email and display name (min 2 characters) |
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
