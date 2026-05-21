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

## Custom user attributes

Custom attributes are arbitrary key-value pairs stored on each user record. They can be used for tenant-specific metadata (department, employee ID, cost center, plan tier, etc.) that your application needs but that Hearth's standard user schema does not cover.

### Free-form mode (default)

When no `attribute_definitions` are configured for the realm, any key-value pair is accepted. Constraints:

- Max 50 attributes per user
- Keys: max 128 bytes, non-empty
- Values: max 1 024 bytes

### Schema-enforced mode

When `attribute_definitions.users` is configured in the realm, only declared keys are accepted; unknown keys are rejected. Required attributes must be present on create. Enum-typed attributes validate the value against an allowed list.

See the [Configuration reference](../specs/CONFIGURATION.md) for how to define attribute schemas.
