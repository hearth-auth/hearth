# Permission-delivery modes

**Audience:** operators and developers deciding how resource servers should verify
authorization claims at runtime.

Hearth issues JWTs signed with per-realm Ed25519 keys. How your resource servers consume
authorization data — roles, groups, and permissions — depends on the
`access_token_authorization` mode configured on the `OAuthClient`. Three modes are
available, each with a different latency profile, freshness guarantee, and operational
model.

---

## Quick-choice guide

| Use `embedded` when… | Use `introspection` when… | Use `decision` when… |
|---|---|---|
| Resource server can decode JWTs locally | Resource server cannot cache JWTs or needs current permissions per call | Resource server checks a single permission per-request and must be deny-safe |
| Minimum latency is the priority | Role/group changes must propagate within seconds | Org-scoped checks or RFC 8707 resource-scoped checks are required |
| Stateless token validation is required (edge, serverless) | Central revocation is required without waiting out TTL | Simplest integration path: one HTTP call, one boolean answer |
| RBAC is stable between login and token TTL | Introspection call is cheaper than JWT parse + claim validation | Client-credential tokens are _not_ involved (decision mode rejects them) |

**When in doubt, start with `embedded`.** It is the default and requires no endpoint
changes on the resource server side.

---

## Decision tree

```
Does your resource server need to enforce revocation within seconds
(not "within one access-token TTL")?
│
├─ No ──► Does your resource server support JWT signature verification?
│         │
│         ├─ Yes ──► embedded (default)
│         └─ No  ──► introspection
│
└─ Yes ──► Do you need a single binary allow/deny answer per permission
           (rather than full RBAC claims)?
           │
           ├─ Yes ──► decision
           └─ No  ──► introspection
```

---

## Latency tradeoff

| Mode | Resource-server authorization cost | Network hops | Freshness window |
|---|---|---|---|
| `embedded` | Ed25519 verify in-process (~1 μs) | 0 | `access_token_ttl` (default 15 min) |
| `introspection` | 1 call to `/introspect` (p50 < 50 μs, p99 < 500 μs) | 1 | Current (session liveness re-checked) |
| `decision` | 1 call to `POST /oauth/authorize` per permission | 1 | Current (session liveness re-checked) |

`embedded` is the hot-path mode. Token validation runs entirely in-process against
memory-mapped structures with zero heap allocations and no syscalls. See
[`ARCHITECTURE.md § 3`](../specs/ARCHITECTURE.md) for the full hot-path contract.

`introspection` and `decision` calls are off the Hearth hot path — each call validates
the token signature, expiry, and session liveness in-process before resolving live RBAC,
but the network round-trip is the dominant cost at the resource server.

---

## Mode details

### `embedded` (default)

Permissions, roles, and groups are embedded in the JWT at issuance. Resource servers
verify the token signature with Hearth's JWKS and read claims directly.

**Token payload (issuance):**
```json
{
  "sub": "user_01234567-89ab-cdef-0123-456789abcdef",
  "iss": "https://auth.example.com",
  "aud": ["my-app"],
  "exp": 1234567890,
  "iat": 1234564290,
  "tid": "01234567-89ab-cdef-0123-456789abcdef",
  "roles": ["docs-editor"],
  "groups": ["engineering"],
  "permissions": ["docs.edit", "docs.view"]
}
```

**Resource-server check (no network call):**
```bash
# Fetch JWKS once and cache (rotate on 401)
curl https://auth.example.com/realms/<realm_id>/jwks

# Decode and verify locally with any JWT library
# Then check the permissions claim:
# token.permissions.contains("docs.edit")  → true/false
```

**Security rules:**
- MUST validate `iss`, `aud`, `exp`, `iat`, and Ed25519 signature on every request.
- MUST NOT accept tokens with `alg: none` or symmetric algorithms.
- MAY cache the JWKS for up to the `Cache-Control: max-age` the endpoint returns; MUST
  re-fetch on a 401.
- MUST accept that `permissions`, `roles`, and `groups` reflect the user's state at
  token-issuance time, not the current instant. Stale window = `access_token_ttl`.

---

### `introspection`

The JWT carries only identity claims; resource servers call `POST /introspect` for live
RBAC data. Hearth validates session liveness on every introspection call, so revocation
propagates within the next request rather than waiting for token TTL.

**Token payload (issuance) — RBAC claims stripped:**
```json
{
  "sub": "user_01234567-89ab-cdef-0123-456789abcdef",
  "iss": "https://auth.example.com",
  "aud": ["my-app"],
  "exp": 1234567890,
  "iat": 1234564290,
  "scope": "openid docs"
}
```

**Resource-server introspection call:**
```bash
POST /realms/<realm_id>/introspect
Content-Type: application/json
Authorization: Basic <base64(client_id:client_secret)>

{
  "token": "<access_token>",
  "token_type_hint": "access_token"
}
```

Authentication accepts HTTP Basic Auth or JSON body fields `client_id` + `client_secret`.

**Response (active token):**
```json
{
  "active": true,
  "sub": "user_01234567-89ab-cdef-0123-456789abcdef",
  "client_id": "<client_uuid>",
  "scope": "openid docs",
  "exp": 1234567890,
  "iat": 1234564290,
  "iss": "https://auth.example.com",
  "mode": "introspection",
  "permissions": ["docs.edit", "docs.view"],
  "roles": ["docs-editor"],
  "groups": ["engineering"]
}
```

**Response (inactive token):**
```json
{ "active": false }
```

**Security rules:**
- MUST treat `active: false` as a deny. Do not inspect other fields on an inactive response.
- MUST authenticate with valid client credentials on every call; unauthenticated introspection
  is rejected.
- The `permissions`, `roles`, and `groups` in the response are live as of the call.
- MUST NOT cache introspection results longer than `max_age` if present, or at all if
  absent. Caching defeats the freshness guarantee.

---

### `decision`

The JWT carries only identity claims. Resource servers call `POST /oauth/authorize` for a
binary allow/deny answer on a single permission. Hearth validates the token and resolves
live RBAC in a single call. Fails closed on any error.

**Token payload (issuance):** same stripped shape as `introspection` above.

**Resource-server decision call:**
```bash
POST /oauth/authorize
Authorization: Bearer <access_token>
X-Realm-ID: <realm_uuid>
Content-Type: application/json

{
  "permission": "docs.edit",
  "organization_id": "org_...",
  "resource": "https://docs.example.com/doc/42"
}
```

| Request field | Type | Required | Description |
|---|---|---|---|
| `permission` | string | **yes** | Permission to check, e.g. `"docs.edit"`. |
| `organization_id` | string | no | Org ID (`org_…`) to scope the check to org-level assignments. |
| `resource` | string | no | RFC 8707 resource URI for audience-scoped checks. |

**Response — always HTTP 200:**
```json
{ "allowed": true }
```
or
```json
{ "allowed": false }
```

**Security rules:**
- MUST treat `allowed: false` as a deny, regardless of the reason — the endpoint never
  distinguishes between an invalid token, an expired session, a missing permission, or an
  internal error. This is the fail-closed guarantee.
- Client-credential tokens (no user context) are always denied at this endpoint. User
  tokens only.
- MUST send the token as a `Bearer` in the `Authorization` header — not in the request body.
- MUST send `X-Realm-ID` to target the correct realm.
- MUST validate that the HTTP status is 200 and parse `allowed` before acting on the response.
  A non-200 response (e.g. 400 if `permission` field is absent) indicates a caller bug.
- For org-scoped permissions, MUST pass `organization_id`; omitting it checks against
  realm-level assignments only.
- SHOULD NOT cache the response across distinct requests — the call is intentionally
  per-request for freshness.

---

## Refresh-token revocation caveat

Revoking a refresh token or session does **not** invalidate already-issued access tokens.

| Mode | Revocation propagation |
|---|---|
| `embedded` | Stale permissions persist until `access_token_ttl` expires. The maximum staleness window equals your configured TTL (default 15 minutes). |
| `introspection` | Session liveness is checked on every `/introspect` call. A revoked session is reflected within the next resource-server request. |
| `decision` | Session liveness is checked on every `/oauth/authorize` call. Same propagation as `introspection`. |

If near-instant revocation is required in `embedded` mode, issue tokens with a short
`access_token_ttl` (e.g. 5 minutes) and rely on the refresh-token for session extension.
A future `sv` (session-version) claim mechanism is planned for sub-TTL revocation without
a network hop; see [`AUTHORIZATION.md § 14`](../specs/AUTHORIZATION.md).

---

## Configuring the mode

Set `access_token_authorization` when registering or updating a client via the Admin API.

**Register a new client with `decision` mode:**
```bash
curl -X POST http://127.0.0.1:8420/admin/clients \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-Realm-ID: <realm-uuid>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Docs Service",
    "redirect_uris": ["https://docs.example.com/callback"],
    "grant_types": ["authorization_code"],
    "access_token_authorization": "decision"
  }'
```

**Update an existing client to `introspection` mode:**
```bash
curl -X PATCH http://127.0.0.1:8420/admin/clients/<client-id> \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-Realm-ID: <realm-uuid>" \
  -H "Content-Type: application/json" \
  -d '{ "access_token_authorization": "introspection" }'
```

Valid values: `"embedded"` (default), `"introspection"`, `"decision"`.

Existing clients without an explicit mode default to `"embedded"` for full backward
compatibility.

---

## Keycloak comparison

| Keycloak concept | Hearth equivalent |
|---|---|
| Opaque token + `/userinfo` call | `introspection` mode |
| Policy enforcer (`keycloak.json`) calling `POST /authz/resource` | `decision` mode |
| JWT with embedded roles/groups claims | `embedded` mode (default) |
| UMA resource server with permission tickets | `decision` mode (simplified; Hearth does not implement UMA) |

Keycloak's default for most flows is opaque tokens with introspection. Hearth defaults to
`embedded` for lower latency; switch to `introspection` or `decision` if you need the
Keycloak-equivalent behavior.

---

## Org-scoped permission checks

When a token is issued in an organization context, org-scoped role assignments appear in
the resolved permissions. For `introspection` mode this is automatic — Hearth resolves the
correct scope from the token's `oid` claim. For `decision` mode, pass the org ID
explicitly:

```json
{
  "permission": "org.billing.view",
  "organization_id": "org_01234567-89ab-cdef-0123-456789abcdef"
}
```

Omitting `organization_id` in a decision call checks realm-level assignments only; org-scoped
assignments are not visible without it.

---

## SDK cross-references

SDK helpers for reading embedded claims are documented in the RBAC guide:
[`docs/guides/rbac.md`](rbac.md).

Phase B SDK integrations for `introspection` and `decision` modes (TypeScript +
Go middleware helpers) will be cross-linked here once those issues ship.

---

## Reference

- [`docs/specs/AUTHORIZATION.md § 15`](../specs/AUTHORIZATION.md) — normative mode
  specification, wire shapes, security rules.
- [`docs/specs/ARCHITECTURE.md § 4.2.1`](../specs/ARCHITECTURE.md) — wire protocol
  surface; hot-path vs. off-path designation.
- [`docs/specs/AUTHORIZATION.md § 14`](../specs/AUTHORIZATION.md) — planned `sv`
  session-version revocation (roadmap).
