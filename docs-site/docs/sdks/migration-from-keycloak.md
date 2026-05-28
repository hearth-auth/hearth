---
id: migration-from-keycloak
title: Migrating from Keycloak
sidebar_label: Migrate from Keycloak
description: Side-by-side recipe for moving from Keycloak to Hearth — data export, SDK swap, and RBAC mapping.
---

# Migrating from Keycloak

This guide is a side-by-side recipe for teams moving from Keycloak to Hearth.
It covers data migration, SDK swap, and authorization model translation.

> **Version context:** This guide was written against Keycloak 24.x and the
> current Hearth main branch (May 2025). Verify claim names against your
> specific Keycloak configuration.

## Concept mapping

| Keycloak | Hearth | Notes |
|----------|--------|-------|
| Realm | Realm | Same scope: a tenant boundary for users, clients, and roles |
| Client | OAuth Client | Hearth uses `client_id` / `redirect_uris`; no client secrets for public clients |
| Realm role | Role | Stored as `roles: string[]` in the JWT |
| Composite role | Role with permissions | Hearth maps role → permission set at issuance time |
| Group | Group | Stored as `groups: string[]` in the JWT |
| Organization (Keycloak 24+) | Organization | `oid` JWT claim; Hearth B2B tenancy model |
| UMA / fine-grained authz | Permission | Hearth uses a flat `permissions: string[]` claim in the JWT |
| `preferred_username` | `sub` | Hearth's stable user identifier is always `sub` (UUID) |
| Client scope | OAuth scope | Same OIDC semantics |
| PKCE | PKCE | Hearth requires PKCE for all public clients |

## Step 1 — Export your Keycloak realm

In the Keycloak Admin Console:

1. Open **Realm Settings → Action → Partial export**
2. Enable **Export groups and roles** and **Export clients**
3. Click **Export** to download `realm-export.json`

Or via the Admin CLI:

```bash
/opt/keycloak/bin/kc.sh export \
  --realm my-realm \
  --users realm_file \
  --file realm-export.json
```

## Step 2 — Import into Hearth

Hearth includes a built-in Keycloak migration command that reads the export
file and creates users, clients, and roles:

```bash
hearth migrate keycloak \
  --file realm-export.json \
  --data-dir /var/lib/hearth \
  --dry-run  # preview without writing
```

Remove `--dry-run` to apply. The importer reports per-user success/failure:

```
Imported 1 248 users, 3 failed (see migration.log)
```

### What the importer handles

- **Users and email addresses** — including inactive accounts
- **Credential hashing** — Keycloak's PBKDF2-SHA256 credentials are imported
  verbatim and verified natively; they upgrade to Argon2id on the user's next
  password change (no forced re-authentication required)
- **Realm roles** — mapped 1:1 to Hearth roles on the imported realm
- **Groups** — mapped to Hearth groups; group membership preserved
- **OAuth clients** — `client_id` and `redirect_uris` preserved

### What needs manual follow-up

- **Client secrets** — Keycloak exports do not include plaintext client secrets;
  rotate them in Hearth after import
- **Identity providers (IdP)** — SAML/OIDC IdP configurations are not imported;
  reconfigure under Hearth's federation settings
- **Fine-grained policies** — Keycloak UMA policies must be translated to
  Hearth role→permission assignments manually
- **TOTP / WebAuthn credentials** — authenticator registrations are not portable;
  users re-enroll on next login

## Step 3 — Update your application code

### TypeScript SDK

**Before (Keycloak JS Adapter):**

```typescript
import Keycloak from "keycloak-js";

const kc = new Keycloak({
  url: "https://keycloak.example.com",
  realm: "my-realm",
  clientId: "my-app",
});

await kc.init({ onLoad: "login-required" });

// RBAC — Keycloak adapter
if (kc.hasRealmRole("admin")) { ... }
if (kc.hasResourceRole("billing-admin", "my-app")) { ... }

// Token refresh
await kc.updateToken(60);
```

**After (Hearth SDK):**

```typescript
import {
  HearthClient,
  createHearth,
  HearthProvider,
  useHasRole,
  useHasPermission,
} from "@hearth/sdk";

const client = new HearthClient({
  baseUrl: "https://hearth.example.com",
  realmId: "<realm_id>",
});

// RBAC — synchronous local checks from JWT claims
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<realm_id>",
  getToken: () => localStorage.getItem("access_token"),
});

if (hearth.hasRole("admin")) { ... }
if (hearth.hasPermission("billing.read")) { ... }

// Token refresh
const tokens = await client.refreshTokens("<client_id>", refreshToken);
```

**React hooks — before (Keycloak):**

```tsx
// Keycloak — no official hook; typically wrapped manually
const isAdmin = keycloak.hasRealmRole("admin");
```

**React hooks — after (Hearth):**

```tsx
function AdminPanel() {
  const isAdmin = useHasRole("admin"); // HearthProvider must be mounted above
  return isAdmin ? <Admin /> : null;
}
```

### Go SDK

**Before (Keycloak Go middleware — common pattern):**

```go
import "github.com/Nerzal/gocloak/v13"

client := gocloak.NewClient("https://keycloak.example.com")

// Validate token against Keycloak introspect endpoint (network call on every request)
result, err := client.RetrospectToken(ctx, token, clientID, clientSecret, realm)
if !*result.Active {
    return errors.New("token invalid")
}

// Role check — requires fetching user info
userInfo, _ := client.GetRawUserInfo(ctx, token, realm)
```

**After (Hearth Go SDK):**

```go
import "github.com/anthropics/hearth/sdks/go/hearth"

client := hearth.NewClient("https://hearth.example.com", "<realm_id>")

// Validate token against JWKS (cached, zero-network after first fetch)
keySet, _ := jwk.Fetch(ctx, "https://hearth.example.com/realms/<realm_id>/jwks")
tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(keySet))

// Role and permission checks — synchronous, zero-network, no introspect call
if client.HasRole(token, "admin") { ... }
if client.HasPermission(token, "billing.read") { ... }
```

### Authorization model translation

Keycloak's UMA fine-grained authorization requires a network round-trip to the
policy enforcement point on every request. Hearth embeds all RBAC claims into
the JWT at issuance time:

| Keycloak pattern | Hearth equivalent |
|-----------------|-------------------|
| Realm role check via adapter | `hearth.hasRole("role")` or `HasRole(token, "role")` |
| Resource role check | `hearth.hasPermission("resource.action")` |
| UMA policy enforcement point | Local JWT claim — no PEP needed |
| `realm_access.roles[]` in token | `roles: string[]` claim |
| `resource_access.<client>.roles[]` | `permissions: string[]` claim |
| Group membership via `/userinfo` | `groups: string[]` claim in JWT |

## Step 4 — Update the discovery URL

Replace the Keycloak OIDC discovery URL with Hearth's:

```
# Keycloak
https://keycloak.example.com/realms/my-realm/.well-known/openid-configuration

# Hearth
https://hearth.example.com/realms/<realm_id>/.well-known/openid-configuration
```

Any library that reads the discovery document (e.g., `openid-client`,
`passport-openidconnect`, Go's `coreos/go-oidc`) will auto-configure from the
new URL — no other changes needed for standard OIDC flows.

## Step 5 — Verify in staging

1. Deploy Hearth alongside Keycloak with the imported data
2. Sign in with a migrated user — verify tokens contain expected roles and groups
3. Check `GET /v1/me/permissions` returns the expected RBAC claim set
4. Run your existing integration test suite against the Hearth endpoints
5. Gradually route traffic using a feature flag or reverse-proxy weight

## Common issues

**"Token signature verification failed"**

Your application is still pointing at Keycloak's JWKS URL. Update it to
`https://hearth.example.com/realms/<realm_id>/jwks`.

**"Role X not found after migration"**

Keycloak composite roles are not automatically decomposed into Hearth
permissions. Map them manually in the admin UI:
`Admin → Realms → <realm> → Roles → <role> → Permissions`.

**"User can't log in after migration"**

PBKDF2 credentials are imported and verified natively — they do not require a
password reset. If login fails, check:
- The user's account status (may be `inactive` if exported from Keycloak as disabled)
- Whether TOTP was required in Keycloak (re-enrollment needed in Hearth)

**"Client secret rejected"**

Keycloak exports do not include plaintext secrets. Rotate the client secret in
Hearth's admin UI and update your application's `HEARTH_CLIENT_SECRET`.

## Further reading

- [Keycloak migration CLI reference](https://github.com/hearth-auth/hearth/blob/main/docs/specs/IMPLEMENTATION_ORDER.md) — `hearth migrate keycloak` flags
- [RBAC guide](../rbac.md) — Hearth role/permission model in depth
- [TypeScript SDK quickstart](./typescript.md)
- [Go SDK quickstart](./go.md)
