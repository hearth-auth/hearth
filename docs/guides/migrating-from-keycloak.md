# Migrating from Keycloak

**Audience:** operators moving an existing Keycloak deployment to Hearth.
**Goal:** Export a Keycloak realm, import it into Hearth, verify users and roles migrated correctly, and cut over application traffic.
**Time to complete:** 30–60 min for a typical realm; large realms (100 k+ users) may require additional time for the import step.

This guide walks you through moving an existing Keycloak deployment to Hearth. You will export your Keycloak data, import it into Hearth's embedded storage, verify the result, and update your application configuration.

:::note[Scope of this guide]
Keycloak realm exports produced by Keycloak 21 and later. The importer handles PBKDF2-SHA256 and PBKDF2-SHA512 password credentials natively. Users with bcrypt or other hashes are imported without a credential and must reset their passwords on first login.
:::

:::tip[Runnable example]
`examples/keycloak-migration/` contains a self-contained end-to-end example — a committed sample export, annotated config, and a one-command `./run.sh` that migrates, boots Hearth, and verifies the result. Run it on a clean checkout to confirm the migration pipeline works before using your own export.
:::

---

## Conceptual mapping

Understanding the terminology difference is the first step. Hearth borrows the "realm" concept from Keycloak but uses it consistently across every feature.

| Keycloak concept | Hearth equivalent | Notes |
|---|---|---|
| **Realm** | **Realm** | Direct equivalent. One Hearth realm = one Keycloak realm. |
| **Client** | **Application** (OAuth client) | Same OAuth 2.0 semantics; Hearth calls them "applications" in the UI. |
| **Realm role** | **Role** | Roles are scoped to a realm. Client roles are not imported (see [Out of scope](#out-of-scope)). |
| **Role mapping** | **Role assignment** | The RBAC engine stores the same subject → role relationship. |
| **User** | **User** | Email, name, and status fields map directly. |
| **Group** | **Organization** (B2B) or **Group** (RBAC) | Keycloak groups used for access control become RBAC groups; groups used for B2B tenancy become Organizations. |
| **Identity provider (IdP federation)** | Not yet available | See [Out of scope](#out-of-scope). |
| **Authentication flow** | **Auth policy** (per-realm) | Hearth supports password, passkey, TOTP, and magic-link; custom SPI flows do not migrate. |
| **Client scope** | **Scope bundle** | Scope bundles are configured in `hearth.yaml`; they are not imported from Keycloak. |
| **Session** | **Session** | Existing sessions are not migrated — users must log in again after migration. |

---

## Step 1 — Export from Keycloak

### Full realm export

```bash
# Replace <realm> with your realm name
/opt/keycloak/bin/kc.sh export \
  --realm <realm> \
  --users realm_file \
  --file keycloak-export.json
```

For Keycloak running in Docker:
```bash
docker exec -it keycloak /opt/keycloak/bin/kc.sh export \
  --realm <realm> \
  --users realm_file \
  --file /tmp/keycloak-export.json

docker cp keycloak:/tmp/keycloak-export.json ./keycloak-export.json
```

:::warning[Important]
Use `--users realm_file` (not `--users different_files`) so that all users are included in the single export file. The importer expects the standard single-file format.
:::

---

## Step 2 — Dry-run validation

Before writing anything, validate the export against Hearth's importer to see what will be imported and catch any surprises:

```bash
hearth migrate keycloak \
  --file keycloak-export.json \
  --dry-run
```

The report printed to stdout shows:
- Realm name resolved from the export
- Number of users found, imported, and skipped (with skip reasons)
- Number of OAuth clients found and imported
- Realm roles found and created
- Any credential algorithm mismatches (users that will be imported without a password credential)

A dry run uses a temporary in-memory store and makes no changes to any data directory.

---

## Step 3 — Import

Decide on a data directory. For a fresh deployment this is typically `/var/lib/hearth` (created automatically if it does not exist):

```bash
hearth migrate keycloak \
  --file keycloak-export.json \
  --data-dir /var/lib/hearth
```

**Optional flags:**

| Flag | Purpose |
|---|---|
| `--realm <uuid>` | Force the realm to a specific UUID instead of using the one from the export. Useful when you need a predictable realm ID to match pre-configured applications. |
| `--dry-run` | Validate without writing (see Step 2). |

The command prints the same migration report as the dry run, but this time all records are written to the WAL. The operation is atomic at the record level — if the process is interrupted mid-import, WAL replay on next startup discards any incomplete records and you can re-run the import.

---

## What the importer handles

The Keycloak importer (`src/identity/migration/keycloak.rs`) processes:

- **Realm** — name, ID, and basic configuration
- **Users** — email, given name, family name, email-verified flag, enabled/disabled status
- **Password credentials** — PBKDF2-SHA256 and PBKDF2-SHA512 are preserved verbatim as PHC strings. Hearth verifies them natively without re-hashing. On the user's next successful login, Hearth transparently upgrades the credential to Argon2id.
- **Realm roles** — created and assigned to the users who held them in Keycloak
- **OAuth clients** — client ID, redirect URIs, grant types, and confidential/public designation

---

## Step 4 — Start Hearth

Point `hearth.yaml` at the populated data directory and start the server:

```yaml
storage:
  data_dir: /var/lib/hearth

oidc:
  issuer: "https://auth.example.com"   # Must match the issuer your apps expect
```

```bash
hearth serve -c hearth.yaml
```

Verify the server is healthy:
```bash
curl http://127.0.0.1:8420/health
```

---

## Step 5 — Post-migration checklist

Work through this list before directing production traffic to Hearth.

### Verify users imported correctly

```bash
# Requires an admin token — see /admin/bootstrap for dev or your hearth.yaml admin config
curl -H "Authorization: Bearer <admin-token>" \
  http://127.0.0.1:8420/admin/realms/<realm-id>/users | jq length
```

Compare the count against Keycloak. Users skipped during import appear in the migration report with a reason.

### Test a login

Confirm at least one password-credential user can authenticate by navigating to the
**realm-scoped** login UI — substitute the realm name from your export (the `realm`
field, e.g. `acme`):

```
http://127.0.0.1:8420/ui/realms/<realm-name>/login
```

Sign in with a known user's email and password. This is the path that exercises the
imported credential hash; `/ui/admin/login` is a different page for Hearth's own
system-realm administrators and will **not** accept a migrated tenant user.

Also confirm a **wrong** password is rejected. A login check that only tries the
correct password cannot distinguish "the credential migrated" from "the server
accepts anything".

> **Note:** Hearth does not support the Resource Owner Password Credential grant
> (`grant_type=password`) — it was removed and is offered at no token endpoint. All
> user logins go through the browser flow above or the authorization code flow.
> `examples/keycloak-migration/verify.mjs` automates exactly these two checks.

### Verify the OIDC discovery document

Query the **realm-scoped** discovery document, not the server root:

```bash
curl http://127.0.0.1:8420/realms/<realm-name>/.well-known/openid-configuration | jq .issuer
curl http://127.0.0.1:8420/realms/<realm-name>/.well-known/jwks.json | jq '.keys | length'
```

The `issuer` field must exactly match the value configured in `oidc.issuer` and the
value your applications have hard-coded or discovered previously.

> The server-root `/.well-known/openid-configuration` answers for the default issuer
> and returns 200 even when the migrated realm itself is unreachable — so it is not a
> valid check that the import succeeded. Use the realm-scoped path above.

### Update redirect URIs in your applications

Keycloak's client admin URL is no longer relevant. For each OAuth application, confirm that the redirect URIs configured on the application in Hearth match what your app sends. Edit via:
- Admin UI: `/ui/admin/applications/<client-id>/edit`
- Or update `hearth.yaml` under `realms.<name>.clients` and run `hearth config reload`

### Rotate signing keys (recommended)

Keycloak and Hearth use different signing algorithms (Keycloak defaults to RS256; Hearth uses Ed25519). Because the algorithms differ, tokens issued by Keycloak are not valid in Hearth and vice versa. No key material is imported from Keycloak — Hearth generates a fresh Ed25519 key per realm on first startup.

Inform your application teams of the new JWKS endpoint:
```
GET /.well-known/jwks.json
```

Any application that hard-codes or long-caches the Keycloak public key must be updated to fetch from the Hearth JWKS endpoint.

### Verify role assignments

```bash
curl -H "Authorization: Bearer <admin-token>" \
  "http://127.0.0.1:8420/admin/realms/<realm-id>/users/<user-id>/roles"
```

Cross-check at least a representative sample of role assignments against Keycloak.

### Plan MFA re-enrollment

TOTP secrets and WebAuthn credentials are not included in Keycloak's realm export. After migration, users with MFA enabled in Keycloak will need to re-enroll their authenticator in Hearth. Coordinate the re-enrollment window before switching traffic.

---

## SAML security behaviors

If your Keycloak deployment uses SAML — either as a Service Provider consuming upstream IdP assertions, or as an IdP serving SAML SPs — review the following table before configuring SAML connectors in Hearth. Several protections that Keycloak leaves configurable are enforced unconditionally by Hearth.

| Behavior | Keycloak | Hearth |
|---|---|---|
| **Decompression bomb protection** | Not enforced by default; HTTP-Redirect binding inflates without a byte ceiling | Enforced: DEFLATE inflation is capped at 1 MiB on all bindings. Oversized payloads are rejected before XML parsing. |
| **Assertion expiry required** | Configurable; assertions without `NotOnOrAfter` are accepted by default | Enforced: assertions without `NotOnOrAfter` are rejected unconditionally. |
| **Audience/destination validation** | Validated against the `Host` request header (attacker-controllable) | Validated against `onboarding.base_url`. **Operators must set this in production** (see below). |
| **`want_assertions_signed`** | Configurable per IdP; enforcement is optional | Configurable per IdP connector (`want_assertions_signed: true`). When set to `true`, assertion-level signatures are required and the connector rejects unsigned assertions even if the outer `<Response>` is signed. |
| **SAML SSO session gate** | N/A — Hearth is acting as SP here | SAML SSO endpoints (`/federation/saml/begin`) require an authenticated Hearth session; unauthenticated requests are redirected to the Hearth login page rather than forwarded to the upstream IdP. |

### Operator action required: set `onboarding.base_url`

Audience and `Destination` validation compares the IdP's assertion against the SP's public URL. Without a configured base URL, Hearth falls back to the `Host` request header, which can be manipulated by a reverse proxy or an attacker. In production, always set:

```yaml
onboarding:
  base_url: "https://auth.example.com"
```

Hearth uses the same `onboarding.base_url` for emailed links (verification, password reset), so you may already have this set. If not, add it before enabling any SAML connector.

Keycloak operators may not be aware of this field because Keycloak anchors destination validation to the request host by default. Hearth treats the configured value as authoritative and ignores request headers entirely when it is set.

### YAML example — SAML IdP connector with hardened settings

```yaml
realms:
  my-realm:
    federation:
      - kind: saml
        display_name: "Corporate IdP"
        entity_id: "https://idp.corp.example.com/metadata"
        sso_url: "https://idp.corp.example.com/saml/sso"
        idp_certificate_pem: |
          -----BEGIN CERTIFICATE-----
          <your IdP signing certificate>
          -----END CERTIFICATE-----
        want_assertions_signed: true    # require assertion-level XML-DSIG
        sign_authn_requests: true       # sign outbound AuthnRequests
```

---

## Out of scope

The following Keycloak features do not migrate automatically. They require manual configuration or are not yet implemented in Hearth.

| Keycloak feature | Status in Hearth | Action required |
|---|---|---|
| **Client roles** | Not imported | Recreate as realm roles manually if needed |
| **Groups** (used as RBAC containers) | Not imported | Recreate as Hearth RBAC groups in `hearth.yaml` |
| **Identity provider federation** (Google, SAML, LDAP) | Not yet available | Track on the roadmap; users must authenticate with a local credential in the interim |
| **Custom authentication flows / SPI** | Not applicable | Hearth uses a built-in auth policy engine; SPI extensions do not port |
| **TOTP / WebAuthn credentials** | Not exported by Keycloak | Users must re-enroll after migration |
| **Session tokens** | Not migrated | All users must log in again after switchover |
| **Custom themes** | Not imported | Recreate using Hearth's [theming system](../../docs/specs/THEME.md) |
| **Events / audit history** | Not imported | Hearth starts a fresh audit log on migration |
| **Client scopes** | Not imported | Recreate as [scope bundles](rbac.md) in `hearth.yaml` |

---

## Migration gaps

The importer skips four categories of Keycloak data that have no direct equivalent in Hearth's current data model. Each gap lists what Keycloak stores, why Hearth does not import it, and what to do after migration.

:::note[See also]
The [SDK migration guide](/docs/sdks/migration-from-keycloak) covers the same gaps from a code and SDK-swap perspective.
:::

### Client roles

**What Keycloak stores:** Roles scoped to a specific client (application), exposed as `resource_access.<client>.roles` in the token.

**Why not imported:** Hearth uses realm-scoped roles only. There is no per-client role namespace. Client roles would conflict with or shadow realm roles of the same name across multiple clients.

**Workaround:** Recreate client roles as realm roles using a naming convention that encodes the client. For example, use `my-app:billing-admin` instead of `billing-admin` scoped to `my-app`. Assign those roles to the same users who held them in Keycloak:

```bash
curl -X POST \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "my-app:billing-admin"}' \
  http://127.0.0.1:8420/admin/realms/<realm-id>/users/<user-id>/roles
```

### Composite-role parent links

**What Keycloak stores:** Composite roles contain other roles; the parent-child composition is stored as a set of member role references on the parent.

**Why not imported:** Hearth maps roles directly to permission sets at token-issuance time rather than composing roles through inheritance trees. The flat `roles: string[]` and `permissions: string[]` JWT claims replace the need for role inheritance.

**Workaround:** Identify users who held composite roles in Keycloak. In Hearth, assign those users the equivalent leaf roles (already imported as realm roles) and map any additional permissions the composite parent granted via the admin UI:

1. Open **Admin → Realms → \<realm\> → Roles → \<role\> → Permissions**
2. Add the permission strings that the composite role previously implied
3. Assign the leaf roles to affected users as needed

### Groups

**What Keycloak stores:** Hierarchical containers of users, used for bulk role assignment and attribute propagation.

**Why not imported:** Keycloak groups serve two different purposes — access-control grouping (closer to Hearth RBAC groups) and B2B tenancy (closer to Hearth Organizations). The importer cannot safely infer which purpose each group served, so it skips all groups to avoid creating incorrect RBAC or Organization records.

**Workaround:** After migration, recreate groups based on their original purpose:

- Groups used for **access control** → create Hearth RBAC groups in `hearth.yaml` under `realms.<name>.groups`, then assign users
- Groups used for **B2B tenancy** → create Hearth Organizations via the admin UI or:

```bash
curl -X POST \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "slug": "acme-corp"}' \
  http://127.0.0.1:8420/admin/realms/<realm-id>/organizations
```

### Required Actions

**What Keycloak stores:** Required Actions (such as `VERIFY_EMAIL`, `UPDATE_PASSWORD`, `CONFIGURE_TOTP`, `TERMS_AND_CONDITIONS`) are flags on a user record that force the user to complete a specific step at next login.

**Why not imported:** Hearth does not currently implement the same Required Action model. There is no field on the imported user record for pending required actions, so migrated users arrive with no forced next-login step.

**Workaround by action type:**

| Keycloak Required Action | Post-migration step |
|---|---|
| `VERIFY_EMAIL` | The `email_verified` flag is imported as-is. If it was `false`, Hearth marks the account unverified. Trigger re-verification: `POST /admin/realms/<realm-id>/users/<user-id>/send-verification-email` |
| `UPDATE_PASSWORD` | Disable the account (`"status": "inactive"`) and issue a magic-link or admin-reset to force a password change before re-enabling. |
| `CONFIGURE_TOTP` | TOTP credentials are not portable from Keycloak (see Out of scope). If MFA is required by the realm auth policy, Hearth prompts enrollment automatically at next login. |
| `TERMS_AND_CONDITIONS` | No equivalent. Implement acceptance tracking in your application layer if required. |

---

## Rollback plan

Because the Hearth import writes to a separate data directory and Keycloak is unchanged, rollback is straightforward:

1. Stop traffic to Hearth.
2. Route traffic back to Keycloak.
3. Investigate the issue.
4. Re-run the import after fixing the problem (the import is idempotent for most records).
