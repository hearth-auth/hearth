# Auth0 → Hearth Migration

End-to-end runnable example that **consumes** an Auth0 migration bundle and
imports it into Hearth, then verifies the result. This directory is the
"consume bundle" counterpart to
[`examples/auth0-migration-bundler/`](../auth0-migration-bundler/), which
produces a live bundle from an Auth0 tenant.

## Overview

```
Auth0 tenant                           Hearth
────────────────                       ──────────────────────────────────────
tenant name / id         ──────────►  realm (name + UUID)
users + password hashes  ──────────►  users (Active / PendingVerification)
OAuth clients            ──────────►  OAuth applications
organizations + members  ──────────►  organizations + memberships
roles + assignments      ──────────►  RBAC roles + role assignments
```

`sample-bundle.json` is a hand-authored bundle representing a fictional
"acme-corp" tenant with three users, two clients, one organization, and two
roles. Running `./run.sh` migrates the bundle into a fresh ephemeral data
directory, boots `hearth --dev`, and then runs `verify.mjs` to confirm the
migration succeeded end-to-end.

## Quick start (one command)

```bash
cd examples/auth0-migration
./run.sh
```

Prerequisites: `cargo`, `node` ≥ 18, `curl`, `jq`.

## Step-by-step runbook

### Step 1 — (Optional) produce a live bundle

If you want to migrate a real Auth0 tenant instead of using
`sample-bundle.json`, generate the bundle first:

```bash
cd examples/auth0-migration-bundler
npm install
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_CLIENT_ID=xxxxx
export AUTH0_CLIENT_SECRET=xxxxx
node bundle.mjs > ../auth0-migration/my-tenant.json
```

See [`examples/auth0-migration-bundler/README.md`](../auth0-migration-bundler/README.md)
for full prerequisites and options (including `INCLUDE_SECRETS=1`).

### Step 2 — Migrate the bundle

```bash
# Use the sample bundle (this example):
hearth migrate auth0 \
  --file examples/auth0-migration/sample-bundle.json \
  --data-dir /var/lib/hearth/data

# Or dry-run to validate without writing:
hearth migrate auth0 \
  --file examples/auth0-migration/sample-bundle.json \
  --data-dir /tmp/test-dir \
  --dry-run
```

The command prints a migration summary:

```
Migration summary:
  realm:                7b5d9f26-3c8a-4b1e-a6f2-2d08e7c81045
  users imported:        3
  users w/ skipped cred: 0
  clients imported:      2
  role assignments:      2
```

Save the **realm UUID** — you will need it for API calls that require
`X-Realm-ID`.

### Step 3 — Boot Hearth

For the smoke test (ephemeral, no config file):

```bash
HEARTH_DEV_DATA_DIR=/var/lib/hearth/data \
  hearth serve --dev --bind 127.0.0.1 --port 8431
```

For production, copy `hearth.yaml` from this directory, fill in the
placeholders, and run:

```bash
hearth serve -c /etc/hearth/hearth.yaml
```

### Step 4 — Run verify.mjs

```bash
BASE=http://127.0.0.1:8431 \
  MIGRATED_REALM_ID=7b5d9f26-3c8a-4b1e-a6f2-2d08e7c81045 \
  node examples/auth0-migration/verify.mjs
```

Expected output:

```
verify.mjs — Hearth Auth0 migration smoke test
  base:     http://127.0.0.1:8431
  realm:    acme-corp  (7b5d9f26-3c8a-4b1e-a6f2-2d08e7c81045)

▸ step 1 — /health
  ✓ health endpoint returns 200
▸ step 2 — OIDC discovery document
  ✓ discovery document returns 200
  ✓ discovery doc has issuer claim
  ✓ discovery doc has token_endpoint
  ✓ discovery doc has jwks_uri
▸ step 3 — JWKS (Ed25519 key present)
  ✓ JWKS endpoint returns 200
  ✓ JWKS has at least one key
  ✓ key type is OKP (asymmetric)
  ✓ curve is Ed25519
▸ step 4 — ROPC login as migrated user alice
  ✓ ROPC returns access_token
  ✓ alice@acme-corp.test logged in successfully
▸ step 5 — /v1/me/permissions (alice has admin role)
  ✓ alice has "admin" role
  ✓ effective roles: [admin]
▸ step 6 — admin bootstrap + migrated users visible
  ✓ admin bootstrap succeeded
  ✓ migrated realm "acme-corp" is listed in /admin/realms

▸ all checks passed — migration verified ✓
```

## Sample bundle contents

| User | Status after import | Password | Notes |
|------|--------------------|---------|----|
| alice@acme-corp.test | Active | `TestMigration1!` | bcrypt hash included; can log in immediately |
| bob@acme-corp.test | PendingVerification | — | `email_verified: false`; must reset password on first login |
| charlie@acme-corp.test | Disabled | — | `blocked: true`; cannot log in until an admin re-enables the account |

### Users without importable credentials

Auth0 does not export password hashes by default. Users imported without a
credential (like bob) land in `UserStatus::PendingVerification` when their
email is unverified, or `UserStatus::Active` with no stored credential when
their email is verified. Either way, their **first login attempt will fail**
until they complete a password reset.

Operators should send reset emails immediately after migration:

```bash
# Via the Admin UI: Users → select user → Send password reset email
# Via the Admin API (per user):
curl -X POST http://localhost:8420/admin/realms/<realm>/users/<user-id>/reset-password \
  -H "Authorization: Bearer <admin-token>"
```

Hearth's reset flow is identical to Auth0's "Change Password" email flow:
the user receives a single-use, time-limited link to set a new password.

## Mapping reference

| Auth0 concept | Hearth equivalent | Notes |
|---|---|---|
| Tenant name | Realm name (slug) | Slugified if needed (spaces → hyphens) |
| Tenant UUID | Realm UUID | Preserved when `tenant.id` is a valid UUID |
| `email_verified: false` | `UserStatus::PendingVerification` | Password reset required |
| `blocked: true` | `UserStatus::Disabled` | Admin must re-enable |
| `custom_password_hash` (bcrypt) | PHC string, verified natively | No re-hash needed |
| `custom_password_hash` (md5/sha1) | Skipped, warning emitted | Unsupported algorithms |
| OAuth client (`spa`/`native`) | Public OAuth application | No client secret stored |
| OAuth client (`regular_web`/`non_interactive`) | Confidential OAuth application | Secret hashed on import |
| Organization + member roster | Organization + memberships | Role mapped: owner→Owner, admin→Admin, else Member |
| Realm-level role assignments | RBAC role assignments | Roles created if they don't exist |

## Troubleshooting

**`alice login via ROPC: HTTP 401`**
The bcrypt hash in `sample-bundle.json` may not match the password string
`TestMigration1!`. Regenerate the hash for your platform:

```bash
# PHP:
php -r "echo crypt('TestMigration1!', '\$2b\$04\$abcdefghijklmnopqrstuuu');"
# Python (requires bcrypt package):
python3 -c "import bcrypt; print(bcrypt.hashpw(b'TestMigration1!', b'\$2b\$04\$abcdefghijklmnopqrstuuu').decode())"
```

The hash must start with `$2a$`, `$2b$`, or `$2y$`.

**`could not parse realm UUID from migration output`**
Ensure `hearth migrate auth0` exited 0 and printed a `realm:` line. Run
with `--dry-run` first to validate the bundle without writing storage.

**`hearth did not become healthy in time`**
Check `$DATA_DIR/hearth.log`. The storage directory written by the migration
must be accessible to the server process. If running in CI, ensure the temp
directory is on a writable filesystem.

**Port conflict**
Set `HEARTH_PORT=<port>` before calling `./run.sh` to use a different port.

## Files

| File | Purpose |
|------|---------|
| `sample-bundle.json` | Hand-authored Auth0Bundle — 3 users, 2 clients, 1 org, 2 roles |
| `hearth.yaml` | Annotated production config — Auth0 settings → Hearth keys |
| `run.sh` | One-command end-to-end smoke test |
| `verify.mjs` | Node ESM verifier — login, permissions, JWKS |

## Related

- [`examples/auth0-migration-bundler/`](../auth0-migration-bundler/) — How to
  produce a bundle from a live Auth0 tenant (requires Auth0 M2M credentials).
- [`src/identity/migration/auth0.rs`](../../src/identity/migration/auth0.rs) —
  Auth0Bundle struct definition and importer implementation.
- [`src/identity/migration/auth0_credentials.rs`](../../src/identity/migration/auth0_credentials.rs) —
  Credential conversion: Auth0 hash formats → Hearth PHC strings.
- `hearth migrate auth0 --help` — CLI reference.
