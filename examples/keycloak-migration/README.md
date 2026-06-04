# Keycloak Migration — Runnable Example

One-command end-to-end walkthrough of `hearth migrate keycloak`.

```bash
./run.sh
```

> For full migration prose, conceptual mapping, and production checklists see
> [`docs/guides/migrating-from-keycloak.md`](../../docs/guides/migrating-from-keycloak.md).

---

## What `./run.sh` does

1. **Builds** the `hearth` binary (`cargo build --release`).
2. **Creates** a throwaway temp data dir (`mktemp -d`), deleted on exit.
3. **Migrates** `sample-export.json` into that dir via `hearth migrate keycloak`.
4. **Boots** `hearth serve --dev` pointing at the migrated store (`HEARTH_DEV_DATA_DIR`).
5. **Runs** `verify.mjs` — logs in as a migrated user, checks roles and JWKS.
6. **Tears down** and exits with `verify.mjs`'s status code.

Prerequisites: Rust toolchain, Node.js ≥ 18.

---

## Files

| File | Purpose |
|------|---------|
| `sample-export.json` | Small Keycloak realm export: 3 users, 2 roles, 1 client, 1 group |
| `hearth.yaml` | Annotated config: Keycloak → Hearth key mappings, token TTLs, security |
| `run.sh` | One-command orchestrator |
| `verify.mjs` | Node ESM verifier: zero-dep, exits non-zero on any mismatch |

---

## Sample export contents

| User | Credential | Password | Roles | Notes |
|------|-----------|----------|-------|-------|
| `alice@acme.test` | PBKDF2-SHA256 | `hunter2` | admin, member | Verifiable after migration |
| `bob@acme.test` | PBKDF2-SHA512 | *(unknown)* | member | Hash **skipped** — Bob must reset password |
| `charlie@acme.test` | *(none)* | — | member | No credential — must reset password |

The `acme-web` client carries `"secret": "top-secret-value"` — an obvious placeholder that is never validated by `verify.mjs` (Hearth's ROPC grant does not check client secrets). If your repo runs automated secret scanning (gitleaks, trufflehog), add `examples/keycloak-migration/sample-export.json` to your allowlist.

The `Engineering` group (containing Alice) is present in the export as it would appear in a real Keycloak dump. **Keycloak groups are not auto-imported** by the current importer — they are out of scope (see [Out of scope](../../docs/guides/migrating-from-keycloak.md#out-of-scope)). Post-migration, recreate groups as Hearth Organizations (B2B tenancy) or RBAC Groups as appropriate for your use case.

---

## Exporting from Keycloak (real deployment)

### kc.sh (bare-metal / zip install)

```bash
/opt/keycloak/bin/kc.sh export \
  --realm <your-realm> \
  --users realm_file \
  --file keycloak-export.json
```

### Docker

```bash
docker exec -it keycloak /opt/keycloak/bin/kc.sh export \
  --realm <your-realm> \
  --users realm_file \
  --file /tmp/keycloak-export.json

docker cp keycloak:/tmp/keycloak-export.json ./keycloak-export.json
```

Use `--users realm_file` (not `--users different_files`) so all users land in one file.

---

## Importing your own export

```bash
# Migrate into a permanent data dir (not a tempdir)
hearth migrate keycloak \
  --file keycloak-export.json \
  --data-dir /var/lib/hearth

# Dry run — validate without writing
hearth migrate keycloak \
  --file keycloak-export.json \
  --dry-run
```

Then boot Hearth pointing at that dir — no `--dev` in production:

```bash
# hearth.yaml must have storage.data_dir set
hearth serve --config /etc/hearth/hearth.yaml
```

---

## `--dev` flag requirements

`run.sh` passes `--dev` to `hearth serve`. This is required because:

- **A-6 (bootstrap guard):** `POST /admin/bootstrap` is only available in dev mode.
- **A-10 (JWKS rate limiter):** JWKS endpoint rate limits are relaxed in dev mode, so `verify.mjs` can call it freely.
- **A-5 (slug cooldown):** The 30-day realm-slug cooldown is bypassed in dev mode, so the same realm name can be re-imported on repeated runs.

Do **not** use `--dev` in production.

---

## Credential import semantics

| Credential type | Outcome | Login after migration |
|-----------------|---------|----------------------|
| `pbkdf2-sha256` | Imported as PHC string; verified natively by Hearth | Password works immediately |
| `pbkdf2-sha512` | **Skipped** — not supported by Hearth's verifier | Must reset password |
| `bcrypt` / other | **Skipped** | Must reset password |
| *(none)* | User record imported, no credential stored | Must reset password |

Users who need to reset their password receive the standard Hearth
"Set your password" email flow triggered by `POST /admin/realms/<realm-id>/users/<user-id>/send-setup-email`
or by the admin UI.

> **Security note:** Users without importable credentials (PBKDF2-SHA512, bcrypt, or
> no credential) are imported as active accounts with no stored password. They cannot
> log in until they complete the password-reset flow. Consider immediately triggering
> password-reset emails for affected users, or setting `auth.allowed_auth_methods` to
> exclude `password` for the realm until resets are complete.

---

## Troubleshooting

**`hearth migrate keycloak` errors with "duplicate realm"**

The realm UUID already exists in the data dir. Either wipe the data dir or pass
`--realm <new-uuid>` to import into a different UUID.

**`verify.mjs` fails: `token grant failed (401)`**

Alice's credential may not have been imported. Check the migration output for
`pbkdf2-sha256` warnings. The sample export embeds a real hash of `hunter2`
that was generated with `pbkdf2_hmac<Sha256>` — it must verify correctly.

**`verify.mjs` fails: `realm_not_found`**

The server is using a different data dir than the one the migration wrote to.
Confirm `HEARTH_DEV_DATA_DIR` points at the same path passed to `--data-dir`.

**Server logs show `address already in use` on port 8420**

Another Hearth instance is running. Kill it and retry.
