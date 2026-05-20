# Config-Driven Data Migration

Hearth tracks a secrets-stripped snapshot of `hearth.yaml` in the WAL after each successful startup. On the next boot it diffs the new config against that snapshot and automatically performs any required data operations — no manual admin steps, no CLI flags, no scheduled jobs.

This page covers every migration type the engine handles.

---

## Soft-Delete Model

Removing a realm slug from `hearth.yaml` **does not hard-delete it**. Hearth sets the realm's status to `Archived` and preserves all data indefinitely.

```
hearth.yaml removes "legacy" slug
  → realm.status = Archived
  → all users, sessions, OAuth clients, audit events preserved
  → realm visible in Admin UI with "Archived" badge
```

Re-adding the same slug later **restores** the realm exactly as it was. The slug is the permanent identity of a realm — Hearth will never create a second realm with the same slug while an archived one exists.

To permanently destroy an archived realm's data, either:
- Add `archive_drop: true` to its YAML entry before removing the slug, **or**
- Click "Delete permanently" in the Admin UI after it is archived.

---

## Cross-Realm User Migration

Declare `migrate_from` on the **destination** realm (the one that should receive users). Hearth runs the migration on the next boot automatically.

```yaml
realms:
  new-portal:                    # destination
    migrate_from: legacy-portal  # source slug
    migrate:
      users: true                # default: true
      orgs: true                 # default: true
      applications: true         # default: true — OAuth clients
      on_conflict: error         # "error" (default) | "skip"
```

### Move vs. Copy

| Key | Source after migration |
|-----|----------------------|
| `migrate_from` | Archived automatically |
| `copy_from` | Remains Active |

```yaml
realms:
  replica:
    copy_from: production        # source stays Active
    migrate:
      users: true
      orgs: false
      on_conflict: skip
```

### Conflict resolution

| `on_conflict` | Behaviour |
|---------------|-----------|
| `error` (default) | Startup aborts if a user with the same email already exists in the destination. Operator must resolve manually. |
| `skip` | Conflicting users are left in the source; migration continues with the remaining records. |

### Atomicity and crash safety

Each user is written to the WAL as an atomic batch. A progress key (`config:migration:progress:{source}:{user_id}`) is committed after each user. If Hearth crashes mid-migration, the next boot resumes from the last completed user — no user is migrated twice, no user is lost.

### `archive_drop`

```yaml
realms:
  legacy-portal:
    archive_drop: true           # permanently destroy on archive
```

When `archive_drop: true` is set and the slug is removed (or migration completes), Hearth hard-deletes the realm and all its data instead of archiving it. Use this only when you are certain the data is no longer needed.

---

## Signing Key Rotation

Setting `rotate_signing_key: true` on a realm generates a new Ed25519 signing key on the next boot:

```yaml
realms:
  production:
    rotate_signing_key: true     # auto-cleared after rotation completes
```

1. A new key is generated and stored.
2. Both the old key and the new key are served in the JWKS endpoint for a configurable grace period (default: 1 h) so existing tokens remain valid.
3. New tokens are signed with the new key immediately.
4. After the grace period the old key is retired from JWKS.
5. The `rotate_signing_key` flag is removed from the stored config snapshot so it does not trigger again on the next boot.

---

## Host-Key (Master-Key) Rotation

Hearth uses envelope encryption:

```
HEARTH_MASTER_KEY
  └─ encrypts per-realm KEKs  (hearth.keys)
       └─ encrypts per-file DEKs
            └─ encrypts file data
```

To rotate the master key without downtime:

1. Generate a new key (32-byte random, base64-encoded).
2. Set environment variables before starting:
   ```
   HEARTH_MASTER_KEY=<new-key>
   HEARTH_PREVIOUS_MASTER_KEY=<old-key>
   ```
3. Start Hearth. On boot it:
   - Decrypts each realm KEK using `HEARTH_PREVIOUS_MASTER_KEY`
   - Re-encrypts each KEK under `HEARTH_MASTER_KEY`
   - Clears `HEARTH_PREVIOUS_MASTER_KEY` from in-process memory
4. Once startup succeeds, **remove `HEARTH_PREVIOUS_MASTER_KEY` from the environment**. It is no longer needed.

The re-encryption is atomic per KEK (WAL-backed). A crash mid-rotation is safe: partially re-encrypted KEKs are replayed on the next boot with the same two-key environment.

---

## Argon2id Cost Changes

Changing `password_memory_cost` or `password_time_cost` — globally under `auth:` or per-realm — takes effect **lazily**:

- Existing credential hashes are **not** bulk-migrated.
- On each user's next successful login, Hearth detects the cost mismatch, verifies the password, and rehashes it at the new cost in a single atomic write.
- No downtime, no migration window, no admin intervention required.

The global settings serve as defaults; per-realm values override them:

```yaml
auth:
  password_memory_cost: 65536    # global default (64 MiB)
  password_time_cost: 3

realms:
  high-security:
    password_memory_cost: 131072 # 128 MiB — override for this realm
    password_time_cost: 4
```

---

## Orphaned Realms

If a realm is archived while it still has users and no `migrate_from` destination was configured, Hearth:

1. Emits a structured `WARN` log entry at startup identifying the realm and user count.
2. Continues startup normally — orphaned realms are **never** a startup blocker.
3. Displays a recovery banner in the Admin UI on the realm's detail page.

From the Admin UI an operator can:
- Configure a `migrate_from` on another realm and restart to migrate the data.
- Click "Delete permanently" to hard-delete the orphaned realm and all its data.

---

## Full Example

```yaml
realms:
  # Destination realm — absorbs users from "legacy" on next boot.
  customer-portal:
    display_name: "Customer Portal"
    migrate_from: legacy           # move semantics; "legacy" archived after success
    migrate:
      users: true
      orgs: true
      applications: false          # do not copy OAuth clients
      on_conflict: skip            # skip conflicting emails, keep going
    rotate_signing_key: true       # also rotate JWT signing key this boot

  # Source realm — will be archived automatically after migration.
  # Remove archive_drop or set to false to preserve data after archiving.
  legacy:
    display_name: "Legacy (migrating out)"
    archive_drop: false

  # A realm that is copied to "staging" without being archived.
  production:
    display_name: "Production"

  staging:
    display_name: "Staging"
    copy_from: production          # copy semantics; "production" stays Active
    migrate:
      users: true
      orgs: false
      applications: true
      on_conflict: skip
```

---

## Config Snapshot and Diff Engine

After each successful startup Hearth writes a secrets-stripped snapshot of the active configuration to the WAL under the key `config:snapshot:latest`. Secrets (passwords, API keys, client secrets) are stripped before writing — the snapshot is safe to inspect.

On the next boot the diff engine compares the new config against the snapshot and emits a `ConfigDiff` variant for every detected change. Each variant is handled by a dedicated migration handler:

| Change detected | Handler |
|-----------------|---------|
| Realm slug added | Restore archived realm or create new |
| Realm slug removed | Archive realm (soft-delete) |
| `migrate_from` declared | Run cross-realm user migration |
| `copy_from` declared | Run cross-realm copy |
| `rotate_signing_key: true` | Generate new Ed25519 key, enter grace period |
| `password_memory_cost` changed | Mark realm for lazy rehash |
| `archive_drop: true` set | Hard-delete instead of archive on slug removal |

The `ConfigDiff` enum is exhaustive — the Rust compiler enforces that every variant has a handler, preventing silent no-ops when new migration types are added.
