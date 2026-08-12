# Backup and Restore Guide

Hearth ships a built-in backup CLI that exports realm data to a self-contained `.hearth-backup` archive and restores from it without a running server. The backup engine reads directly from the embedded storage engine, so no HTTP server needs to be running during the operation.

---

## Archive format

A `.hearth-backup` file is a zstd-compressed archive. Inside, each realm is stored under `realms/<slug>/` with one NDJSON file per entity type:

| File | Contents |
|---|---|
| `manifest.json` | Archive header: version, timestamp, record counts, SHA-256 checksums, optional DEK |
| `realms/<slug>/realm.json` | Realm configuration record |
| `realms/<slug>/users.ndjson` | User records (one JSON object per line) |
| `realms/<slug>/credentials.ndjson` | Hashed credentials |
| `realms/<slug>/clients.ndjson` | OAuth 2.0 application registrations |
| `realms/<slug>/roles.ndjson` | RBAC role definitions |
| `realms/<slug>/permissions.ndjson` | Permission definitions |
| `realms/<slug>/groups.ndjson` | Group definitions |
| `realms/<slug>/assignments.ndjson` | Role/group assignment records |
| `realms/<slug>/scopes.ndjson` | OAuth 2.0 scope definitions |
| `realms/<slug>/organizations.ndjson` | Organization records |
| `realms/<slug>/signing_key.json` | Realm signing key (AES-256-GCM encrypted with the DEK) |
| `realms/<slug>/audit.ndjson` | Audit events (**only when `--include-audit` is passed**) |

The NDJSON format (one JSON object per line) enables streaming reads during large restores without loading the full file into memory.

### Signing key encryption

Every backup includes an AES-256-GCM encrypted copy of each realm's Ed25519 signing key, protected by a random 32-byte **DEK** (Data Encryption Key). The DEK itself is stored base64-encoded in `manifest.json`.

When `--encrypt` is passed, the DEK is additionally wrapped with a passphrase using **Argon2id** (m=65536, t=3, p=4) so that the archive is self-contained and the passphrase is the only external secret needed to restore signing keys. KDF parameters (algorithm, memory, iterations, parallelism, salt) are stored alongside the wrapped DEK in `manifest.json`.

---

## Commands

### `hearth backup create`

Exports all realms (or a specific realm) to a `.hearth-backup` archive.

```
hearth backup create [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--output`, `-o` | `./hearth-backup-<timestamp>.hearth-backup` | Output archive path |
| `--realm` | all realms | Export only this realm (name or UUID) |
| `--include-audit` | off | Include audit events in the export (can be very large) |
| `--encrypt` | off | Protect the signing-key DEK with an interactively-prompted passphrase |
| `--data-dir` | `data` | Path to the Hearth data directory |

**Examples:**

```bash
# Full backup, all realms
hearth backup create --data-dir /var/lib/hearth/data

# Single realm, custom output path
hearth backup create \
  --data-dir /var/lib/hearth/data \
  --realm production \
  --output /backups/prod-$(date +%F).hearth-backup

# Encrypted backup including audit log
hearth backup create \
  --data-dir /var/lib/hearth/data \
  --include-audit \
  --encrypt \
  --output /backups/full-encrypted-$(date +%F).hearth-backup
# → prompts: "Enter backup passphrase:"
```

**Exit codes:** `0` success · `1` partial failure · `2` fatal error.

---

### `hearth backup restore`

Restores realm data from a `.hearth-backup` archive into an existing data directory.

```
hearth backup restore --input <archive> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--input`, `-i` | required | Path to the archive |
| `--realm` | all realms | Restore only this realm (by archive slug) |
| `--mode` | `skip` | Conflict resolution: `skip` keeps existing records, `overwrite` replaces them |
| `--dry-run` | off | Parse and report without writing anything |
| `--data-dir` | `data` | Path to the target data directory |

Restore prints a per-entity-type table of inserted and skipped counts. Exit `0` means all records imported cleanly; exit `1` means partial success (some records skipped or failed); exit `2` means a fatal error (archive unreadable, target unopenable).

**Examples:**

```bash
# Dry-run to preview what would be restored
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --dry-run

# Full restore into an empty data directory
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --data-dir /var/lib/hearth/data-restored

# Restore single realm, overwriting conflicts
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --realm production \
  --mode overwrite \
  --data-dir /var/lib/hearth/data
```

> **Signing-key continuity.** Restore preserves each realm's Ed25519 signing key by default (HEA-745). Every JWT issued before backup keeps validating after restore, and the realm's published JWKS `kid` is unchanged. If you need a fresh key after restore — for example because the original key is suspected compromised — run `hearth realm rotate-signing-key` explicitly. See the [Disaster Recovery Guide](./disaster-recovery.md#post-incident-signing-key-rotation) for the rotation procedure.

**Exit codes:** `0` success · `1` partial (some records skipped/failed) · `2` fatal error.

---

### `hearth backup verify`

Recomputes SHA-256 checksums of all files in the archive and compares them against `manifest.json`. Detects silent corruption or tampering.

```
hearth backup verify --input <archive>
```

```bash
hearth backup verify --input /backups/prod-2026-05-19.hearth-backup
# → OK: all 14 files verified
# → exits 0 (pass) or 3 (integrity failure)
```

**Exit codes:** `0` all checksums match · `3` one or more checksums do not match.

---

### `hearth backup inspect`

Prints a human-readable summary of the archive manifest without decompressing entity files. Useful for quick status checks before a restore.

```
hearth backup inspect --input <archive>
```

Output includes: archive version, creation timestamp, Hearth version, per-realm record counts, whether signing keys are present, and whether the DEK is passphrase-protected.

```bash
hearth backup inspect --input /backups/prod-2026-05-19.hearth-backup
```

---

## Recovery point objective (RPO)

> **Hearth has no point-in-time recovery.** There is no WAL archiving and no
> incremental backup. **Your recovery point is the last successful full
> backup** — everything written after it is lost in a disk-loss or
> datacenter-loss event.

State it to your stakeholders in these terms:

> With hourly backups, the maximum data loss window is **one hour plus the
> duration of one backup run.**

The general form is:

```
worst-case data loss  =  backup interval  +  duration of one backup run
```

The backup's duration counts because the recovery point is the **start** of the
run, not the end — see the consistency caveat below. Substitute your own
cadence: daily backups mean a worst case of just over 24 hours.

**Measure your own run duration** rather than assuming one; it scales with realm
size and is the only term in the formula that is not under your direct control.
Time a real backup on production-shaped data:

```bash
time curl -fsS -X POST -H "Authorization: Bearer $HEARTH_ADMIN_TOKEN" \
  "http://127.0.0.1:8420/admin/backup" -o /tmp/timing-probe.hearth-backup
```

For small realms this is typically well under a minute, making the interval the
dominant term. Confirm it during your [test-restore
drill](./disaster-recovery.md#test-restore-drill-checklist) and re-measure as
the realm grows.

**What this figure does and does not cover:**

| Failure | Data loss |
|---|---|
| Process crash / `kill -9`, disk intact | **Zero** — the WAL replays on startup |
| Single node lost in a 3-node cluster | **Zero** — surviving nodes hold the writes |
| Disk loss on a single-node deployment | **Last backup** (the formula above) |
| Whole-cluster or datacenter loss | **Last backup** (the formula above) |

WAL replay protects you from a crash, **not** from losing the disk: the WAL
lives in the data directory alongside the data, and it is truncated in place
when it rotates rather than being retained as history. It is not a recovery
source beyond the current segment, and it is never shipped off-host.

### Consistency caveat — the recovery point is an interval, not an instant

An archive is a **live sequential scan**, not a snapshot. Each entity type is
read at a different moment during the run: users first, then credentials,
clients, roles, and so on. If the realm is being written to during the backup,
the archive can capture an internally inconsistent view — for example a role
assignment referring to a user who was created after `users.ndjson` was already
written, or a user whose assignments were deleted later in the same run.

The window of exposure is one backup run. To eliminate it, back up during a
maintenance window or from a realm that is not taking writes. Treat the
recovery point as *the start of the run*, and prefer `--dry-run` on restore to
inspect counts before committing.

### Roadmap

PITR, WAL archiving, and incremental backup are designed but **not in 1.x** —
see the [design spike](../plans/HEA-2170-pitr-wal-archiving-design.md) for the
approach, the phasing, and an explicit list of what will not be built.

---

## Backup strategy recommendations

### Scheduled backups

> **A running server holds an exclusive lock on its data directory.**
> `hearth backup create --data-dir <live dir>` will fail with
> `data directory '...' is already locked by another process` (exit code 2)
> while `hearth serve` is running. The CLI is for **offline** data directories
> only — a stopped node, or a copy of one.

To back up a **live** server, use the admin HTTP endpoint, which runs inside the
server process and needs no lock:

```bash
# /etc/cron.d/hearth-backup
0 * * * * hearth curl -fsS -X POST \
  -H "Authorization: Bearer $HEARTH_ADMIN_TOKEN" \
  "http://127.0.0.1:8420/admin/backup" \
  -o /backups/hearth-$(date +\%FT\%H).hearth-backup \
  >> /var/log/hearth/backup.log 2>&1
```

The endpoint requires the `hearth.export` capability in addition to
`hearth.admin`, and is rate-limited to **10 calls per hour per user**, which
caps how tight a cadence you can schedule. Note that `POST /admin/backup` has
no equivalent of the CLI's `--encrypt` flag; encrypt the resulting archive at
rest yourself, or take encrypted archives from a stopped node with the CLI.

Use the CLI form only against a data directory no server is using:

```bash
systemctl stop hearth
hearth backup create --data-dir /var/lib/hearth/data \
  --output /backups/hearth-$(date +%F).hearth-backup --encrypt
systemctl start hearth
```

Rotate old archives with a retention tool (e.g., `find /backups -name "*.hearth-backup" -mtime +30 -delete`).

### Cluster deployments

In a multi-node cluster, **take backups from a follower** to avoid adding I/O
load to the leader (which is processing all writes). Point the `POST
/admin/backup` call at the follower's own admin listener — a running follower
holds the exclusive lock on its data directory, so the CLI form will not work
against it either.

### Verifying backups

Always verify after creation and before storing off-site. `hearth backup verify`
reads only the archive, so it works regardless of which path produced it and
does not touch the data directory:

```bash
curl -fsS -X POST -H "Authorization: Bearer $HEARTH_ADMIN_TOKEN" \
  "http://127.0.0.1:8420/admin/backup" -o /tmp/latest.hearth-backup \
  && hearth backup verify --input /tmp/latest.hearth-backup \
  && mv /tmp/latest.hearth-backup /backups/
```

An unverified backup is not a backup. Fold the `verify` step into the same
scheduled job so a corrupt archive fails the run loudly instead of sitting
undetected until a restore.

### Restoring to a new node

```bash
# 1. Install Hearth on the new node
# 2. Create an empty data directory
mkdir -p /var/lib/hearth/data

# 3. Restore
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --data-dir /var/lib/hearth/data

# 4. Start the server
hearth serve -c /etc/hearth/hearth.yaml
```

For cluster mode, after the restore completes, bootstrap the new node into the cluster normally (it starts with data already populated rather than replaying the entire Raft log from peers).

---

## What is NOT backed up

| Excluded | Why |
|---|---|
| Active sessions | Sessions are short-lived; users re-authenticate after restore |
| Revoked JTI blocklist | Intentionally excluded — restored server accepts previously-revoked tokens; rotate signing keys after a restore if this is a concern |
| Raft log (`raft.db`) | Cluster metadata only; not needed for standalone restore |
| Audit events | Excluded by default; use `--include-audit` if compliance requires it |
