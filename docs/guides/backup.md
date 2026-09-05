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

#### What an unencrypted archive does *not* contain

The `signing_key.json` member is only restorable when the archive is encrypted (the DEK is present and, for `--encrypt` archives, unwrappable with the passphrase). An **unencrypted** archive — one with no wrapped DEK, or opened without the passphrase — carries **no usable signing key**: the realm records, users, credentials, clients, RBAC model, organizations, and (optionally) audit events are all present, but the Ed25519 signing key is not.

Restoring such an archive would generate a **fresh** signing key, which invalidates every JWT and session issued before the backup. Because that is a silent, data-loss-adjacent outcome, **restore fails closed** on a missing signing key (see [`hearth backup restore`](#hearth-backup-restore) below): it aborts with an actionable error rather than degrading. Produce a restorable archive by exporting with encryption enabled (`--encrypt`, or set `HEARTH_MASTER_KEY`), which the `hearth backup create` command now requires.

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
| `--mode` | `skip` | Conflict resolution: `skip` keeps existing records. `overwrite` is **refused** when the target realm is already present — see below |
| `--dry-run` | off | Parse and report without writing anything |
| `--allow-missing-signing-key` | off | Restore anyway when the archive has no restorable signing key, accepting a freshly generated key (see below) |
| `--data-dir` | `data` | Path to the target data directory |

Restore prints a per-entity-type table of inserted and skipped counts, broken down by entity type (roles, permissions, groups, assignments, scopes, organizations, audit events). Exit `0` means all records imported cleanly; exit `1` means partial success (some records skipped or failed); exit `2` means a fatal error (archive unreadable, target unopenable, or unrecognized archive member).

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

# Restore a single realm into a data directory where it is absent
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --realm production \
  --data-dir /var/lib/hearth/data-restored
```

> **Signing-key continuity.** Restore preserves each realm's Ed25519 signing key by default (HEA-745). Every JWT issued before backup keeps validating after restore, and the realm's published JWKS `kid` is unchanged. If you need a fresh key after restore — for example because the original key is suspected compromised — run `hearth realm rotate-signing-key` explicitly. See the [Disaster Recovery Guide](./disaster-recovery.md#post-incident-signing-key-rotation) for the rotation procedure.
>
> **Fail-closed on a missing signing key (HEA-2168).** If the archive carries no restorable signing key (an unencrypted archive, one produced before signing-key export, or an encrypted archive opened without the passphrase), restore **refuses** with a clear error rather than silently minting a fresh key that would invalidate every pre-backup JWT and session. The remedy is to restore from an encrypted archive whose key round-trips (`hearth backup create --encrypt` / `HEARTH_MASTER_KEY`). If you genuinely intend to start the realm on a new key, pass `--allow-missing-signing-key` to acknowledge that every token issued before the backup will stop validating. The HTTP restore endpoint always fails closed and has no override.
>
> **`--mode overwrite` will not replace a live realm (audit 2026-08-28 §3 B3).** Overwrite used to
> delete the target realm and then re-import it. `delete_realm` runs its cascade on a background
> task for a realm above `cascade_background_threshold` and returns before that cascade finishes, so
> the re-import raced its own deletion and usually lost: the realm was left destroyed, truncated, or
> without its signing key. Of 1,160 recorded runs none completed and 975 destroyed or truncated the
> realm. Restore now **refuses** when the target realm is already present, with nothing deleted.
> Restoring into a data directory where the realm is absent — the disaster-recovery case — is
> unaffected and needs no `--mode` flag at all. To genuinely replace a live realm, delete it
> explicitly, wait for the deletion to complete, then restore.
>
> **Fail-closed on unrecognized archive members (HEA-2160).** If the archive contains a member not recognized by the importer (for example, an archive produced by a newer or forked version of Hearth), restore aborts with exit `2` rather than silently skipping the unknown data. This prevents a partial restore from appearing successful while quietly discarding state. To recover, ensure the Hearth binary version matches or exceeds the version that produced the archive.

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

### Referential consistency — each realm is snapshotted (HEA-2167)

An export reads each entity type at a different moment during the run (users
first, then credentials, clients, roles, and so on). To stop a concurrent write
from tearing the archive — for example a role assignment referring to a user
created *after* `users.ndjson` was written — the exporter holds a per-node
**consistency barrier** across the whole of a single realm's read pass. Every
entity in a realm's archive therefore reflects one point in time, and every
reference (an assignment's subject, a credential's user) resolves within the
same archive.

**Write-availability impact — know this before you schedule backups.** While an
export holds the barrier, **writes to that node block** until the export's read
pass for the current realm completes; they are not lost, only delayed. Reads —
token validation, session and user lookups — are **never** blocked, so
authentication continues normally during a backup. The blocking window scales
with realm size (how long it takes to scan and serialise the realm's entities),
so for very large realms prefer a low-write window. The barrier is released
between realms, so a multi-realm backup does not hold all writes for the whole
run.

This barrier is **single-node**. Multi-node export consistency is not provided
(clustering is EXPERIMENTAL — see the clustering guide). The offline CLI
(`hearth backup create` against a stopped node's data directory) has no
concurrent writer and so is trivially consistent.

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
