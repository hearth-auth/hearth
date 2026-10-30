# Disaster Recovery Guide

**Audience:** operators responding to or preparing for a catastrophic Hearth failure — corrupted storage, signing-key compromise, Raft split-brain, or full data loss.
**Goal:** Identify the failure shape, execute the correct recovery procedure, and validate functional parity before restoring traffic.
**Time to complete:** Minutes for WAL auto-recovery; 30–90 min for a full restore depending on dataset size. See [RTO and RPO estimation](#rto-and-rpo-estimation) for sizing guidance.

This guide is the operator runbook for recovering a Hearth deployment from
catastrophic events: corrupted SST files, torn WAL writes, Raft log
divergence, signing-key compromise, and full data-loss restore. It
complements the [Backup and Restore Guide](./backup.md) (which covers the
happy-path archive lifecycle) and the [Clustering Guide](./clustering.md)
(which covers normal multi-node operation).

If you are reading this during an active incident, jump straight to the
matching section, then return to the **Test-restore drill** at the end of
the guide once the incident is closed.

| Symptom | Section |
|---|---|
| `ERROR storage: ChecksumMismatch` on startup, single SST file affected | [SST corruption recovery](#sst-corruption-recovery) |
| `ERROR storage: WAL replay: CRC mismatch with trailing data` on startup | [WAL torn-write recovery](#wal-torn-write-recovery) |
| `ERROR storage: data directory '…' is already locked by another process` | [Data directory already locked](#data-directory-already-locked) |
| `ERROR storage: torn Raft snapshot restore detected: marker file '…'` | [Torn Raft snapshot restore](#torn-raft-snapshot-restore) |
| Cluster will not elect a leader / followers refuse to join | [Raft divergence and split-brain](#raft-divergence-and-split-brain) |
| Suspected leak of a realm's signing key | [Post-incident signing-key rotation](#post-incident-signing-key-rotation) |
| Whole node lost — restoring from backup | [Full-restore procedure](#full-restore-procedure) |
| Planning capacity: how long will recovery take? | [RTO and RPO estimation](#rto-and-rpo-estimation) |
| Verifying backups are actually restorable | [Test-restore drill checklist](#test-restore-drill-checklist) |

---

## Recovery invariants

Three invariants hold across every procedure in this guide. If you find
yourself about to break one, stop and escalate before continuing.

1. **Single writer.** Hearth must not be running against the data directory
   you are recovering. Stop the server (`systemctl stop hearth` or
   equivalent) before any manual file manipulation. Hearth holds an
   OS-level advisory `flock` on `{data_dir}/LOCK` — if the file is
   present and locked, the process is still running. Confirm it is released
   before proceeding:
   ```bash
   flock --nonblock /var/lib/hearth/data/LOCK echo "lock is free" \
     || echo "LOCK is held — process still running"
   ```
   A second process opening the same `storage.data_dir` is rejected at
   startup with `ERROR storage: data directory '…' is already locked`
   rather than silently causing WAL corruption.

2. **Snapshot before mutation.** Always copy the data directory to a
   parallel path (`cp -a data data.pre-recovery.$(date +%s)`) before
   touching it. Hearth's on-disk format is forgiving but recovery steps
   that delete files (e.g. truncating a corrupt SST) cannot be undone.

3. **Signing-key continuity.** Restores preserve the realm's Ed25519
   signing key by design (see HEA-745). Every issued JWT keeps validating
   after restore. If you intentionally need a fresh key — for example after
   suspected key leak — do this explicitly with `rotate_realm_signing_key`,
   never by deleting the archive's `signing_key.json`.

---

## SST corruption recovery

### Failure shape

On startup, Hearth opens every SST file in `data/sst/` and verifies the
CRC32 of its decrypted contents. A mismatch surfaces as:

```
ERROR storage: ChecksumMismatch { offset: <N> }
ERROR hearth: failed to open storage engine
```

This usually indicates one of:

- Disk-level bit rot (most common on consumer-grade SSDs without
  end-to-end ECC).
- Filesystem corruption from an unclean shutdown without `data=ordered` /
  journaling, or a kernel panic during fsync.
- A botched manual file copy that lost bytes (e.g. `cp` over NFS without
  `--checksum`).

### Recovery steps

1. **Stop the server and snapshot.**

   ```bash
   systemctl stop hearth
   cp -a /var/lib/hearth/data /var/lib/hearth/data.pre-recovery.$(date +%s)
   ```

2. **Identify the affected SST.** The CRC error currently surfaces only
   the byte offset within the file. Find the file by running:

   ```bash
   ls -la /var/lib/hearth/data/sst/*.sst
   # Compare mtimes against the time the error first appeared
   ```

   When in doubt, cross-reference each SST file's mtime against the
   timestamp the error first appeared in your logs — the last file written
   before the crash is typically the torn one.

3. **Restore the affected SST from backup.** Hearth SSTs are immutable
   once written, so the bytes in your last `.hearth-backup` archive are
   authoritative for any key range that was already flushed to that SST at
   backup time:

   Restore into a **fresh** data directory, then cut over. Restore refuses to
   replace a realm that is already present (audit 2026-08-28 §3 B3), so
   restoring on top of the damaged directory will not work — and the
   `--mode overwrite` this step used to prescribe is what destroyed the realm
   in 975 of 1,160 recorded runs.

   ```bash
   # Restore the entire realm that owns the corrupt SST into a new directory.
   # Use --realm if you know which realm's data is in the file (one SST
   # may contain entries from multiple realms — restoring all realms is
   # always safe).
   systemctl stop hearth

   hearth backup restore \
     --input /backups/latest.hearth-backup \
     --config /etc/hearth/hearth.yaml \
     --data-dir /var/lib/hearth/data-restored

   # Cut over only after the restore reports success.
   mv /var/lib/hearth/data /var/lib/hearth/data.corrupt.$(date -u +%Y%m%dT%H%M%SZ)
   mv /var/lib/hearth/data-restored /var/lib/hearth/data

   systemctl start hearth
   ```

4. **If no backup is available**, you must accept the data loss in the
   corrupted SST and let Hearth scan the remaining tiers to converge.
   Move the corrupt file aside and restart:

   ```bash
   mv /var/lib/hearth/data/sst/<corrupt-file>.sst \
      /var/lib/hearth/data.pre-recovery.<timestamp>/

   systemctl start hearth
   ```

   Any keys whose only durable copy lived in that SST are gone. The
   prefix scans that converge cleanly without the file are: any key range
   whose newer values were re-written by subsequent operations (these
   land in later SSTs), and any key range that lives entirely in the WAL
   or memtable. Realm registry keys (`realm:id:`, `realm:name:`,
   `realm:key:`) are typically small enough that the system-realm SST
   holds the whole index — if that SST is the corrupt one, restore from
   backup is mandatory.

5. **Verify** by running a checksum scan on the now-clean data dir:

   ```bash
   hearth backup create --data-dir /var/lib/hearth/data --output /tmp/post-recovery.hearth-backup
   hearth backup verify --input /tmp/post-recovery.hearth-backup
   rm /tmp/post-recovery.hearth-backup
   ```

   This archive is a checksum scan, not a restore point: it is unsigned, so
   `hearth backup restore` refuses it outside dev mode. If you want a
   post-recovery restore point, take a signed one into your backup directory
   (`hearth backup create --sign-key /etc/hearth/backup-signing.pem --output
   /backups/…`) — see [Signed archives](./backup.md#signed-archives).

---

## WAL torn-write recovery

### Failure shape

After an unclean shutdown (power loss, OOM kill, `kill -9` during a flush)
you may see:

```
WARN storage: WAL replay: CRC mismatch with trailing data —
              truncating to last good record (possible concurrent
              write fault or unclean shutdown)
```

This is **handled automatically**: Hearth's WAL reader (see
`src/storage/wal.rs:656`) stops at the first CRC failure and truncates
everything after the last fully-verified record. Operators do not
intervene for the normal torn-write case.

### When operator action is required

- **The warning persists across multiple restarts.** This indicates the
  WAL contains a record with a valid CRC followed by a corrupt one — i.e.
  the storage stack is producing torn writes mid-record, not just at the
  tail. Stop using the underlying disk, copy the data directory to known-
  good storage, and restart.

- **You need to know what was lost.** The records discarded by truncation
  are exactly those whose response to the client had not yet been sent —
  by the at-least-once delivery contract, any client that received `200
  OK` saw its write durable. If you must reconcile, replay the request
  log of the upstream component (load balancer, reverse proxy) for the
  uncertain window.

- **Replication-driven divergence (cluster mode).** A follower may
  legitimately discard tail records that conflict with the leader. The
  Raft log replay supersedes the local WAL in that case — no operator
  action needed.

### Partial WAL header

A WAL segment starts with an 82-byte header: a 4-byte `HWAL` magic, a 2-byte
format version, and a 76-byte encryption header. Hearth writes it in one call,
when it creates a segment and again each time it rotates one. A write fault at
that moment (a full disk, a failing device) can still leave the header short.

You see this at startup:

```
WARN storage: WAL recovery: header is shorter than one complete header
              (write fault during segment creation or rotation) —
              re-initialising an empty segment; no record can be lost
              because the record region starts at byte 82
```

This is **handled automatically**, and it loses nothing. Records begin at byte
82, and the shortest record is 24 bytes, so a segment of 81 bytes or fewer holds
no record at all. Hearth re-initialises it as an empty segment and starts.

If the fault happened during a *rotation*, the writes that segment held were
already flushed to an SST before the truncation, so they are still on disk.
Hearth also fences the WAL at that point, so every write after the fault is
refused rather than acknowledged:

```
ERROR storage: WAL rotation failed after the segment was truncated;
               the next start re-initialises the segment
```

**When operator action is required.** If the warning returns on every restart,
the device is rejecting writes. Stop writing to it, copy the data directory to
known-good storage, and restart there. There is no manual repair command: do
**not** hand-edit or delete a WAL segment that is 82 bytes or longer, because
that one does hold records.

---

## WAL write fence

### Failure shape

A write fault in the WAL fences it. A fenced node serves reads normally and
refuses **every** write, because bytes written after a torn record are discarded
on replay: acknowledging them would acknowledge data that recovery throws away.

You see this once, when it engages:

```
ERROR storage: WAL write fence engaged — every subsequent write is refused
               for the life of this process; restart to clear it.
               /readyz reports not-ready.
```

`reason` names the fault that engaged it: `group_commit_write_fault`,
`rotation_write_fault`, `write_rollback_failed`, or
`record_counter_unreleasable`.

### How to detect it

| Signal | What you see |
|--------|--------------|
| `/readyz` | `503`, body `{"status":"not_ready","storage":"write_fenced"}` |
| `/metrics` | `hearth_wal_write_fenced{reason="..."} 1` |
| Logs | the `ERROR storage: WAL write fence engaged` line above |

The metric time series is **absent** during normal operation. Its presence on a
live scrape means that node accepts no writes. Alert on presence, not on value:

```yaml
- alert: HearthWalWriteFenced
  expr: hearth_wal_write_fenced == 1
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Hearth node {{ $labels.instance }} refuses all writes (WAL fenced)"
```

### Recovery

**A fence is permanent for the life of the process.** Restart Hearth to clear
it. In a cluster, `/readyz` already removed the node from the load balancer, so
a restart is not a further outage.

A fence that returns after the restart means the device is rejecting writes.
Follow **Partial WAL header** above: move the data directory to known-good
storage.

---

## Data directory already locked

### Failure shape

Hearth refuses to start and prints:

```
ERROR storage: data directory '/var/lib/hearth/data' is already locked
               by another process; stop the running Hearth instance
               before starting a new one
```

This means an OS-level advisory `flock` on `{data_dir}/LOCK` is already held.
Two separate processes must never share a `storage.data_dir` — the second writer
would corrupt the WAL.

Common causes:

- A previous `hearth serve` process is still running (common after a failed
  `systemctl restart` or a direct `hearth serve` invocation that was
  backgrounded and forgotten).
- A Helm rollout used `strategy.type: RollingUpdate` instead of `Recreate`,
  so the new pod started before the old one terminated. The Helm chart sets
  `strategy.type: Recreate` by default to prevent this.
- Two manual invocations pointed at the same `--data-dir`.

### Recovery steps

1. **Find the process holding the lock:**

   ```bash
   flock --nonblock /var/lib/hearth/data/LOCK echo "free" \
     || echo "locked — finding owner"
   # If locked:
   lsof /var/lib/hearth/data/LOCK
   ```

2. **Stop it cleanly:**

   ```bash
   systemctl stop hearth
   # or: kill <pid>
   ```

3. **Confirm the lock is released**, then start Hearth again:

   ```bash
   flock --nonblock /var/lib/hearth/data/LOCK echo "lock is free"
   systemctl start hearth
   ```

The `LOCK` file itself is never deleted — its presence is expected. Only the `flock`
lease matters. Do not delete `LOCK`; it is recreated on startup but its absence
prevents the advisory lock from working on the next run.

---

## Torn Raft snapshot restore

### Failure shape

After a follower crash or kill during Raft snapshot install, Hearth refuses to
start and prints:

```
ERROR storage: torn Raft snapshot restore detected: marker file
               '/var/lib/hearth/data/SNAPSHOT_RESTORE_IN_PROGRESS'
               (snapshot <id>) was left by a process killed between
               Phase 1 (delete) and Phase 2 (replay); delete the
               marker file and restart so the node can re-request
               the snapshot from the leader, or wipe the data directory entirely
```

### Why this happens

Hearth's Raft snapshot install is a two-phase operation:

- **Phase 1** — delete all realm keys from the local data directory.
- **Phase 2** — replay the leader's snapshot data into the now-empty directory.

Before Phase 1 begins, the engine writes `{data_dir}/SNAPSHOT_RESTORE_IN_PROGRESS`
durably to disk. After Phase 2 completes, the marker is removed. If the node is
killed between the two phases, the marker remains and the data directory contains
a partial (empty or mixed) state. Hearth refuses to serve reads from this state
rather than silently returning incorrect data.

### Recovery

The node needs to receive the snapshot again from the leader. The recovery steps
depend on whether the cluster is healthy.

**Cluster is healthy (preferred path):**

1. Delete the marker file:

   ```bash
   rm /var/lib/hearth/data/SNAPSHOT_RESTORE_IN_PROGRESS
   ```

2. Restart the node:

   ```bash
   systemctl start hearth
   ```

The node re-joins the cluster, the leader detects that it is behind, and
re-sends the snapshot. Phase 1 + Phase 2 run to completion; the marker
is removed automatically.

If the node's Raft log has been purged, this restart is refused instead
(`this node's Raft log is purged through index N but its data directory
holds no persisted applied state …`): Phase 1 removed the node's persisted
applied index, and the log no longer holds the entries to rebuild from.
The node cannot rejoin. Use the path below.

**The restart is refused, or the cluster has no leader:**

There is no safe way to bring this one node back. **Do not wipe its data
directory and start it empty.** The data directory holds `raft.db`, and a
node that starts empty under its old node ID has forgotten its Raft vote.
Raft's safety proof does not allow for that, and the node with the lowest
ID also starts a cluster of its own
([CONSISTENCY.md](../dev/CONSISTENCY.md) G9; Clustering Guide
[C-6](./clustering.md#c-6--cluster-membership-is-immutable-after-bootstrap)).
Recover from a backup instead:

1. Stop every node.
2. Rebuild the cluster from your most recent signed backup with the
   upgrading guide's [rebuild procedure](./upgrading.md#cluster-purged-log-upgrade):
   restore once into one empty data directory and copy that directory to
   every node before the new cluster first starts. Or restore the backup
   onto one node and run it as a single node, which is the supported
   deployment shape.

Writes made after that backup are lost (see [RPO](#recovery-point-objective-rpo--how-much-data-you-can-lose)).

> **Do not restore a backup into this one node** while the other nodes run:
> the backup is older than what the leader already applied, and a node
> restored on its own diverges from its peers.

---

## Raft divergence and split-brain

> **Cluster mode is experimental and not supported for production**
> ([Clustering Guide](./clustering.md)). The supported deployment is one
> node with tested backups. This section tells you how to get back to a
> known state from a cluster that diverged. It does not repair the cluster
> in place: Hearth has no operation that does.

### Failure shape

Symptoms in a multi-node cluster:

- `GET /admin/cluster/status` shows no node with `"role":"leader"` for
  longer than a few election rounds, or two nodes that each report
  `"role":"leader"`.
- Followers log `term mismatch` or `index mismatch` on every AppendEntries.
- `GET /admin/cluster/status` shows nodes with different `last_log_term`
  values and no path to convergence.

Known causes:

1. **A node was started with an empty data directory under its old node
   ID.** The data directory holds `raft.db`, so the node has forgotten its
   Raft vote, and if it has the lowest node ID it starts a cluster of its
   own ([CONSISTENCY.md](../dev/CONSISTENCY.md) G9). This is the most
   likely cause, because older revisions of these guides told operators
   to replace a node this way.
2. **A node was restored from a backup on its own**, so its state comes
   from a different point than its peers.
3. **Clock skew** larger than the leader-timestamp tolerance — see the
   prerequisites in the [Clustering Guide](./clustering.md). Fix NTP first.

### Recovery steps

Membership lives in each node's `raft.db` and is fixed at bootstrap.
Editing `cluster.peers` in `hearth.yaml` does not change it, and a node
initialises Raft only when its data directory is empty
([C-6](./clustering.md#c-6--cluster-membership-is-immutable-after-bootstrap)).
So you cannot shrink the cluster to the surviving side, and you cannot
re-add a wiped node. The only recovery is to stop the cluster and start
again from one node's data.

1. **Stop every node.**

   ```bash
   for n in node-1 node-2 node-3; do
     ssh $n "systemctl stop hearth"
   done
   ```

2. **Take a signed backup of every node** before you change anything.
   These backups are your evidence and your source of data. Store them
   off the cluster:

   ```bash
   hearth backup create \
     --data-dir /var/lib/hearth/data \
     --include-audit \
     --sign-key /etc/hearth/backup-signing.pem \
     --output /backups/divergence-$(hostname)-$(date +%s).hearth-backup
   ```

   `hearth backup create` takes an exclusive lock on the data directory,
   so the node must be stopped (step 1). Restore refuses an unsigned
   archive outside dev mode. If the signing key lives only on a separate
   backup host, omit `--sign-key` and run `hearth backup sign` on each
   archive there ([Signed archives](./backup.md#signed-archives)).

3. **Pick the authoritative node.** This is a business decision: usually
   the node whose data has the most recent user-visible writes. Compare the
   archives:

   ```bash
   hearth backup inspect --input /backups/divergence-node-1-<ts>.hearth-backup
   # Prints per-realm record counts: users, credentials, clients, roles,
   # groups, orgs, audit.
   ```

   Sessions are **not** in the archive, so the counts show which node holds
   more durable records, not which node served more logins.

4. **Start again from the authoritative node's backup.** Choose one:

   - **One node (supported).** Restore the backup onto one node and run it
     without a `cluster:` section, as described in
     [Restoring to a new node](./backup.md#restoring-to-a-new-node).
   - **A new cluster (experimental).** Follow the upgrading guide's
     [rebuild procedure](./upgrading.md#cluster-purged-log-upgrade):
     every node starts with an empty data directory, you restore the
     backup once into one empty data directory, and you copy that directory
     to every node before the new cluster first starts. Never restore once
     per node, and never restore into a cluster that has already started.

5. **Reconcile lost writes.** Compare the restored state with the backups
   of the other nodes from step 2, to find writes that only the losing
   side had. Make them again through the normal API, as the relevant user
   or admin.

### Prevention

- Never start a node of a running cluster with an empty data directory.
  There is no supported way to replace a failed node
  ([CONSISTENCY.md](../dev/CONSISTENCY.md) G5 and G9).
- Never restore a backup into one node of a cluster.
- Take backups from the leader, and keep a history of them. See
  [Cluster deployments](./backup.md#cluster-deployments).

---

## Post-incident signing-key rotation

Hearth's restore path preserves signing keys (HEA-745) so that JWTs
issued before backup remain valid after restore. This is the right
default for routine operations. After certain incidents the **opposite**
property is required: every pre-incident JWT must be invalidated. Examples:

- Suspected leak of a realm's PKCS#8 signing key (e.g. operator
  workstation compromise, accidental commit of `realm:key:*` storage
  bytes).
- Cryptographic-library CVE that retroactively weakens existing tokens.
- Compliance requirement to invalidate all tokens after a privileged
  user offboards.

### Rotation procedure

Rotation issues a new key and, by default, **revokes every retired key
for the realm**. A token signed with the old key stops validating at
once. That is what makes rotation a remedy for a leaked key: while the
old key stays valid, whoever holds it keeps minting new credentials.

A *planned* rotation — routine key hygiene, no incident — may keep
existing sessions alive by opting into a grace window, during which
JWKS serves both keys so relying parties can re-fetch before their
tokens fail. Never use a window after a compromise.

1. **Issue the rotation.** Call the admin API with the realm's UUID:

   ```bash
   curl -s -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "X-Realm-ID: <realm-uuid>" \
     https://auth.example.com/admin/realms/<realm-uuid>/rotate-signing-key
   # Returns: {"message":"signing key rotated","grace_period_secs":<N>}
   ```

   `X-Realm-ID` is **mandatory** on every `/admin` route — without it the
   server answers `400 {"error":"missing X-Realm-ID header"}`, not `401`.
   The token must carry `hearth.realm.admin` and be scoped to the same
   realm named in the path; a token from another realm gets `403`.

   The response reports `"grace_period_secs":0` — the retired key is
   revoked. This is the correct call for an incident.

   The rotation also records, in the same atomic write, every key it
   retires or revokes. A later backup restore — even of an archive made
   before the rotation, and even after the realm is deleted — refuses to
   reinstall any of them, so restoring an old backup cannot undo the
   revocation.

   For a **planned** rotation, ask for a window explicitly:

   ```bash
   curl -s -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "X-Realm-ID: <realm-uuid>" \
     "https://auth.example.com/admin/realms/<realm-uuid>/rotate-signing-key?grace_period_secs=3600"
   ```

   Choose a window that matches your slowest RP's JWKS cache TTL plus a
   margin — 1 hour suits an internally-controlled fleet that polls JWKS
   every 5 minutes. A value that is not a non-negative integer is
   rejected with `400`.

   `token.signing_key_rotation_grace_period` in `hearth.yaml` sets the
   window for the config-driven rotation (`rotate_signing_key: true` on a
   realm, applied at startup). Left unset it defaults to the longest
   refresh-token lifetime the config can issue, so a planned rotation does
   not sign out sessions whose refresh tokens are still valid. It does
   **not** change this endpoint, which revokes unless the request says
   otherwise.

   Both paths write a `realm_updated` audit event carrying
   `metadata.action = "rotate_signing_key"`; the config-driven one adds
   `metadata.source = "config"` and an actor of `system`.

   In a cluster, rotation is visible to every node: the rotation epoch is
   persisted alongside the key material and replicated, and each node drops
   its local signing-key and token-claims caches when it sees the epoch
   move. You do not need to restart the other nodes.

2. **Force re-issuance of all in-flight tokens.** Existing access tokens
   stay valid until they hit `exp`. To invalidate all active sessions
   immediately, bump the session version for the realm — clients will
   re-authenticate against the new key on their next request:

   ```bash
   curl -s -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "X-Realm-ID: <realm-uuid>" \
     https://auth.example.com/admin/realms/<realm-uuid>/sv-bump-all
   # Returns: {"bumped":<n>}
   # Returns 404 if session versioning is disabled for this realm.
   ```

   Also requires `hearth.realm.admin`. This is a heavy operation — it
   generates one delta entry per active session.

3. **Verify rotation took effect.** After a revoking rotation the
   realm's JWKS carries only the new key. After a rotation with a
   window it carries two (active + retiring) until the deadline:

   ```bash
   curl https://auth.example.com/realms/production/.well-known/jwks.json
   ```

4. **For a true compromise**: in addition to rotation, audit-log every
   API call and admin action since the suspected leak window — the
   leaked key signed those tokens, so anything authenticated by them
   needs review.

### When to combine rotation with restore

If you restored from a backup *and* the backup itself was suspect (the
leak window predates the backup), perform restore first, then rotate
immediately. The restored realm comes up with the original
signing key (per HEA-745); rotation then invalidates that key and all
tokens issued before rotation.

---

## Full-restore procedure

This is the procedure for rebuilding a deployment from a backup archive
after total data loss (disk failure with no snapshot, accidental `rm
-rf`, ransomware). It is the same as the [routine restore in the Backup
guide](./backup.md#restoring-to-a-new-node) but with an explicit
post-restore validation checklist appropriate for an incident.

1. **Install Hearth** at the same major.minor version as the backup. The
   archive `manifest.json` records the source `hearth_version`; verify
   with `hearth backup inspect --input <archive>` before continuing.

2. **Prepare an empty data directory** and restore:

   ```bash
   mkdir -p /var/lib/hearth/data
   hearth backup restore \
     --input /backups/latest.hearth-backup \
     --config /etc/hearth/hearth.yaml \
     --data-dir /var/lib/hearth/data
   ```

   Exit code `0` means every record imported cleanly. Exit `1` means
   partial success — read the report carefully; some realms/users may be
   missing. Exit `2` means the archive is unreadable or was refused; try the
   previous backup.

   Restore authenticates the archive first: its manifest signature must verify
   against `security.backup.verify_key` (read from `--config`, or pass
   `--verify-key`). An unsigned archive, a bad signature, or no configured key
   is refused before anything is written — see
   [Signed archives](./backup.md#signed-archives). In an incident, do **not**
   reach for `--allow-unsigned` to get past a refusal: an archive that fails
   authentication may be the attacker's. Use it only for an archive whose
   origin you have established out of band.

3. **Verify signing-key continuity.** Hearth's restore preserves the
   per-realm Ed25519 signing key (HEA-745). A token issued before backup
   should still validate. Use `curl` plus `jq` to compare a saved JWKS
   from before the incident against the post-restore JWKS:

   ```bash
   hearth serve -c /etc/hearth/hearth.yaml &
   sleep 5
   curl -s https://auth.example.com/realms/production/.well-known/jwks.json \
     | jq '.keys[0].kid'
   # Compare against the kid saved from the pre-incident JWKS snapshot.
   # They MUST match.
   ```

4. **Confirm operator-console access.** The restore's last lines say what it
   did with the **system realm** — the realm that holds every operator-console
   account — based on what was actually imported:

   - `System realm: N operator-console account(s) restored; …` — those
     operators sign in at `/ui/admin/login` with their original passwords and
     second factors (sessions are not restored, so everyone signs in again).
     The line also says what happened to the system signing key; into an empty
     data directory the archived key is installed, so system-realm tokens keep
     their `kid`. Any operator reported as refused did **not** come back. Sign
     in once now: the cluster endpoints (`/admin/cluster/*`) and every
     cross-realm operation need a system-realm token.
   - `System realm: this restore did NOT restore operator-console access — …`
     — the archive carried the system realm but no operator came back from it
     (each was already present and kept, or was refused). Existing operators
     keep their current credentials; check the counts it prints.
   - `This restore does not contain the system realm …` — the archive brought
     back no operator account, and a restored store holds realms, so the
     first-run setup URL is not issued. Restore the system realm from another
     archive **before** you start the server: an unfiltered
     `hearth backup create` (it includes the system realm), or a
     `POST /admin/backup` made by a system-realm caller on this release or
     later. HTTP exports from v1.6.11 and earlier never carried it. A second
     restore into the same data directory adds it:

     ```bash
     hearth backup restore \
       --input /backups/system-realm.hearth-backup \
       --config /etc/hearth/hearth.yaml \
       --data-dir /var/lib/hearth/data
     ```

   Tenant realms' own admins keep working against `/admin` with their realm's
   `X-Realm-ID` either way. See
   [Restoring the system realm](./backup.md#restoring-the-system-realm) for the
   skip / merge / overwrite rules and who may restore it.

5. **Run the test-restore drill checklist** (below) against the new
   deployment to confirm functional parity, then cut over traffic.

---

## RTO and RPO estimation

These are baseline planning numbers, not guarantees. Measure on your
actual hardware and storage during the [test-restore
drill](#test-restore-drill-checklist).

### Recovery Point Objective (RPO) — how much data you can lose

> **Hearth has no point-in-time recovery, no WAL archiving, and no
> incremental backup.** Your recovery point is the last successful full
> backup. See the [backup guide's RPO
> statement](./backup.md#recovery-point-objective-rpo) for the canonical
> operator-facing wording and the [design
> spike](https://github.com/hearth-auth/hearth/blob/4d9dda1f5b514891e90dadeffb03d1a026af4e51/docs/plans/HEA-2170-pitr-wal-archiving-design.md) for the post-1.x
> plan.

Worst-case data loss is **the backup interval plus the duration of one
backup run** — the recovery point is the *start* of a run, not its end:

| Backup cadence | Worst-case data loss |
|---|---|
| Hourly | ~1 hour + one run |
| Every 6 hours | ~6 hours + one run |
| Daily (typical) | ~24 hours + one run |

Measure your own run duration. In the restore drill, `POST /admin/backup` of a
realm with 1,000,000 users took 5.5 s ([Measured times](#measured-times)), so the
backup interval is the dominant term. Do not use the restore time as an
estimate of the backup time: in the same drill, the restore took 100 times
longer than the backup.

RPO is dominated by your backup schedule, not by Hearth's recovery
mechanics. Hearth itself is durable to the last `fsync` — for any single-
node crash without disk loss, RPO is effectively zero because the WAL
replays on startup.

**Do not read that as disk-loss protection.** The WAL lives inside the data
directory, is truncated in place on rotation rather than retained as
history, and is never shipped off-host. It recovers a crashed process, not
a lost disk.

Cluster mode is experimental and is not a recovery plan: there is no
supported way to replace a failed node, so plan your RPO on backups alone.

Each realm in an archive reflects one point in time, because the exporter
holds a per-realm consistency barrier, but different realms reflect
different points within the run — see [Referential
consistency](./backup.md#referential-consistency--each-realm-is-snapshotted-hea-2167).

### Recovery Time Objective (RTO) — how long recovery takes

RTO is the sum of these times:

1. The time to get a host and to copy the archive to it. The restore drill
   does not measure this time.
2. The restore (`hearth backup restore`).
3. The start of the server until `/readyz` answers 200.

After a restore, every user must sign in again, because a backup does not
carry sessions ([What a backup does not
carry](./backup.md#what-a-backup-does-not-carry)).

#### Measured times

The [restore drill](./backup.md#restore-drill) measured these times on
2026-10-30, on `main` at `09711488` (v4.6.15 and #696). The runner is a
GitHub-hosted runner with 4 CPUs and 16 GB of memory. Each run passed all 14
checks of the drill.

| Users (one realm) | Archive | `POST /admin/backup` | Restore | Start until `/readyz` answers 200 | Recovery (restore and start) | Run |
|---:|---:|---:|---:|---:|---:|---|
| 250,000 | 67.4 MiB | 1.4 s | 2 min 41 s | 4.0 s | 2 min 45 s | [41100519533](https://github.com/hearth-auth/hearth/actions/runs/41100519533) |
| 500,000 | 135.0 MiB | 2.9 s | 3 min 42 s | 4.0 s | 3 min 46 s | [41100522563](https://github.com/hearth-auth/hearth/actions/runs/41100522563) |
| 1,000,000 | 270.4 MiB | 5.5 s | 9 min 10 s | 3.0 s | 9 min 13 s | [41097818397](https://github.com/hearth-auth/hearth/actions/runs/41097818397) |

The restore time changes from run to run. On 2026-10-29, before #696, the same
drills restored 250,000 users in 1 min 28 s, 500,000 users in 4 min 4 s and
1,000,000 users in 7 min 38 s
([40941183987](https://github.com/hearth-auth/hearth/actions/runs/40941183987),
[40941187987](https://github.com/hearth-auth/hearth/actions/runs/40941187987),
[40932385441](https://github.com/hearth-auth/hearth/actions/runs/40932385441)).
#696 changed the backup only, not the restore.

**The drill data is smaller than most production data.** The imported users
have no password, no MFA factor and one custom attribute. Only four users have
a password. A realm in which each user has a password or MFA factors, or that
has groups and organizations, gives a larger archive and a longer restore.
Use these times for a first plan only, and measure on your own data and
hardware.

The restore CLI processes one realm after the other. To make the RTO
shorter for a large deployment:

- Put the archive on the same disk as the target `--data-dir` before you
  start, so that the restore does not read it over the network.
- Use NVMe storage rather than SATA SSD, because every restored write is
  synced to disk.

### Supported deployment shape

The supported deployment is **one node, with backups to off-host storage
and a restore you have tested** (see the drill below). Your RPO is your
backup interval plus one run. Your RTO is the time to restore the latest
backup onto a new node and start it.

For one realm with 1,000,000 users on the drill runner, one backup run took
5.5 s, and the restore and start took 8 to 10 minutes ([Measured
times](#measured-times)). With hourly backups, the RPO is about one hour.
The RTO is about 10 minutes, plus the time to get a host and to copy the
archive to it.

Cluster mode is experimental and gives you no shorter RTO today. Hearth has
no operation that promotes a follower, membership is fixed at bootstrap,
and per-node state does not survive a node switch
([Clustering Guide](./clustering.md)). A failed cluster node cannot be
replaced; the recovery is a restore from backup, as for one node.

---

## Test-restore drill checklist

Run this drill quarterly. An untested backup is not a backup.

1. **Pick the most recent backup** of production. Do not synthesise a
   test fixture — the point is to exercise real archive bytes.

   ```bash
   ls -la /backups/ | tail -5
   ```

2. **Stand up an isolated drill environment.** A laptop, a `tmpdir`, or
   a throwaway VM — anywhere with no network path to a production data
   directory.

   ```bash
   DRILL_DIR=$(mktemp -d)
   ```

3. **Restore the archive** into the drill environment and capture the
   exit code:

   ```bash
   hearth backup restore \
     --input /backups/latest.hearth-backup \
     --config /etc/hearth/hearth.yaml \
     --data-dir "$DRILL_DIR" \
     | tee /tmp/restore-report.txt
   echo "exit: $?"
   ```

   Pass criteria: exit `0`, every realm reports `created` counts matching
   the manifest, zero `errored` rows.

4. **Start a drill server** against the restored data:

   `hearth serve` has no `--data-dir` flag — the data directory comes from
   the config file only. Write a throwaway config pointing at the drill
   directory, then bind with `--bind`/`--port`:

   ```bash
   cat > /tmp/drill.yaml <<EOF
   storage:
     data_dir: "$DRILL_DIR"
   EOF
   hearth serve --config /tmp/drill.yaml --bind 127.0.0.1 --port 8080 &
   DRILL_PID=$!
   sleep 5
   ```

5. **Verify functional invariants.** All of them MUST pass; any failure is
   a backup integrity bug — file an issue immediately. Also read the restore
   report: a client it lists as not restored was refused because its archived
   record could not be restored as strong as its source (see
   [Client credentials](backup.md#client-credentials)).

   - [ ] JWKS responds for every realm in the manifest:
     ```bash
     curl -fsS http://127.0.0.1:8080/realms/<realm>/.well-known/jwks.json
     ```
   - [ ] Signing-key continuity holds — `kid` matches the pre-restore
     production JWKS:
     ```bash
     diff \
       <(curl -fsS https://auth.example.com/realms/<realm>/.well-known/jwks.json | jq .keys[0].kid) \
       <(curl -fsS http://127.0.0.1:8080/realms/<realm>/.well-known/jwks.json | jq .keys[0].kid)
     ```
   - [ ] At least one known user can authenticate with their existing
     password (run against the drill server, not prod) — navigate to the
     browser login UI and sign in manually:
     ```
     http://127.0.0.1:8080/ui/admin/login
     ```
     Hearth does not support `grant_type=password` (ROPC was removed in HEA-1862).
     Use the browser-based authorization code flow for user credential verification.
   - [ ] At least one OAuth client can complete `client_credentials` and
     the returned access token validates:
     ```bash
     TOKEN=$(curl -fsS -X POST http://127.0.0.1:8080/oauth/token \
       -d grant_type=client_credentials -d client_id=<id> -d client_secret=<secret> \
       | jq -r .access_token)
     curl -fsS -H "Authorization: Bearer $TOKEN" \
       -H "X-Realm-ID: <realm-uuid>" \
       http://127.0.0.1:8080/admin/realms
     ```
     `X-Realm-ID` is required on `/admin` routes; omitting it returns `400`,
     which `-fsS` surfaces as a drill failure indistinguishable from a real
     backup-integrity bug. Use the UUID of the realm the client belongs to.
   - [ ] The same client is still **refused without its secret** — a restore
     that dropped the credential would turn it into a public client that
     anyone knowing its `client_id` can act as:
     ```bash
     curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/oauth/token \
       -d grant_type=client_credentials -d client_id=<id>
     # expect 401
     ```

6. **Tear down and document.**

   ```bash
   kill "$DRILL_PID"
   rm -rf "$DRILL_DIR"
   ```

   Record the drill outcome (date, archive name, exit code, time to
   restore, any failures) in your operational log. Track the trend over
   time — restore times that creep upward signal storage growth that may
   threaten your RTO target.

7. **Schedule the next drill.** Quarterly minimum, monthly for
   deployments with strict RTO commitments.

---

## Related material

- [Upgrading Guide](./upgrading.md) — pre-upgrade checklist, binary swap, rollback procedure.
- [Backup and Restore Guide](./backup.md) — archive format, CLI
  reference, scheduled-backup recipes.
- [Clustering Guide](./clustering.md) — multi-node operation,
  certificate management, peer configuration.
- [Storage Sizing Guide](./storage-sizing.md) — tier latencies and
  capacity planning baselines.
- [Security Hardening Guide](./security-hardening.md) — production
  configuration for the security-sensitive surfaces touched in this
  guide.
- HEA-745 — the signing-key persistence fix and regression test
  referenced throughout the post-incident sections.
