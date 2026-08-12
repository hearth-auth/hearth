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

   When in doubt, run `hearth storage scan` (if available in your build) or
   open each SST through the same engine. The first file that fails to
   open is the corrupt one.

3. **Restore the affected SST from backup.** Hearth SSTs are immutable
   once written, so the bytes in your last `.hearth-backup` archive are
   authoritative for any key range that was already flushed to that SST at
   backup time:

   ```bash
   # Restore the entire realm that owns the corrupt SST.
   # Use --realm if you know which realm's data is in the file (one SST
   # may contain entries from multiple realms — restoring all realms is
   # always safe).
   hearth backup restore \
     --input /backups/latest.hearth-backup \
     --data-dir /var/lib/hearth/data \
     --mode overwrite
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
   ```

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

**Cluster is unavailable or you want a clean slate:**

Wipe the data directory entirely and let the node stream a fresh snapshot on join:

```bash
systemctl stop hearth
rm -rf /var/lib/hearth/data
mkdir -p /var/lib/hearth/data
systemctl start hearth
```

> **Do not manually restore from a backup** while the marker is present — the
> backup captures a point-in-time snapshot that may be older than what the
> cluster leader already applied. Let the leader's snapshot catch-up handle it.

---

## Raft divergence and split-brain

### Failure shape

Symptoms in a multi-node cluster:

- No leader election after `cluster.election_timeout_ms` × 3.
- Followers log `term mismatch` or `index mismatch` on every AppendEntries.
- `hearth cluster status` shows nodes in different `last_log_term` values
  with no path to convergence.

Root causes (in order of frequency):

1. **Clock skew** larger than the leader-timestamp tolerance — see the
   prereq in the [Clustering Guide](./clustering.md). Fix NTP first; many
   "divergence" reports are NTP outages in disguise.
2. **A minority subcluster ran with a forced quorum override** while the
   majority was still alive (true split-brain). Both subclusters now have
   independent log suffixes that cannot be reconciled.
3. **A node was restored from a backup taken at a different log index
   than its peers** — common after a botched per-node restore where the
   operator restored one node from an older archive than the others.

### Recovery steps

The Hearth cluster has no automatic split-brain merge. The operator
designates which side is authoritative; the losing side is wiped and
rejoined empty.

1. **Stop the cluster.** All nodes.

   ```bash
   for n in node-1 node-2 node-3; do
     ssh $n "systemctl stop hearth"
   done
   ```

2. **Pick the authoritative side.** This is a business call —
   typically the side with the higher `applied_index` *and* the most
   recent user-visible writes. Identify it by checking each node's
   storage:

   ```bash
   hearth backup inspect --data-dir /var/lib/hearth/data
   # Record counts per realm; the side with the most recent writes
   # will usually have the highest user/session counts.
   ```

3. **Take a backup of every diverging node** before wiping anything:

   ```bash
   hearth backup create \
     --data-dir /var/lib/hearth/data \
     --include-audit \
     --output /backups/divergence-$(hostname)-$(date +%s).hearth-backup
   ```

   These backups are evidence — store them off-cluster.

4. **Bootstrap the authoritative node alone.** Edit its `hearth.yaml` to
   list only itself in `cluster.peers`, start it, and confirm it elects
   itself leader of a single-node cluster:

   ```bash
   systemctl start hearth
   hearth cluster status   # Should show: leader=this_node, peers=[]
   ```

5. **Wipe the losing nodes' data directories** (after the backups in
   step 3 are confirmed off-cluster):

   ```bash
   ssh node-2 "rm -rf /var/lib/hearth/data && mkdir -p /var/lib/hearth/data"
   ssh node-3 "rm -rf /var/lib/hearth/data && mkdir -p /var/lib/hearth/data"
   ```

6. **Add the wiped nodes back as fresh followers**, restore the full
   `cluster.peers` list on the leader, restart it, then start the empty
   followers. Each one streams a snapshot from the leader (no manual
   restore needed):

   ```bash
   ssh node-1 "systemctl restart hearth"
   ssh node-2 "systemctl start hearth"
   ssh node-3 "systemctl start hearth"
   ```

7. **Reconcile lost writes.** Diff the post-recovery state against the
   per-node backups from step 3 to identify writes that existed on the
   losing side and were not present on the authoritative side. Replay
   them via the normal API as the relevant user/admin.

### Prevention

- Always run an odd number of nodes (3 or 5). Never run 2.
- Never use forced quorum overrides (`--unsafe-force-quorum` flags or
  equivalent) without first confirming the other side is genuinely down.
- Take backups from the leader once daily and from any follower hourly
  — this gives you a per-node history when a divergence occurs.

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

The `IdentityEngine::rotate_realm_signing_key` API (see
`src/identity/engine.rs:2944`) issues a new key, marks the old one
*retiring* with a grace period, and serves both via JWKS until the
grace deadline so in-flight RPs can re-fetch keys without an immediate
verification failure.

1. **Issue the rotation.** Through the admin API or CLI:

   ```bash
   hearth realm rotate-signing-key --realm production \
     --grace-period-hours 24
   ```

   Choose a grace period that matches your slowest RP's JWKS cache TTL
   plus a margin. 24 hours is the conservative default; 1 hour is fine
   for an internally-controlled fleet that polls the JWKS endpoint every
   5 minutes.

2. **Force re-issuance of all in-flight tokens.** Existing access tokens
   stay valid until they hit `exp`. To invalidate immediately, revoke
   every active session in the realm — clients will re-authenticate
   against the new key on next request:

   ```bash
   hearth session revoke-all --realm production
   ```

3. **Verify rotation took effect.** The realm's JWKS should now contain
   two keys (active + retiring); after the grace deadline, only the new
   key remains:

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
     --data-dir /var/lib/hearth/data
   ```

   Exit code `0` means every record imported cleanly. Exit `1` means
   partial success — read the report carefully; some realms/users may be
   missing. Exit `2` means the archive is unreadable; try the previous
   backup.

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

4. **Run the test-restore drill checklist** (below) against the new
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
> spike](../plans/HEA-2170-pitr-wal-archiving-design.md) for the post-1.x
> plan.

Worst-case data loss is **the backup interval plus the duration of one
backup run** — the recovery point is the *start* of a run, not its end:

| Backup cadence | Worst-case data loss |
|---|---|
| Hourly | ~1 hour + one run |
| Every 6 hours | ~6 hours + one run |
| Daily (typical) | ~24 hours + one run |

Measure your own run duration — the RTO table below covers *restore* time,
which is not a proxy for *backup* time (restore is dominated by per-record
re-encryption on write; export is a read scan).

RPO is dominated by your backup schedule, not by Hearth's recovery
mechanics. Hearth itself is durable to the last `fsync` — for any single-
node crash without disk loss, RPO is effectively zero because the WAL
replays on startup.

**Do not read that as disk-loss protection.** The WAL lives inside the data
directory, is truncated in place on rotation rather than retained as
history, and is never shipped off-host. It recovers a crashed process, not
a lost disk.

In cluster mode, RPO for a single-node failure is zero (the other nodes
hold the writes). RPO for whole-cluster loss equals the backup cadence
plus one run.

Archives are also **live scans rather than snapshots**, so an archive taken
while the realm is under write load can be internally inconsistent within
that one-run window — see [Consistency
caveat](./backup.md#consistency-caveat--the-recovery-point-is-an-interval-not-an-instant).

### Recovery Time Objective (RTO) — how long recovery takes

RTO breaks down into archive read time + entity restore time + server
warm-up. These rough numbers come from the
`large_realm_restore_under_60s` performance baseline (`tests/backup.rs`)
and the storage-tier latencies in [Storage Sizing](./storage-sizing.md):

| Deployment size | Backup file size | Restore time | Server warm-up | Total RTO |
|---|---|---|---|---|
| Small (1 realm, 10 k users) | ~30 MB | < 60 s | ~10 s | **< 2 min** |
| Medium (5 realms, 100 k users) | ~300 MB | ~5 min | ~30 s | **< 10 min** |
| Large (20 realms, 1 M users) | ~3 GB | ~30–60 min | ~2 min | **< 90 min** |

The dominant cost in large restores is per-user Argon2id hash rewriting
(credentials are imported verbatim, but the storage layer still encrypts
each row). To meet a tighter RTO for large deployments, consider:

- Restoring per-realm in parallel from the same archive (one CLI
  invocation per realm — they do not contend on writes).
- Pre-staging the archive on the same disk as the target `--data-dir` to
  avoid network read overhead.
- Running on NVMe rather than SATA SSD — the bottleneck after CPU is the
  WAL fsync.

For cluster mode, after restore on one node, expect an additional
1–2 minutes per follower for snapshot streaming, regardless of dataset
size up to ~10 GB.

### Cluster vs single-node trade-offs

| | Single node | Cluster (3 node) |
|---|---|---|
| RPO (node loss, disk loss) | Last backup | Zero |
| RPO (full datacenter loss) | Last backup | Last backup |
| RTO (single failure) | Restore from backup | Promote follower (< 30 s) |
| RTO (cluster-wide failure) | Restore from backup | Restore from backup |
| Operational overhead | Low | NTP, mTLS, quorum management |

For most deployments under 100 k users, single-node Hearth + hourly
backups to off-host storage offers the best RTO/RPO-per-dollar.
Cluster mode shines for deployments where any unplanned outage of even
30 seconds is unacceptable.

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
     --data-dir "$DRILL_DIR" \
     | tee /tmp/restore-report.txt
   echo "exit: $?"
   ```

   Pass criteria: exit `0`, every realm reports `created` counts matching
   the manifest, zero `errored` rows.

4. **Start a drill server** against the restored data:

   ```bash
   hearth serve --data-dir "$DRILL_DIR" --listen 127.0.0.1:8080 &
   DRILL_PID=$!
   sleep 5
   ```

5. **Verify functional invariants.** All four MUST pass; any failure is
   a backup integrity bug — file an issue immediately.

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
     curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/admin/realms
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
