# Upgrading Hearth

**Audience:** operators running a Hearth deployment who need to upgrade to a newer release.
**Goal:** Replace the running binary (or container image) safely, verify the new version is healthy, and know exactly how to roll back if something goes wrong.
**Time to complete:** 5–10 minutes for a single-node deployment; 15–30 minutes for a cluster.

Hearth is a single-binary server with an embedded storage engine. Upgrading means swapping the binary (or container image) and restarting the process. There is no separate database migration tool or schema migration step — WAL format migrations run automatically on startup.

---

## Before you start

### Pre-upgrade checklist

Work through this list for every upgrade, including patch releases.

- [ ] **Read the CHANGELOG.** Check `CHANGELOG.md` for your target version. Look for `### Changed`, `### Removed`, and `### Security` entries that affect your configuration or integration. Breaking changes are prefixed `**Breaking:**`.
- [ ] **Take a backup.** Run this immediately before the upgrade — even if you took one last night.

  > **Stop the server first.** `hearth backup create` opens the store directly and
  > the data directory carries an exclusive `LOCK`. Against a running instance it
  > exits `2` with `data directory '…' is already locked by another process`. So the
  > real order is: stop the service (step 1 of the [upgrade procedure](#upgrade-procedure)),
  > take the backup, install the new binary, start. Budget the backup into your
  > downtime window rather than treating it as a pre-flight step.

  > **Give it the key-encryption key.** A production store's signing keys are
  > encrypted at rest, and the command cannot read them without the KEK. Export
  > `HEARTH_KEK`, or pass `--config` pointing at the `hearth.yaml` that carries
  > `security.key_encryption_key`. `HEARTH_MASTER_KEY` must be set as well, just
  > as it is for `serve`.

  > **Sign it now, not during a rollback.** The [rollback](#rollback-procedure) restores
  > this archive, and restore refuses an unsigned archive outside dev mode
  > (exit `2`: `the archive is unsigned` with a verify key configured,
  > `no backup verify key is configured` without one). Pass
  > `--sign-key` so the archive is restorable the moment it is written. If the
  > signing key lives only on a separate backup host, copy the archive there and
  > run `hearth backup sign` on it before you start the upgrade — do not leave
  > that step for the middle of a rollback. See
  > [Signed archives](./backup.md#signed-archives).

  ```bash
  export HEARTH_KEK=$(cat /etc/hearth/kek.hex)
  PRE_UPGRADE=/backups/pre-upgrade-$(date +%Y%m%d-%H%M%S).hearth-backup

  hearth backup create \
    --data-dir /var/lib/hearth/data \
    --include-audit \
    --sign-key /etc/hearth/backup-signing.pem \
    --output "$PRE_UPGRADE"
  ```

  > **A bad `--data-dir` now fails loudly.** `backup create` refuses a path that
  > does not exist and refuses a store with no realms in it, and `backup verify`
  > refuses an archive with zero files. Until task 26.26 all three exited `0`, so
  > a typo'd path produced an empty archive that verified clean. Still read the
  > realm list from `backup inspect` (below) before trusting an archive.
  Verify it was written cleanly:

  ```bash
  hearth backup verify --input "$PRE_UPGRADE"
  ```

- [ ] **Record the current version.** You will need this for rollback.

  ```bash
  hearth --version
  ```

- [ ] **Inspect the backup manifest.** Confirm the archive records the current binary version, which you will need if a rollback requires a specific restore path:

  ```bash
  hearth backup inspect \
    --input /backups/pre-upgrade-<timestamp>.hearth-backup
  # Archive:           /backups/pre-upgrade-<timestamp>.hearth-backup
  #   format version : 2
  #   hearth version : 1.6.11-143-gcfb6c4f5   ← the binary that wrote the archive
  #   created at     : 2026-09-21T16:57:00Z
  #   signing key DEK: present (passphrase-protected)
  #   checksummed files: 42
  #   realms (2): …
  ```

  `format version` is the **archive** format (currently `2`) and is unrelated to the WAL format
  version checked below.

  The `signing key DEK` line reports `present (passphrase-protected)` on every archive this
  build writes, whether or not `--encrypt` was passed — it is not a reliable signal for "was
  this archive encrypted". You are prompted for a passphrase on restore only when the archive
  was actually created with `--encrypt`; if you used that flag, make sure you still have the
  passphrase before relying on this archive for rollback.

  **`checksummed files: 0` or an empty `realms` list means the archive is empty** — re-check the
  `--data-dir` path and take it again.

- [ ] **Check the WAL format version.** The WAL header layout is `[4B magic "HWAL"][2B version, little-endian]`. Read the current version directly:

  ```bash
  xxd -l 6 /var/lib/hearth/data/hearth.wal
  # → 00000000: 4857 414c 0100    HWAL..
  #                       ^^^^ version 1 (little-endian u16)
  ```

  **As of the current release the WAL format version is `1`, and it has not changed across any shipped
  v1.x release.** The only migration in the table is `v0 → v1`, which upgrades the legacy pre-header
  format. **An unchanged WAL version does NOT make in-place rollback safe.** The WAL and SST
  *headers* are versioned; the records inside them are not. Users, sessions, credentials and audit
  events are encoded with `postcard` (`src/codec.rs`), which is not self-describing and carries no
  per-record version, and those types change between releases — for example `AuditAction` gained
  `InvitationCreated`, `InvitationAccepted` and `InvitationRevoked` after v1.6.11. An older binary
  cannot decode a record that uses a variant or field it does not know. See
  [Rollback](#rollback-procedure).

  When a bump *does* occur it is one-way: upgrading rewrites the file to the new version on startup,
  and the older binary will then refuse to start with `WAL format version N is not supported by this
  binary; upgrade Hearth or restore from backup`. See [Rollback](#rollback-procedure) for that path.

- [ ] **Confirm single-writer invariant.** Ensure no other process is pointing at the same `storage.data_dir`:

  ```bash
  flock --nonblock /var/lib/hearth/data/LOCK echo "lock is free" \
    || echo "LOCK is held — confirm which process owns it before proceeding"
  ```

---

## Upgrade procedure

### systemd (bare-metal / VM)

This procedure replaces the binary while the service is managed by systemd. Total downtime: the time for Hearth to stop cleanly plus startup time (typically 5–15 seconds).

1. **Stop the service.**

   ```bash
   sudo systemctl stop hearth
   ```

   `systemctl stop` sends SIGTERM. Hearth catches SIGTERM and drains in-flight HTTP and gRPC requests before exiting cleanly (controlled by `operational.shutdown_timeout_secs`, default 10 s). Wait for the service to reach the `inactive` state before continuing:

   ```bash
   sudo systemctl is-active hearth
   # → inactive
   ```

2. **Install the new binary.**

   Download the release binary for your platform from [GitHub Releases](https://github.com/hearth-auth/hearth/releases) or build from source:

   ```bash
   # From GitHub Releases:
   sudo install -m 755 hearth-<version>-linux-x86_64 /usr/local/bin/hearth

   # Verify the binary is in place:
   hearth --version
   ```

3. **Start the service.**

   ```bash
   sudo systemctl start hearth
   ```

4. **Confirm it is ready.**

   ```bash
   sudo systemctl is-active hearth
   # → active
   curl -fsS http://localhost:8420/readyz
   # → {"status":"ready","storage":"ok"}
   ```

   Check the journal for startup errors or warnings:

   ```bash
   sudo journalctl -u hearth -n 50
   ```

5. **Run post-upgrade verification** (see [Post-upgrade verification](#post-upgrade-verification)).

---

### Docker Compose

1. **Pull the new image.**

   ```bash
   docker pull ghcr.io/hearth-auth/hearth:<new-version>
   ```

   > **Known gap:** re-checked 2026-09-21, an anonymous manifest fetch for this package returns
   > **401** for every tag. Run `docker login ghcr.io` with a token carrying `read:packages`
   > first, or upgrade via the release binary and the systemd path below. Tracked as remediation
   > task 3.4.

2. **Update the image tag** in your `docker-compose.yml` (or `.env` file, if you parameterise the tag):

   ```yaml
   services:
     hearth:
       image: ghcr.io/hearth-auth/hearth:<new-version>
   ```

3. **Stop, remove the container, and start with the new image.** Do not use `restart` — it reuses the old container layer.

   ```bash
   docker compose -f deploy/docker-compose.yml stop hearth
   docker compose -f deploy/docker-compose.yml rm -f hearth
   docker compose -f deploy/docker-compose.yml up -d hearth
   ```

4. **Verify.**

   ```bash
   docker compose -f deploy/docker-compose.yml ps
   curl -fsS http://localhost:8420/readyz
   # → {"status":"ready","storage":"ok"}
   ```

---

### Helm (Kubernetes)

The Hearth Helm chart uses `strategy.type: Recreate` in its Deployment. This means the old pod is **stopped before the new pod starts**, ensuring only one process ever holds the WAL lock. **Expect a brief outage** (typically 5–30 seconds depending on image pull time) during every Helm upgrade.

1. **Update the chart** by editing your values file to reference the new image tag, or pass it directly:

   ```bash
   # Option A: set the tag inline
   helm upgrade hearth deploy/helm/hearth \
     -f my-values.yaml \
     --namespace hearth \
     --set image.tag=<new-version>

   # Option B: edit my-values.yaml first
   # image:
   #   tag: "<new-version>"
   helm upgrade hearth deploy/helm/hearth \
     -f my-values.yaml \
     --namespace hearth
   ```

2. **Watch the rollout.**

   ```bash
   kubectl rollout status deployment/hearth -n hearth
   # → Waiting for deployment "hearth" rollout to finish: 0 of 1 updated replicas are available...
   # → deployment "hearth" successfully rolled out
   ```

3. **Verify.**

   ```bash
   kubectl get pods -n hearth
   kubectl port-forward -n hearth svc/hearth 8420:8420 &
   curl -fsS http://127.0.0.1:8420/readyz
   # → {"status":"ready","storage":"ok"}
   kill %1
   ```

> **Why `Recreate` instead of `RollingUpdate`?** Hearth holds an exclusive advisory lock on `storage.data_dir` via `{data_dir}/LOCK`. A rolling strategy would start the new pod while the old one is still running and holding the lock — the new pod would crash-loop with:
>
> ```
> data directory '/var/lib/hearth/data' is already locked by another process;
> stop the running Hearth instance before starting a new one
> ```
>
> `Recreate` prevents this by ensuring only one pod is ever scheduled against the PVC at a time. An upgrade therefore has a short outage while the old pod stops and the new one starts. **Single-node is the only supported production topology**; Raft cluster mode is experimental and must not be used for failover or zero-downtime upgrades (see [Clustering](./clustering.md)).

---

## Post-upgrade verification

Run these checks immediately after bringing the new binary up, regardless of deployment method.

- [ ] **Readiness endpoint responds.**

  ```bash
  curl -fsS http://localhost:8420/readyz
  # → {"status":"ready","storage":"ok"}
  ```

  `/readyz` confirms both that the process is alive and that the storage engine completed
  WAL replay and is accepting requests. A `503` here means storage is still recovering —
  wait and retry before directing traffic to this instance.

  For Kubernetes probes use the purpose-specific endpoints:

  | Endpoint | Purpose | Kubernetes probe type |
  |----------|----------|-----------------------|
  | `/health` | Process liveness — always 200 if the binary is running | `livenessProbe` |
  | `/healthz` | Same as `/health` (alias) | `livenessProbe` |
  | `/readyz` | Readiness — verifies storage is responsive; fails until WAL replay completes | `readinessProbe` |

  The Helm chart already routes these correctly. If you are writing your own Kubernetes manifests, configure `/health` or `/healthz` as the liveness probe and `/readyz` as the readiness probe.

- [ ] **OIDC discovery documents are served for all realms.** Replace `<realm>` with each realm name in your deployment:

  ```bash
  curl -fsS https://auth.example.com/realms/<realm>/.well-known/openid-configuration \
    | jq .issuer
  # → "https://auth.example.com/realms/<realm>"
  ```

- [ ] **JWKS responds and signing key IDs are unchanged.** Compare the `kid` values against a snapshot taken before the upgrade. They must match unless you intentionally rotated signing keys.

  ```bash
  curl -fsS https://auth.example.com/realms/<realm>/.well-known/jwks.json | jq .
  ```

- [ ] **Admin API is reachable.**

  ```bash
  curl -fsS -H "Authorization: Bearer <admin-token>" \
    -H "X-Realm-ID: <realm-uuid>" \
    http://localhost:8420/admin/realms | jq .
  ```

  `X-Realm-ID` is mandatory on every `/admin/*` route. Omit it and the call answers
  `400 {"error":"missing X-Realm-ID header"}` — which is easy to misread as an upgrade
  regression when it is a missing header.

- [ ] **No unexpected WARN or ERROR lines in the log** since startup. On systemd:

  ```bash
  sudo journalctl -u hearth --since "5 minutes ago" | grep -E 'ERROR|WARN'
  ```

  Expected warnings (harmless): none. Any `ERROR` line after successful startup is a regression — stop the server, roll back (see below), and file an issue.

---

## Rollback procedure

### Rollback means restore from backup

**Do not roll back in place across releases. Restore the pre-upgrade backup instead.** An unchanged
WAL format version (the `xxd` check in the [pre-upgrade checklist](#pre-upgrade-checklist)) proves
only that the older binary can open the files; it does not prove it can decode the records in them:

- Records (users, sessions, credentials, audit events) are encoded with `postcard`
  (`src/codec.rs`). The encoding is not self-describing and carries no per-record version.
- Those types change between releases. An enum that gains a variant is the common case —
  `AuditAction` gained `InvitationCreated`, `InvitationAccepted` and `InvitationRevoked` after
  v1.6.11 — and postcard stores the variant *index*, so an older binary cannot decode a record the
  newer one wrote with a new variant. There is no downgrade guard that refuses to start; the failure
  surfaces when the unreadable record is read.
- In **cluster mode** (experimental), the release after v1.6.11 also changes the Raft log format, so
  a cluster node cannot roll back in place either ([Cluster upgrades](#cluster-full-restart)).

The rollback path is therefore the same whether or not the WAL version moved: stop the new binary,
keep a copy of the post-upgrade data directory, reinstall the old binary and restore the archive you
took and signed in the pre-upgrade checklist — the steps under
[When the WAL format version changed](#when-the-wal-format-version-changed) below. Writes made after
the upgrade are lost unless you re-apply them. An in-place rollback with no restore is only defensible
between two builds whose stored types are known to be identical (for example a rebuild of the same
commit); nothing in the release process verifies that today.

### When the WAL format version changed

Hearth's WAL reader rejects files written by a **newer** binary. Startup fails with:

```
WAL format version N is not supported by this binary;
upgrade Hearth or restore from backup
```

Older binaries cannot read WAL files written by newer binaries. To roll back:

1. **Stop the new binary.**

   ```bash
   sudo systemctl stop hearth
   ```

2. **Back up the data directory** (it may contain writes made since the upgrade).

   ```bash
   cp -a /var/lib/hearth/data \
          /var/lib/hearth/data.post-upgrade-$(date +%s)
   ```

3. **Restore from the pre-upgrade backup** you took before the upgrade. It must
   be the archive you signed in the pre-upgrade checklist: restore authenticates
   it against `security.backup.verify_key` from `--config` and refuses an
   unsigned one (exit `2`, nothing written).

   ```bash
   rm -rf /var/lib/hearth/data
   mkdir -p /var/lib/hearth/data
   hearth backup restore \
     --input /backups/pre-upgrade-<timestamp>.hearth-backup \
     --config /etc/hearth/hearth.yaml \
     --data-dir /var/lib/hearth/data
   ```

4. **Reinstall the previous binary.**

   ```bash
   sudo install -m 755 hearth-<old-version>-linux-x86_64 /usr/local/bin/hearth
   hearth --version  # confirm
   ```

5. **Start the service.**

   ```bash
   sudo systemctl start hearth
   curl -fsS http://localhost:8420/readyz
   # → {"status":"ready","storage":"ok"}
   ```

6. **Reconcile writes made since the upgrade.** Any writes that occurred between the upgrade and the rollback will be missing from the restored data directory. Cross-reference your application's own request logs for the window between upgrade time and rollback time and replay them via the admin API if needed.

### Rollback on Kubernetes (Helm)

```bash
# View revision history
helm history hearth -n hearth

# Roll back to the previous revision
helm rollback hearth -n hearth
```

`helm rollback` re-applies the previous Helm release values (including the old image tag). The Recreate strategy ensures the old pod is fully terminated before the rollback pod starts.

> If the WAL format version changed, `helm rollback` alone is not enough — you must also restore the data directory from the pre-upgrade backup before restarting, following the same steps as bare-metal rollback above (steps 3–6), executed inside the pod or via an init container.

---

## Known upgrade notes

This section lists configuration or behavior changes that require operator action on upgrade. Entries are appended for each Hearth minor or major release.

### Copied-from-example configs: `*_lifetime_secs`

If your `hearth.yaml` was derived from `examples/auth0-migration/` or `examples/keycloak-migration/`,
it may contain `access_token_lifetime_secs` / `refresh_token_lifetime_secs`. **These were never valid
Hearth config keys** — they were stale placeholders in the example files (corrected in HEA-2143).

They were silently ignored by older binaries, so token TTLs quietly fell back to defaults rather than
the values you set. Replace them with the real keys, which take duration strings:

```yaml
token:
  access_token_ttl: "15m"    # default: 15 minutes
  refresh_token_ttl: "7d"    # default: 7 days
```

Once `deny_unknown_fields` lands (see below), leaving them in place becomes a hard startup error
instead of a silent no-op.

<a id="v16-v17"></a>

### v1.6 → v1.7

> These changes currently sit under `## [Unreleased]` in `CHANGELOG.md` — they ship in the first
> release after v1.6.9. Re-check the changelog at the moment you upgrade.

All config structs now carry `#[serde(deny_unknown_fields)]`. Previously, a misspelled or removed key was silently discarded; it is now a hard startup error. The following keys formerly appeared in documentation but were never implemented — remove or rename them before upgrading:

| Old key | Action |
|---|---|
| `auth.audit_log_retention` | Remove — not yet implemented |
| `security.bearer_token` | Move to `metrics.bearer_token` (under the top-level `metrics:` section) |
| `security.password.pepper.active_version` | Rename to `security.password.pepper.version` |
| `security.password.pepper.active_hex` | Rename to `security.password.pepper.key_hex` |
| `security.password.pepper.previous_hex` | Rename to `security.password.pepper.previous_key_hex` |
| `roles[].display_name` | Remove — role entries use `name` and `description`; there is no display-name field |
| `realms[].display_name` (realm-level key) | Remove — not a supported top-level realm key |

The `metrics.bearer_token` rename is particularly important: operators who had `security.bearer_token` set believed `/metrics` was protected. It was not. After the rename, set the correct key under `metrics:` and verify the endpoint requires authentication.

#### Production startup now fails closed on three insecure configurations (HEA-2166)

Outside `--dev`, the server now **refuses to start** — instead of silently running insecurely —
when any of the following holds. If your deployment currently relies on one of these, it was
running with a real vulnerability; fix the configuration before upgrading:

| Condition | Previous behavior | Required action |
|---|---|---|
| No key-encryption key configured | Realm signing keys (Ed25519 private keys) were written to storage **in plaintext**, with no warning | Set the `HEARTH_KEK` env var (recommended) or `security.key_encryption_key` to a random 64-hex-char value: `openssl rand -hex 32` |
| Neither `server.tls_cert_path` nor `server.trust_forwarded_proto: true` set | An `error!` line was logged and startup continued; session cookies were issued **without the `Secure` attribute** | Configure direct TLS (`server.tls_cert_path` + `server.tls_key_path`), or set `server.trust_forwarded_proto: true` if TLS terminates at a reverse proxy |
| `demo.enabled: true` | The mass demo seeder ran in production — every seeded account shares a single, publicly documented default password | Remove the `demo:` block from production configs |

Each violation aborts startup with an error naming the offending key and the fix. `--dev`
behavior is unchanged: the developer loop still requires none of these.

Relatedly, `hearth serve` with **no config file** previously booted a production server from
compiled-in defaults without running validation at all. The defaults now pass through the same
gates, so a bare `hearth serve` refuses to start until a config satisfying the production
checklist is provided (or `--dev` is passed for local development).

**Key encryption:** setting `HEARTH_KEK` for the first time on an existing data directory is safe.
The first KEK-configured start re-encrypts every signing key already on disk — the server-wide key,
every realm's active key, and every retiring key — logs how many it re-wrapped, and marks the store
enrolled. From then on an unenveloped signing key is **refused**, not silently accepted, so an
attacker who strips the envelope cannot downgrade the deployment. No rotation is needed to supersede
the plaintext copies, and no tokens are invalidated. Take a backup before the first KEK-enabled boot,
as with any in-place key migration.

Earlier releases encrypted only *subsequent* writes and accepted unenveloped keys indefinitely; the
previous advice here — rotate every realm's key after the upgrade — is no longer necessary.

### v1.6.x → later

Check the `CHANGELOG.md` `## [Unreleased]` section for in-flight breaking changes before upgrading from a release candidate or a development build.

---

## Cluster upgrades

<a id="cluster-full-restart"></a>

> **The release after v1.6.11 needs a full-cluster restart, not a rolling upgrade.** It adds a Raft
> log command (`IncrementU64`, the atomic control-epoch bump) that older builds cannot decode:
>
> - an older follower refuses every `AppendEntries` that carries the new command, so replication to
>   it stalls for good (not just for that entry);
> - a new-build leader over a majority of older followers cannot commit anything, so every write
>   times out;
> - an older build cannot read a Raft log (`raft.db`) that contains the new command, so **rolling a
>   node back needs a copy of its data directory taken before the upgrade** — the in-place
>   rollback below does not apply to this release in cluster mode.
>
> A new-build node logs `peer cannot decode this node's Raft log: it runs an older Hearth build`
> (once per peer) when it meets such a node. There is no safe fallback: the older write path read
> the counter on one node and wrote its successor, which is exactly the race the new command
> closes, so the new build does not fall back to it.
>
> To upgrade a **young** cluster — one whose Raft logs have not been purged yet: take a backup on
> the leader, **stop every node**, copy each node's whole data directory (including `raft.db`)
> aside, install the new binary on every node, then start them all. Expect a write outage for the
> length of the restart. Single-node deployments are unaffected. To roll back, stop every node,
> put each node's copied data directory back, and start the older binary: a young node's log
> still holds every entry, so the older build can restart it.
>
> **A cluster whose Raft logs were purged cannot be upgraded in place** — and that is nearly every
> cluster in production: with the default snapshot policy a node takes its first snapshot, and
> purges its log, once it has applied about 5,000 entries. Follow
> [Upgrading a cluster whose Raft logs were purged](#cluster-purged-log-upgrade) instead.

<a id="cluster-purged-log-upgrade"></a>

### Upgrading a cluster whose Raft logs were purged

Releases up to v1.6.11 kept the Raft state machine's applied index and the cluster membership **in
memory only**. Once a node's log has been purged, neither can be recovered from its data directory:
the older build cannot restart such a node, and the new build refuses to start it (`this node's
Raft log is purged through index N but its data directory holds no persisted applied state …`).
Re-seeding one node (move its data directory aside and start it empty, so the leader sends it a
snapshot) works only while the rest of the cluster still has a leader. In the full-cluster restart
this release requires, every node is in that state at once, so there is no leader: rebuild the
cluster from a backup.

> **Stopping the old cluster is one-way.** A purged node cannot restart on **either** build, so
> once you stop the nodes in step 2 the old cluster cannot be started again, and putting its data
> directories back does not bring it back. The only rollback is to rebuild a cluster of the
> **older** build from the same backup, by the same offline procedure (steps 4–6 with the older
> binary and its own `hearth backup restore`, into new empty directories). An older restore refuses
> the system realm, so that rebuild restores `pre-upgrade.hearth-backup` only and has no
> operator-console account. Such a cluster works until its logs are purged again, and then has the
> same restart problem.

> **Restore offline, before the new cluster first starts.** Realms come from `hearth.yaml`:
> `POST /admin/realms` answers `405`, and at every start-up the server creates each declared realm
> that is missing — with a **new** id and a **new** signing key. A restore into a cluster that has
> already started therefore finds each realm's name taken, skips the archived realm record and its
> signing key (reported as a conflict, not an error), and writes the realm's users and clients
> under the archive's old realm id. The realms are then empty under their names, every token they
> issued stops validating, and nothing fails. Restoring into an empty data directory before the
> first start avoids this: start-up then finds each realm already there, under its archived id.

**What the rebuild does not bring back.** Read this before you schedule the window:

- **The system realm — unless you export it separately.** It holds every **operator-console
  account**, the grants and API tokens issued in the system realm (for example the system token
  used below) and the system realm's signing key. This release restores it: `hearth backup
  restore` imports the system realm from any archive that carries it, and operators then sign in
  at `/ui/admin/login` with their original passwords and second factors (see the
  [Backup guide](./backup.md#restoring-the-system-realm)). But the archive must carry it, and the
  **v1.6.11 HTTP export in step 1 does not** — no `POST /admin/backup` before this release included
  the system realm. Step 2 therefore takes it separately, offline, with this release's binary. A
  CLI `hearth backup create` without `--realm`, and a `POST /admin/backup` made by a system-realm
  caller **on this release**, both include it. Without it the rebuilt cluster has no
  operator-console account and no supported way to create one (the setup URL is issued only while
  the store holds no realm, and a restored store holds them all); tenant realms' own admins and
  API tokens keep working against `/admin` with their realm's `X-Realm-ID`, but the cluster
  endpoints (`/admin/cluster/*`) need a system-realm token.
- **Sessions.** They are never exported. Every token bound to a session — every user's access and
  refresh token — stops validating, so **every user signs in again**.
- **The revoked-token list.** It is excluded from backups. A token without a session (for example
  a `client_credentials` access token) keeps validating until it expires — **including one that was
  revoked before the backup**. If any such token was revoked and has not expired yet, rotate that
  realm's signing key after the rebuild (default rotation stops every token signed with the old
  key at once; see the [DR guide](./disaster-recovery.md#post-incident-signing-key-rotation)).
- **Audit events**, unless the export passes `include_audit=true` (below does).

The [Backup guide](./backup.md#what-a-backup-does-not-carry) lists the rest.

**Keep `HEARTH_MASTER_KEY` and the key-encryption key.** The export wraps the archive's data key
with the exporting node's `HEARTH_MASTER_KEY`, and `hearth backup restore` unwraps it with the
`HEARTH_MASTER_KEY` in its own environment. With any other value the restore cannot read the
archive at all and writes nothing — `--allow-missing-signing-key` does not change that, and the HTTP
restore has no such override. The same variable is the new store's host key, and every node of a
cluster must share one value anyway: run the restore and the new cluster with the old cluster's
`HEARTH_MASTER_KEY`, and with a `hearth.yaml` that carries its `security.key_encryption_key`.

1. **Before stopping anything**, stop client writes (a maintenance window) and take a backup from
   the leader over HTTP, with a **system-realm** token (only the system realm may export every
   realm — a realm-scoped admin token exports its own realm only) and the system realm's nil UUID
   as `X-Realm-ID`:

   ```bash
   curl -fsS -X POST -H "Authorization: Bearer $SYSTEM_TOKEN" \
     -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000" \
     "https://10.0.0.1:8420/admin/backup?include_audit=true" -o pre-upgrade.hearth-backup
   hearth backup verify --input pre-upgrade.hearth-backup
   hearth backup sign --input pre-upgrade.hearth-backup --key-file /etc/hearth/backup-signing.pem
   ```

   The token needs the `hearth.admin` and `hearth.export` capabilities. Check the archive lists
   every tenant realm (`hearth backup inspect --input pre-upgrade.hearth-backup`); see the
   [Backup guide](./backup.md) for signing (the restore refuses an unsigned archive).

   **No `$SYSTEM_TOKEN`?** v1.6.11 has no production way to mint one, and this release's
   `hearth admin token` needs the node stopped and refuses a cluster node's store — and stopping
   is one-way here ([System-realm tokens](./clustering.md#system-realm-tokens)). Skip this export.
   In step 3, export **every** realm instead: drop `--realm …`, add `--include-audit` and write
   `--output pre-upgrade.hearth-backup`. That one archive then carries the system realm too, so
   step 4 runs only the first restore.
2. **Stop every node** — one-way, see above — and **move each node's data directory aside** (keep
   it, for investigation and for step 3; do not delete it):

   ```bash
   # on every node
   systemctl stop hearth
   mv /var/lib/hearth/data /var/lib/hearth/data-pre-upgrade
   ```

   Moving it aside is what makes the copy in step 5 land in an **empty** directory. A node must not
   start on the new store with any of the old one's files still under it: the old `raft.db` (the
   Raft log and vote, `{storage.data_dir}/raft.db`), WAL segments or SSTs left next to the copied
   store make the node refuse to start or replay old state — differently on each node.
3. **Install the new binary on every node, and export the system realm.** On the node that was
   the leader in step 1, export the system realm from its moved-aside data directory with the
   **new** binary, the old cluster's `HEARTH_MASTER_KEY` and its `hearth.yaml` (for
   `security.key_encryption_key`). Work on a copy so the original stays untouched:

   ```bash
   export HEARTH_MASTER_KEY=...   # the old cluster's value
   cp -a /var/lib/hearth/data-pre-upgrade /var/lib/hearth/data-export-copy
   hearth backup create \
     --data-dir /var/lib/hearth/data-export-copy \
     --config /etc/hearth/hearth.yaml \
     --realm 00000000-0000-0000-0000-000000000000 \
     --sign-key /etc/hearth/backup-signing.pem \
     --output system-realm.hearth-backup
   hearth backup inspect --input system-realm.hearth-backup   # lists one realm: `system`
   ```

   Skip this only if you accept rebuilding without operator-console access (see above).
4. **Restore offline into one new, empty data directory**, on one node, with the new binary, the
   old cluster's `HEARTH_MASTER_KEY` in the environment and the new cluster's `hearth.yaml` (its
   `security.backup.verify_key` must match the key the archives were signed with). `mkdir`
   without `-p` fails if the directory already exists, so the restore cannot land on old files:

   ```bash
   export HEARTH_MASTER_KEY=...   # the old cluster's value
   mkdir /var/lib/hearth/data-new
   hearth backup restore \
     --input pre-upgrade.hearth-backup \
     --config /etc/hearth/hearth.yaml \
     --data-dir /var/lib/hearth/data-new
   hearth backup restore \
     --input system-realm.hearth-backup \
     --config /etc/hearth/hearth.yaml \
     --data-dir /var/lib/hearth/data-new
   test ! -e /var/lib/hearth/data-new/raft.db && echo "no raft.db: OK"
   ```

   Exit `0` means every record restored; read any conflicts and errors it prints before going
   on. The second restore ends with `System realm: N operator-console account(s) restored; …`;
   the first one warns that its archive does not contain the system realm, which is expected
   here. `hearth backup restore`
   writes only the store, never a Raft log, so a directory it restored into while empty holds no
   `raft.db`. Do **not** start `hearth serve` on it yet.

   To check the new cluster with `/admin/cluster/status` in step 6, mint a system-realm token
   **now**, into this directory, before step 5 copies it: every node then starts from the same
   session and audit record, so the token validates on all of them. It lives at most one hour:

   ```bash
   SYSTEM_TOKEN=$(hearth admin token --data-dir /var/lib/hearth/data-new \
     --config /etc/hearth/hearth.yaml --user ops@example.com --ttl 1h)
   ```

   `--user` is an operator-console account from the restored system realm holding `realm.admin`.
   Minting after the copy, on one node, would put the record on that node only
   ([System-realm tokens](./clustering.md#system-realm-tokens)).
5. **Copy that directory to every node** before any node starts, into the path each node's
   `storage.data_dir` names — which step 2 emptied. Create it fresh so the copy cannot merge into
   leftovers, then copy:

   ```bash
   for node in node2 node3; do
     ssh "$node" 'mkdir /var/lib/hearth/data'   # fails if step 2 was skipped on that node
     rsync -a /var/lib/hearth/data-new/ "$node":/var/lib/hearth/data/
   done
   # the restoring node itself: copy it too, so data-new stays as the reference copy
   mkdir /var/lib/hearth/data
   rsync -a /var/lib/hearth/data-new/ /var/lib/hearth/data/
   ```

   Every node must start from the **same bytes**. Do not run the restore once per node: each run
   builds a fresh store and writes its own random keys and timestamps, so the nodes would start
   with different state. Because each target directory is new, it holds exactly the restored store
   and no `raft.db`, so each node starts a fresh Raft log on top of identical state. (Plain
   `rsync -a` deletes nothing at the destination. If you must reuse a directory instead of creating
   it, `rsync -a --delete` removes what the source lacks — but moving the old directory aside is
   the procedure; `--delete` also removes whatever you meant to keep.)
6. **Start every node** with the new binary and a `hearth.yaml` that declares **the same realm
   names** as before (start-up archives a realm the file does not declare). The cluster
   bootstraps as a new cluster does ([Clustering guide](./clustering.md)); start-up finds every
   realm already present under its archived id and signing key. Run the
   [post-restore checks](./disaster-recovery.md#test-restore-drill-checklist).
7. **Re-open client traffic.** Users sign in again (sessions were not restored); relying parties'
   cached JWKS stays valid, because every realm kept its signing key.

> **What the test suite covers, and what it does not.**
> `tests/cluster_three_node_control_coherence.rs::a_cluster_seeded_from_one_offline_restored_directory_serves_it_on_every_node`
> runs the core of steps 4–6 with the real binary: `hearth backup create` of a store (unfiltered,
> so the system realm is in it), `hearth backup restore` into a new empty directory with one shared
> `HEARTH_MASTER_KEY` and no KEK file, a check that no `raft.db` was written, copies into three new
> directories, and a three-node cluster started on them followed by realm reconciliation on the
> leader. It asserts every node holds the realm under its archived id and the operator account,
> and validates a token the leader signs. It does **not** cover: `hearth serve` processes (the
> nodes are in-process cluster engines), a store or an HTTP export written by v1.6.11, the
> system-realm export of step 3 from a stopped node's directory, or the `rsync` copy itself.

For releases that do not change the Raft log format, upgrade a Raft cluster (3 or 5 nodes) with
minimal service interruption as follows:

> There is no `hearth cluster` CLI subcommand. Cluster state is inspected over HTTP via
> `GET /admin/cluster/status`, which requires cluster-admin credentials. It returns `503` when the
> server is running in single-node mode. See the [Clustering guide](./clustering.md).

1. **Take a backup** from the leader node as described in the [pre-upgrade checklist](#pre-upgrade-checklist).

2. **Identify the current leader.** Query each node — exactly one reports `"role": "leader"`.

   ```bash
   curl -fsS -H "Authorization: Bearer <admin-token>" \
     http://10.0.0.1:8420/admin/cluster/status | jq '{role, term, last_applied_index}'
   # → { "role": "leader", "term": 4, "last_applied_index": 10432 }
   ```

3. **Upgrade followers first, one at a time.** Stop the binary on a follower, install the new binary,
   start it, then confirm it has rejoined and caught up before moving to the next node. Compare the
   follower's `last_applied_index` against the leader's — it should converge to within a few entries:

   ```bash
   curl -fsS -H "Authorization: Bearer <admin-token>" \
     http://10.0.0.2:8420/admin/cluster/status | jq '{role, term, last_applied_index}'
   # → { "role": "follower", "term": 4, "last_applied_index": 10429 }
   ```

   > **Peer health only populates on the leader.** The `peers[].is_healthy` field is derived from the
   > leader's replication map. When queried on a *follower*, every peer reports `is_healthy: false`.
   > This is expected and is not a sign of a degraded cluster — judge follower health by querying the
   > **leader**, or by each node's own `role` and `last_applied_index`.

4. **Step the leader down before upgrading it.** Rather than stopping the leader outright and waiting
   for an election to time out, hand off leadership gracefully first:

   ```bash
   curl -fsS -X POST -H "Authorization: Bearer <system-admin-token>" \
     -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000" \
     http://10.0.0.1:8420/admin/cluster/transfer-leadership
   # → { "new_leader_id": 2, "exact_target": false }
   ```

   The request returns `409` if the node you sent it to is not the current leader. Do **not** send a
   `target_node_id`: the underlying Raft library has no targeted-transfer API, so a body naming one
   is refused with `422` and leadership does not move. The response's `new_leader_id` reports which
   voter won the election; `exact_target` is deprecated and always `false`.

   **Expect a brief write outage:** writes fail with `NoLeader` for up to one election timeout
   (~1.5–3 s) during the step-down window. Once another node reports `"role": "leader"`, upgrade the
   old leader as a follower using step 3.

5. **Verify** every node is on the new version, exactly one node reports `"role": "leader"`, and all
   nodes agree on `term`.

> **WAL format constraint in cluster upgrades:** All nodes must run a binary that can read the current WAL format version. Do not downgrade any node to a binary that cannot read the version written by the cluster leader. If a rollback is needed after a cluster upgrade, follow the restore-from-backup path on every node.

---

## Related guides

- [Backup and Restore Guide](./backup.md) — archive format, CLI reference, scheduled-backup recipes
- [Disaster Recovery Guide](./disaster-recovery.md) — WAL corruption, Raft divergence, full-restore procedures, and rollback after catastrophic failure
- [Clustering Guide](./clustering.md) — Raft cluster setup, peer configuration, certificate management
- [Security Hardening Guide](./security-hardening.md) — TLS, token TTLs, signing-key rotation
