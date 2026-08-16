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

  ```bash
  hearth backup create \
    --data-dir /var/lib/hearth/data \
    --include-audit \
    --output /backups/pre-upgrade-$(date +%Y%m%d-%H%M%S).hearth-backup
  ```

  Verify it was written cleanly:

  ```bash
  hearth backup verify \
    --input /backups/pre-upgrade-$(date +%Y%m%d-%H%M%S).hearth-backup
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
  #   format version : 1
  #   hearth version : 1.6.9        ← the binary that wrote the archive
  #   created at     : 2026-08-11T20:45:16Z
  #   signing key DEK: absent       ← "present (passphrase-protected)" if --encrypt was used
  #   checksummed files: 42
  #   realms (2): …
  ```

  If `signing key DEK` reports `present (passphrase-protected)`, you will be prompted for the
  passphrase on restore — make sure you still have it before relying on this archive for rollback.

- [ ] **Check the WAL format version.** The WAL header layout is `[4B magic "HWAL"][2B version, little-endian]`. Read the current version directly:

  ```bash
  xxd -l 6 /var/lib/hearth/data/hearth.wal
  # → 00000000: 4857 414c 0100    HWAL..
  #                       ^^^^ version 1 (little-endian u16)
  ```

  **As of the current release the WAL format version is `1`, and it has not changed across any shipped
  v1.x release.** The only migration in the table is `v0 → v1`, which upgrades the legacy pre-header
  format. In practice this means **in-place binary rollback between shipped v1.x versions is safe** —
  the data directory is byte-compatible. The constraint below matters only if a future release bumps
  the version, which will be called out in `CHANGELOG.md` under `**Breaking:**`.

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

4. **Confirm it is healthy.**

   ```bash
   sudo systemctl is-active hearth
   # → active
   curl -fsS http://localhost:8420/health
   # → {"status":"ok"}
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
   curl -fsS http://localhost:8420/health
   # → {"status":"ok"}
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
   curl -fsS http://127.0.0.1:8420/health
   # → {"status":"ok"}
   kill %1
   ```

> **Why `Recreate` instead of `RollingUpdate`?** Hearth holds an exclusive advisory lock on `storage.data_dir` via `{data_dir}/LOCK`. A rolling strategy would start the new pod while the old one is still running and holding the lock — the new pod would crash-loop with:
>
> ```
> data directory '/var/lib/hearth/data' is already locked by another process;
> stop the running Hearth instance before starting a new one
> ```
>
> `Recreate` prevents this by ensuring only one pod is ever scheduled against the PVC at a time. Use Raft cluster mode for zero-downtime failover.

---

## Post-upgrade verification

Run these checks immediately after bringing the new binary up, regardless of deployment method.

- [ ] **Health endpoint responds.**

  ```bash
  curl -fsS http://localhost:8420/health
  # → {"status":"ok"}
  ```

  For Kubernetes probes use the purpose-specific endpoints (both return `200 OK` when healthy):

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
    http://localhost:8420/admin/realms | jq .
  ```

- [ ] **No unexpected WARN or ERROR lines in the log** since startup. On systemd:

  ```bash
  sudo journalctl -u hearth --since "5 minutes ago" | grep -E 'ERROR|WARN'
  ```

  Expected warnings (harmless): none. Any `ERROR` line after successful startup is a regression — stop the server, roll back (see below), and file an issue.

---

## Rollback procedure

### When rollback is safe without a backup

Rollback to the previous binary is safe in place **if and only if the WAL format version did not change** between the old and new binary.

**For every currently shipped v1.x release this is the case** — the WAL format version has been `1`
throughout, so in-place rollback is the normal path:

1. Stop the new binary.
2. Reinstall the old binary.
3. Start the service.

The data directory is fully compatible and no restore is required. Confirm with the `xxd` check in the
[pre-upgrade checklist](#pre-upgrade-checklist) if you want positive verification before starting.

If you are unsure whether a future version changed the format, **check `CHANGELOG.md` for a
`**Breaking:**` WAL-format entry**, or treat it as a version-bump rollback (below).

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

3. **Restore from the pre-upgrade backup** you took before the upgrade.

   ```bash
   rm -rf /var/lib/hearth/data
   mkdir -p /var/lib/hearth/data
   hearth backup restore \
     --input /backups/pre-upgrade-<timestamp>.hearth-backup \
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
   curl -fsS http://localhost:8420/health
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

### v1.6.x → later

Check the `CHANGELOG.md` `## [Unreleased]` section for in-flight breaking changes before upgrading from a release candidate or a development build.

---

## Cluster upgrades

To upgrade a Raft cluster (3 or 5 nodes) with minimal service interruption:

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
   curl -fsS -X POST -H "Authorization: Bearer <admin-token>" \
     http://10.0.0.1:8420/admin/cluster/transfer-leadership
   ```

   The request returns `409` if the target node is not the current leader. `target_node_id` may be
   supplied in the JSON body, but it is accepted for forward-compatibility only — the underlying Raft
   library has no targeted-transfer API, so the election winner is not guaranteed to match it. Check
   `exact_target` in the response to see whether the winner matched your request.

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
