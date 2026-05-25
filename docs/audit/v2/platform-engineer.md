# Platform / Ops Lane — v2 Re-Audit

**Auditor:** PlatformEngineer
**Audit date:** 2026-05-25
**Branch audited:** `main` at `ccb4ba3` (`Clustering Gap and Other Updates (#90)`)
**Methodology:** Re-grep from scratch. Every claim backed by `file:line` evidence on current `main`. Issue-tracker / prior-report claims are not treated as authoritative.
**v1 report compared against:** the audit-report document on HEA-727 (Platform, ops & deployment readiness, v1).

---

## Verdict

**production-ready-with-caveats.**

The deployment surface has progressed materially since v1: both v1 Blockers (`/admin/cluster/*` endpoints missing; no DR runbook) are now genuinely closed in code, not just on paper. Container build, healthcheck handlers, metrics surface, and backup/restore round-trip — including the signing-key-continuity regression — are operationally reachable and exercised by tests. The remaining caveats are concentrated in a single area: the **path from a freshly-installed Helm chart to a 3-node HA cluster does not work end-to-end**. The chart ships as `Deployment` (not `StatefulSet`), exposes no cluster topology values, and wires probes to the unconditional `/health` endpoint rather than the storage-aware `/readyz`. Single-node container/systemd deployment is solid; clustered Kubernetes deployment needs another pass.

---

## Verified Claims

Each entry includes `file:line` evidence plus the operational path an operator would use (the v1 audit conflated capability with reachability; v2 separates them).

### 1. Container build is production-grade

- **File:line:** `Dockerfile:29` (builder base pinned by tag + sha256 digest), `Dockerfile:78` (runtime base digest-pinned), `Dockerfile:100–103` (non-root UID 10001 + system group), `Dockerfile:114–118` (OCI labels with `BUILD_VERSION` / `BUILD_REVISION` build-args), `Dockerfile:125–126` (`HEALTHCHECK` against `/health`), `Dockerfile:128` (`tini` as PID 1).
- **Operational path:** `docker build` produces a non-root, healthcheck-equipped image. `compose.dev.yaml` (root) and `deploy/docker-compose.yml` exercise the entrypoint. CI builds the same Dockerfile (verified by inspection of `.github/workflows/`).

### 2. Healthcheck endpoints exist and are differentiated

- **File:line:** `src/protocol/http.rs:874` (`healthz` — pure liveness), `:884` (`readyz` — calls `identity.is_storage_healthy()` via `spawn_blocking`, returns 503 on unhealthy storage), `:939` (`health` — legacy 200-always).
- **Route registration:** `src/protocol/http.rs:578–580`.
- **Operational path:** `curl http://host:8420/healthz` for liveness, `/readyz` for readiness, `/health` for legacy load balancers. Documented in Dockerfile comment at `:122`.
- **Caveat (see new gap N1):** these endpoints exist and behave correctly. The Helm chart does **not** wire them through.

### 3. Cluster admin HTTP endpoints exist (v1 Blocker fixed)

- **File:line:** `src/protocol/cluster_admin.rs:39–96` (`POST /admin/cluster/bootstrap`), `:108–171` (`GET /admin/cluster/status`), `:200–259` (`POST /admin/cluster/transfer-leadership`). Routes registered at `src/protocol/http.rs:565–575`.
- **Auth:** `extract_cluster_admin_auth` at `src/protocol/http.rs:342–354` requires an admin token and rejects tenant-realm tokens (must be the nil/system realm). Each handler invokes the check before any state read.
- **Operational path:** documented at `docs/guides/clustering.md:96–146` with the actual `curl` invocation, response shape, and error codes. Documentation now matches code.
- **Tests:** `tests/cluster_admin_endpoints.rs` (lines `141, 161, 181, 203, 226, 249, 278, 301, 324, 352, 374, 396`) exercises auth (401), authz (403 for non-admin / tenant realm), and single-node mode (503) for all three endpoints.

### 4. Multi-node Raft chaos / failover tests exist (v1 Major fixed)

- **File:line:** `simulation/src/tests/cluster_failover.rs:1–10` documents AC-1 (network partition), AC-2 (leader-kill), AC-3 (rolling restart), AC-4 (cold-follower snapshot catch-up). Implementation runs in-process with an `InMemoryNetworkFactory` (`:42–46`) and a `partitioned: PartitionSet` (`:40`) for cross-node partition control.
- **Operational path:** `cargo test -p hearth-simulation cluster_failover` exercises the four acceptance criteria deterministically without TLS or gRPC ports.

### 5. Backup/restore round-trip is comprehensive and preserves signing keys (v1 Major fixed)

- **File:line:** `tests/backup.rs:103` (`full_roundtrip`), `:204` (`test_restore_preserves_signing_keys`), `:333` (realm-scoped), `:379` (corruption detection), `:407` (idempotency), `:461` (dry-run), `:502` (encrypted roundtrip), `:547` (wrong-passphrase rejection), `:580` (overwrite), `:657` (audit inclusion), `:842` (`large_realm_restore_under_60s` — perf baseline).
- **Signing-key persistence:** `src/backup/import.rs:215–228` now passes `signing_key_pkcs8` through to `import_realm_record`, and `:199–203` logs the failure mode if the archive is missing the key bytes. The assertion at `tests/backup.rs:284–288` proves PKCS#8 byte-equality across restore; `:300–309` proves JWKS `kid` continuity; `:317–323` verifies a pre-restore JWT against the *restored* public key.
- **Operational path:** `hearth backup create` / `hearth backup restore` / `hearth backup verify` / `hearth backup inspect`, exposed in `src/main.rs` CLI and documented at `docs/guides/backup.md` and `docs/guides/disaster-recovery.md:380–409`.

### 6. DR runbook exists and is operator-actionable (v1 Blocker fixed)

- **File:line:** `docs/guides/disaster-recovery.md` (579 lines). Sections cover SST corruption (`:73`), WAL torn-write, Raft divergence / split-brain, signing-key rotation, full-restore (`:368–409`), RTO/RPO planning (`:413–476`), test-restore drill (`:480–563`).
- **Quality of actionability (the v1 lens):** every section gives concrete shell commands (`systemctl stop hearth`, `cp -a … data.pre-recovery.$(date +%s)`, `hearth backup restore …`, `curl … /jwks.json | jq …`). Invariants are stated up front at `:26–69` (single writer / snapshot before mutation / signing-key continuity), with the latter cross-referenced to the HEA-745 fix and the regression test.
- **Quarterly drill checklist** at `:480–563` includes the kid-diff command — turning "the restore worked" from a hope into a measurement.

### 7. Metrics surface is unchanged and exposed (v1 no-change)

- **File:line:** `src/metrics.rs:30–87` defines six metrics: `hearth_http_request_duration_seconds`, `hearth_auth_attempts_total`, `hearth_tokens_issued_total`, `hearth_active_sessions`, `hearth_storage_operation_duration_seconds`, `hearth_audit_integrity_failures_total`.
- **Route:** `src/protocol/http.rs:581` registers `/metrics`; handler at `:912–931` gates on `state.metrics_enabled` and serves Prometheus text format 0.0.4.
- **Operational path:** `curl http://host:8420/metrics` returns the snapshot. Prometheus scrape config works out of the box.

### 8. Storage / WAL format versions and migration scaffolding

- **File:line:** `src/storage/migrations.rs:18` (`WAL_VERSION_CURRENT: u16 = 1`), `:78–80` writes the version into the WAL header. `src/backup/types.rs:10` (`MANIFEST_VERSION: u32 = 1`), `:104`, `:166` stamp the version into archive manifests.
- **Operational path:** versioned at the bytes-on-disk level. No actual forward-only migration path is exercised yet (only one version exists). This is policy-shaped, not a regression — see falsified-claims table.

---

## Falsified or Unverified v1 Claims

| v1 claim (quoted) | Status | Current evidence |
|---|---|---|
| "Finding 1: `/admin/cluster/{bootstrap,status,transfer-leadership}` routes return zero matches in `src/`" | **Falsified — fixed.** | Routes exist in `src/protocol/http.rs:565–575`; handlers in `src/protocol/cluster_admin.rs:39, 108, 200`; auth enforced by `extract_cluster_admin_auth` at `http.rs:342–354`. |
| "Finding 2: no test deliberately partitions the network, kills a leader, or stalls a follower… No `simulation/` test targets the cluster layer" | **Falsified — fixed.** | `simulation/src/tests/cluster_failover.rs` runs four AC scenarios (partition, leader kill, rolling restart, snapshot catch-up) with an in-process partition set. |
| "Finding 4: No `docs/guides/disaster-recovery.md` exists" | **Falsified — fixed.** | `docs/guides/disaster-recovery.md` is 579 lines with shell-level commands per failure shape. Symptom-to-section table at `:14–22` doubles as an incident triage flow. |
| "Finding 5: `src/backup/import.rs:216–220` skips the archived `signing_key.json` and generates fresh keys" | **Falsified — fixed.** | `src/backup/import.rs:215–228` now passes archived signing-key bytes into `import_realm_record`; logged warning at `:199–203` when archive lacks them; verified by `tests/backup.rs:204–326`. |
| "Finding 3: No Rust call site invokes openraft's `add_learner()` or `change_membership()`" | **Confirmed — still open.** | `grep -nE "add_learner|change_membership" src/` returns zero matches; only `transfer_leadership` is exposed on `ClusterEngine` (`src/cluster/engine.rs:253`). Replacing a failed node still requires re-bootstrap. |
| "Finding 6: No PITR; full-snapshot backups only" | **Confirmed — still open.** | Backup CLI surface in `src/backup/` is unchanged at the API level: `create`, `restore`, `verify`, `inspect`. No `replay` / `snapshot-since` / incremental subcommand. (v1 already proposed deferring this; flag for honesty, not for urgency.) |
| "Finding 7: Zero `#[instrument]` macros in `src/`" | **Confirmed — still open.** | `grep -c "#\[instrument" src/**/*.rs` finds 4 occurrences across only 2 files (`src/backup/export.rs`, `src/cluster/state_machine.rs`). No per-handler spans. |
| "Finding 8: No `deploy/grafana/` or `deploy/observability/` directory" | **Confirmed — still open.** | `find deploy -type d` returns only `helm`, `helm/hearth`, `helm/hearth/templates`, `systemd`. No dashboards or alerting rules committed. |
| "Finding 10: README line 11 claims 'Single binary · Zero external dependencies'" | **Confirmed — still open.** | `README.md:11` still reads "Sub-millisecond p99 · One binary · Zero external dependencies". `:13` retains the same framing. No `docs/guides/production-checklist.md` exists. |
| "Finding 11: `WAL_VERSION_CURRENT = 1`, `MANIFEST_VERSION = 1`, no migration story" | **Confirmed — still open.** | Versions unchanged. No published format-stability policy in `CHANGELOG.md` or `docs/specs/`. `redb` still `Cargo.toml`-pinned to a major-version-only constraint (caret default). |
| "Finding 12: `values.yaml` defaults to requests `100m CPU / 128 Mi RAM`… no `cluster` block… HPA disabled by default" | **Confirmed — still open.** | `deploy/helm/hearth/values.yaml:42–48` unchanged (`requests: 100m / 128Mi`; `limits: 1000m / 512Mi`). `:15` `replicaCount: 1`. `:172–174` PDB disabled. No `cluster` block in values; chart has no way to render `cluster.peers`. |
| "Finding 13: No graceful Raft-aware shutdown" | **Confirmed — still open.** | `src/main.rs:1701–1706` installs only `tokio::signal::ctrl_c()`; the shutdown future logs and exits. No SIGTERM-specific handler. No leadership-transfer-on-shutdown. `cluster.transfer_leadership` is exposed but is not invoked from the shutdown path. |

---

## New gaps discovered in this sweep

### N1 — Helm probes don't actually check storage health  *(Major)*

`deploy/helm/hearth/templates/deployment.yaml:77–80` reads `livenessProbe` and `readinessProbe` from `values.yaml`. The defaults at `deploy/helm/hearth/values.yaml:150` and `:159` both target **`path: /health`** — which is the unconditional 200 handler at `src/protocol/http.rs:939`, not the storage-aware `/readyz` at `:884`.

**Operational impact:** a pod with broken storage (corruption, `redb` open failure, full disk on the data PVC) will still pass the readiness probe, so the Service will keep routing OIDC / token traffic to a process that cannot serve it. The right endpoint exists in code — it's just not the one the chart points at.

**Fix:** change `values.yaml:150` to `/readyz` (with `failureThreshold` left as is, since `is_storage_healthy()` is a fast check), and `:160` likewise. Keep `livenessProbe` on `/healthz` (pure liveness) so transient storage hiccups don't get the pod killed.

### N2 — Workload kind is `Deployment` for a stateful, embedded-storage service  *(Major)*

`deploy/helm/hearth/templates/deployment.yaml:2` declares `kind: Deployment`. Hearth carries embedded WAL/SST storage on a PVC (`templates/deployment.yaml:65–67`, `values.yaml:75–84`) and in clustered mode requires stable per-node identity (Raft `node_id`, mTLS leaf certs per node, peer DNS names). `Deployment` gives pods random suffixes and no guaranteed pod-to-PVC binding under rescheduling.

**Operational impact:** the clustering guide at `docs/guides/clustering.md:71–82` describes per-node config files (`hearth-1.yaml` ... `hearth-3.yaml`) with stable peer addresses. The current Helm chart has no way to render this topology. Scaling `replicaCount: 3` in the chart would produce three identical pods all loading the same ConfigMap and racing on the same PVC.

**Fix:** convert the workload to `StatefulSet` with `volumeClaimTemplates`, headless `Service`, and per-pod config rendered via `index .Values.cluster.peers $podOrdinal`. Add a `cluster` block to `values.yaml` per the v1 finding-12 proposal.

### N3 — `/admin/cluster/bootstrap` ignores its request body  *(Minor)*

`src/protocol/cluster_admin.rs:39–96` reads the initial member list from `cluster.initial_members()` (the config-time peers list, `:55`) — it does not parse the HTTP body. The docs at `docs/guides/clustering.md:96–101` accordingly send no body, but the route signature accepts arbitrary bodies silently.

**Operational impact:** an operator who wants to bootstrap with a *different* member set than the config file (e.g. to bring up a smaller test cluster) cannot do it via the API. Combined with the absence of `add_learner` (v1 finding 3, still open), the only way to change membership is to rewrite every node's config and rolling-restart — which itself relies on the no-graceful-Raft-shutdown path (v1 finding 13, still open).

**Fix:** either parse a `{"members": [...]}` body and validate against `cluster.peers` (defensive), or reject non-empty bodies with 400 to make the contract explicit.

### N4 — `/admin/cluster/status` peers list excludes self  *(Minor, observability gap)*

`src/protocol/cluster_admin.rs:144–147` filters `metrics.membership_config.nodes()` with `**id != self_id`. Operators reading the status response cannot see this node's own ID or address from the peers array — only from the top-level `term` and inferred-from-role fields. For monitoring scripts that walk the cluster, this means a separate `node_id` lookup is needed per node.

**Operational impact:** small but real for ops tooling. The omission also means an operator cannot verify their own node is a member of the configured membership set by reading status alone.

**Fix:** include `self` in the peers array with an `is_self: true` flag, or surface `node_id` as a top-level field in the response JSON.

### N5 — No CI step exercises the Helm chart or backup CLI end-to-end  *(Minor)*

Re-grepping `.github/workflows/` shows `ci.yml`, `security.yml`, `fuzz.yml`, `ui-nightly.yml`, `bench-regression.yml`, `scorecard.yml`, `dependabot-automerge.yml`, plus the consolidated workflows added in HEA-680. None render the Helm chart against `kubeval` / `helm lint`, none load the chart into a `kind`/`k3d` cluster, and none drive the backup CLI through a round-trip in CI. Local Rust tests cover the backup invariant, but the chart drift (gaps N1, N2) would have been caught by a simple `helm template` + manifest assert in CI.

**Fix:** add a `chart-lint` workflow that runs `helm lint`, `helm template`, and `kubeval`. A second step that does `kind create cluster && helm install hearth --set persistence.enabled=false && kubectl wait …` would catch the readiness-probe gap before it ships.

---

## Operational reachability matrix — top 5 features in this lane

| Feature | Code (file:line) | Wired through routing? | Wired through CLI? | Wired through Helm? | Reachability verdict |
|---|---|---|---|---|---|
| Container build | `Dockerfile:29, 78, 100, 125, 128` | n/a | `docker build`, `docker compose up` (`compose.dev.yaml` at root) | `image.repository` / `image.tag` in `values.yaml:6–10` | **Operationally reachable.** Single-node container deploy works out of the box. |
| Healthcheck endpoints | `src/protocol/http.rs:874, 884, 939`, routes at `:578–580` | Yes (`/health`, `/healthz`, `/readyz`) | n/a | **Partial** — `livenessProbe` and `readinessProbe` both target `/health`, not `/readyz` (gap N1) | **Operationally reachable from raw curl; broken in Helm.** |
| Metrics surface | `src/metrics.rs:30–87`, route at `src/protocol/http.rs:581`, handler at `:912` | Yes, gated by `state.metrics_enabled` | n/a | Enabled by default via config | **Operationally reachable** for scraping. No dashboards or alert rules shipped. |
| Backup / restore round-trip | `src/backup/import.rs:215`, `src/backup/export.rs`, tests at `tests/backup.rs:103, 204` | Admin HTTP endpoint exists (`/admin/backup`, `/admin/backup/restore` — `src/protocol/http.rs:559–562`) | `hearth backup {create,restore,verify,inspect}` | n/a (operator runs against the binary, not the chart) | **Operationally reachable end-to-end.** DR runbook references the same CLI commands. |
| Cluster bootstrap | `src/protocol/cluster_admin.rs:39, 108, 200`; routes at `src/protocol/http.rs:565–575`; engine at `src/cluster/engine.rs:199, 253` | Yes (admin token + nil realm gated) | Indirect (configure `cluster.peers` → start binary → POST bootstrap) | **Not reachable from the current chart** — `Deployment` workload, no `cluster` block in `values.yaml` (gap N2) | **Reachable on bare metal / systemd, not from Helm.** |

---

## Out-of-scope / unknowns

- **Did not boot a real 3-node cluster from the docs.** HEA-776 is a dedicated child issue for that op-check. This audit asserts code/test reachability but not "follow the documented steps on a clean VM and watch it work."
- **Did not run a power-loss / kill -9 durability test.** openraft delegates persistence to the log store (`src/cluster/log_store.rs`); inspection only.
- **Did not assess remote/cross-region replication.** Hearth is single-region Raft; WAN behavior is unknown.
- **Did not lint the Helm chart with `helm lint` or render it with `helm template`.** Findings N1 and N2 come from reading templates and values; an explicit render would surface secondary defects. (See gap N5.)
- **Did not exercise the DR runbook on a real corrupted dataset.** Runbook content is operator-actionable on inspection; the quarterly drill it describes has not yet been run.
- **Did not audit CI workflow content** beyond confirming none of them render the chart or drive the backup CLI.

---

## Top 3 takeaways for the HEA-720 rollup

1. **The two v1 Blockers are genuinely closed** in code, tests, and docs — cluster admin endpoints (`src/protocol/cluster_admin.rs`) and DR runbook (`docs/guides/disaster-recovery.md`, 579 lines including a quarterly drill). The "all done" rollup is *not* fabricated here; it just isn't the whole story.

2. **The Helm chart is the new operational liability**, not openraft. Two latent defects (gap N1 — probes on `/health` not `/readyz`; gap N2 — `Deployment` for a stateful service) mean a Kubernetes operator following the chart's defaults will get a degraded readiness contract and cannot reach the now-functional cluster bootstrap path. Both fixes are S-effort.

3. **The remaining v1 findings (membership API, tracing, dashboards, graceful Raft shutdown, format-stability policy)** are all non-Blockers individually but together describe a service that operates correctly until something fails and an operator has to intervene. They are the right pre-1.0 work for the next Phase A wave.
