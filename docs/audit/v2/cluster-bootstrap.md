# Audit v2 — Cluster Bootstrap (Operational Reachability)

**Auditor:** PlatformEngineer agent (HEA-776)  
**Date:** 2026-05-25  
**Branch audited:** `main` (commit `ccb4ba3`)  
**Method:** Docs-only follow-through — no out-of-band knowledge permitted.  
**Primary sources:** `docs/guides/clustering.md`, `docs/guides/disaster-recovery.md`

---

## Verdict

**not-production-ready**

An operator with no prior Hearth knowledge following only the `main`-branch
docs cannot complete a 3-node cluster bootstrap. Step 3 of the documented
bootstrap sequence returns `403 Forbidden` because the required
`X-Realm-ID: 00000000-0000-0000-0000-000000000000` header is absent from
every curl example and the docs never explain how to obtain a system-realm
admin token. Additionally, the backup section references a CLI command
(`hearth snapshot`) that does not exist, and `docs/guides/disaster-recovery.md`
— the second doc the issue mandates — does not exist on `main` at all.

A fix branch exists (`feature/gap-updates-for-clustering`) that corrects
the clustering.md gaps and adds the missing disaster-recovery guide, but it
has not been merged to `main`.

---

## Verified Claims

Each claim below survived the current `main` code scan with file:line evidence.

| Claim | Evidence |
|---|---|
| Three cluster admin endpoints exist in the router | `src/protocol/http.rs:565–575` |
| `POST /admin/cluster/bootstrap` handler implemented | `src/protocol/cluster_admin.rs:39–98` |
| `GET /admin/cluster/status` handler implemented | `src/protocol/cluster_admin.rs:108–173` |
| `POST /admin/cluster/transfer-leadership` handler implemented | `src/protocol/cluster_admin.rs:200–248` |
| mTLS peer gRPC server reads cert/key/CA from config | `src/cluster/server.rs:128–142` |
| ClusterEngine.initialize_cluster calls openraft | `src/cluster/engine.rs:141–164` |
| Bootstrap is idempotent (409 on double-init) | `src/protocol/cluster_admin.rs:60–69` |
| ClusterConfig fields match clustering.md YAML examples | `src/config/types.rs:1973–1992` |
| Default HTTP port is 8420 | `src/config/types.rs:98–99` |
| Default Raft peer port is 8421 | `src/config/types.rs:2004–2006` |
| `hearth serve -c <config>` flag exists | `src/main.rs:54` |
| `hearth backup create/restore/verify/inspect` all exist | `src/main.rs:109–245` |
| Cluster routes return 503 (not 404) in single-node mode | `src/protocol/cluster_admin.rs:43–50` |
| Cluster auth requires system realm (nil UUID) | `src/protocol/http.rs:342–352` |

---

## Falsified or Unverified v1 Claims

No committed v1 lane report was found under `docs/audit/` for the cluster
bootstrap lane. The only audit file on `main` is
`docs/audit/test-suite-audit-2026-05-16.md`, which covers the test suite,
not cluster operations. All findings below come from fresh evidence only.

---

## New Gaps Discovered

### GAP-1 (CRITICAL): `docs/guides/disaster-recovery.md` does not exist on `main`

The issue mandates following both `docs/guides/clustering.md` and
`docs/guides/disaster-recovery.md`. The latter is absent from `main`.

```
find /home/brad/Code/personal/hearth/docs -name "disaster-recovery.md"
# → no output
```

The file exists only on `feature/gap-updates-for-clustering`. Until that
branch is merged, every operator runbook step that references disaster
recovery has no canonical source.

**Operator impact:** Cannot follow the audit mandate. Incident response has
no documented procedure.

---

### GAP-2 (CRITICAL): `X-Realm-ID` header missing from all cluster curl examples on `main`

**Main branch clustering.md (lines 96–101):**

```bash
curl -s -X POST http://10.0.0.1:8420/admin/cluster/bootstrap \
  -H "Authorization: Bearer <admin-token>"
```

**What the code actually requires** (`src/protocol/http.rs:342–352`):

```rust
pub(crate) fn extract_cluster_admin_auth(...) -> Result<AdminAuth, ...> {
    let auth = extract_admin_auth(headers, state)?;
    if !auth.realm_id.as_uuid().is_nil() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "cluster admin requires system realm"})),
        ));
    }
    Ok(auth)
}
```

The function rejects any non-nil realm UUID with `403 Forbidden`. An operator
following main docs will get:

```json
{"error": "cluster admin requires system realm"}
```

with no guidance on what to pass.

**Fix (on feature branch, not yet merged):**
```bash
curl -s -X POST http://10.0.0.1:8420/admin/cluster/bootstrap \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

**All three cluster endpoints are affected.** The same header is missing
from the `status` (line 103) and `transfer-leadership` (line 157) examples.

---

### GAP-3 (CRITICAL): No guidance on obtaining a system-realm admin token

`clustering.md` uses the placeholder `<admin-token>` but never explains:

1. What the "system realm" is (nil UUID `00000000-0000-0000-0000-000000000000`).
2. How to authenticate against it to obtain a bearer token.
3. That `admin-api.md`'s "UUID or slug" guidance for `X-Realm-ID` does
   **not** apply to cluster endpoints (a slug will produce a non-nil realm ID
   and will be rejected — see GAP-2).

The system realm is populated by `POST /admin/bootstrap` (the first-boot
wizard at `/ui/setup`), but this prerequisite is never mentioned in
`clustering.md`. An operator who has not read the getting-started guide
cannot proceed.

**Code reference:** `src/protocol/http.rs:4561` — admin bootstrap endpoint
creates the system realm's initial admin user.

---

### GAP-4 (HIGH): `hearth snapshot` command does not exist

`clustering.md` backup section (line 177):

```bash
hearth snapshot --data-dir /var/lib/hearth/data --output /backups/hearth-$(date +%F).snap
```

The CLI subcommand `snapshot` does not exist. Confirmed by reading the
`Commands` enum (`src/main.rs:42–107`): the only backup-related subcommand
is `Backup { action: BackupAction }`.

The correct command is:

```bash
hearth backup create --data-dir /var/lib/hearth/data --output /backups/hearth-$(date +%F).hearth-backup
```

Two errors in the documented command:
- Wrong subcommand: `snapshot` → `backup create`
- Wrong file extension: `.snap` → `.hearth-backup`

**Operator impact:** `hearth snapshot ...` exits with
`error: unrecognized subcommand 'snapshot'`. Node backups are not taken.

---

### GAP-5 (HIGH, feature-branch DR guide only): `hearth cluster status` CLI does not exist

`disaster-recovery.md` (Raft divergence step 4):

```bash
hearth cluster status   # Should show: leader=this_node, peers=[]
```

The `cluster` top-level subcommand does not exist in the `Commands` enum
(`src/main.rs:42–107`). The operator must use the HTTP endpoint:

```bash
curl http://10.0.0.1:8420/admin/cluster/status \
  -H "Authorization: Bearer <token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

---

### GAP-6 (HIGH, feature-branch DR guide only): `hearth realm rotate-signing-key` does not exist

`disaster-recovery.md` (post-incident signing-key rotation):

```bash
hearth realm rotate-signing-key --realm production --grace-period-hours 24
```

`RealmAction` has only one variant: `Create` (`src/main.rs:244–248`). The
underlying engine method exists at `src/identity/engine.rs:2944` but is not
exposed via any CLI command or admin HTTP endpoint visible in the router.

**Operator impact:** Key rotation after a compromise has no CLI path. The
documented procedure cannot be executed.

---

### GAP-7 (HIGH, feature-branch DR guide only): `hearth session revoke-all` does not exist

`disaster-recovery.md` (post-incident signing-key rotation):

```bash
hearth session revoke-all --realm production
```

There is no `session` subcommand in the `Commands` enum, and no bulk-revoke
HTTP endpoint is registered in the admin router (`src/protocol/http.rs`
grep for `revoke` yields only per-token revocation at `POST /oauth/revoke`).

---

### GAP-8 (MEDIUM, feature-branch DR guide only): `hearth serve --data-dir` flag does not exist

`disaster-recovery.md` test-restore drill step 4:

```bash
hearth serve --data-dir "$DRILL_DIR" --listen 127.0.0.1:8080 &
```

The `Serve` subcommand (`src/main.rs:44–73`) accepts: `--dev`, `--config`/`-c`,
`--port`, `--bind`, `--verbose`. No `--data-dir` or `--listen` flags exist.

The operator cannot start a drill server against an isolated data directory
without writing a `hearth.yaml` config file pointing to that directory.

---

### GAP-9 (MEDIUM, feature-branch DR guide only): `hearth backup inspect --data-dir` is wrong

`disaster-recovery.md` (Raft divergence step 2):

```bash
hearth backup inspect --data-dir /var/lib/hearth/data
```

The `Inspect` subcommand (`src/main.rs:220–227`) takes `--input <archive>`,
not `--data-dir`. `inspect` reads a `.hearth-backup` archive file, not a
live data directory. This command will error:

```
error: unexpected argument '--data-dir' found
```

---

## Operational Reachability Matrix

The five most critical cluster bootstrap operations, traced end-to-end.

| Operation | Documented | Route Registered | Auth Enforced | CLI/Curl Works (main) | Notes |
|---|:---:|:---:|:---:|:---:|---|
| 1. Generate mTLS certs | ✓ | N/A | N/A | ✓ | openssl examples correct |
| 2. Configure cluster YAML | ✓ | N/A | N/A | ✓ | All config fields verified |
| 3. Start nodes + call bootstrap endpoint | ✓ | ✓ `src/protocol/http.rs:565` | ✓ `src/protocol/http.rs:342` | **✗** | Missing `X-Realm-ID` header; no token guidance |
| 4. Verify cluster status | ✓ | ✓ `src/protocol/http.rs:569` | ✓ | **✗** | Same header issue |
| 5. Take follower backup | ✓ | N/A | N/A | **✗** | `hearth snapshot` command does not exist |

**Reachability summary:** 2 of 5 critical operations are fully reachable following
only main-branch documentation. 3 are blocked by doc gaps that cause hard failures.

---

## Comparison with v1 Audit

No v1 lane report for cluster bootstrap exists in the `docs/audit/` directory
on `main`. The parent issue HEA-720 rollup claimed this feature was "complete",
but the current code sweep finds three blocking operational gaps that would
prevent a cold-start operator from succeeding. The v1 claim is assessed as
**aspirational** — it described architectural completeness (code exists), not
operational reachability (operator can follow docs and succeed).

---

## Recommended Actions (priority order)

1. **Merge `feature/gap-updates-for-clustering`** — fixes GAP-1, GAP-2, and
   adds disaster-recovery.md (which itself has additional CLI gaps per GAP-5
   through GAP-9 that need fixing before merge).
2. **Add system-realm token acquisition steps to clustering.md** (GAP-3) —
   this is not in the feature branch either and needs explicit authoring.
3. **Fix `hearth snapshot` → `hearth backup create` in clustering.md** (GAP-4).
4. **Add `hearth cluster status` CLI command OR correct DR guide** (GAP-5).
5. **Implement `hearth realm rotate-signing-key` CLI** (GAP-6) — the engine
   method exists but is not surfaced.
6. **Add `hearth serve --config` example to test-restore drill** (GAP-8) — or
   add a `--data-dir` override flag.
