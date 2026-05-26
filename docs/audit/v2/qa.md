# QA Lane Re-Audit (HEA-770 v2)

**Audit date:** 2026-05-25  
**Branch audited:** `feature/gap-updates-for-clustering` (commit `e381a64`)  
**Auditor:** QA Agent (HEA-770)

---

## Verdict

**production-ready-with-caveats**

All simulation tests pass, no vacuous asserts found in new test files, and the three
newly-added feature areas (required_actions, backup, cluster_admin) are routed and
operationally reachable. The one material gap is that `cluster_admin_endpoints.rs`
covers only rejection paths — there are no positive-path tests for the three cluster
admin routes.

---

## Verified Claims

| Claim | Evidence |
|-------|----------|
| Simulation suite passes | `cargo nextest run --package hearth-simulation`: 33/33 PASS — `simulation/src/tests/*.rs` |
| Required-action routes are wired | `src/protocol/http.rs:624-633` — `/v1/required-actions/{update-password,request-email-verification,verify-email}` |
| Required-action UI interstitials are routed | `src/protocol/web/mod.rs:750-766` — `GET/POST /required-actions/{update-password,verify-email,verify-email/resend,verify-email/success}` |
| System-realm assertion on cluster admin (HEA-763 fix) | `src/protocol/http.rs:342-354` — `extract_cluster_admin_auth` checks `auth.realm_id.as_uuid().is_nil()`, returns 403 for tenant tokens |
| Cluster admin routes are wired | `src/protocol/http.rs:566-574` — `/admin/cluster/{bootstrap,status,transfer-leadership}` |
| Backup routes are wired | `src/protocol/http.rs:559-561` — `POST /admin/backup`, `POST /admin/backup/restore` |
| No bare `is_ok()` asserts without messages | Regex scan of all new test files; all `assert!(x.is_ok())` calls in existing tests carry messages |
| Property tests are substantive | `tests/rbac_property.rs` and `tests/federation_property.rs` use `prop_assert_eq!` / `prop_assert!` — not zero-assert, proptest macro family |
| `session_crash.rs` tests are real | `simulation/src/tests/session_crash.rs` — two `#[test]` fns that open a real `StorageConfig::dev` tempdir, crash-recover by reopening, and assert sessions survive WAL replay |

---

## Falsified or Unverified v1 Claims

### 1. Test count: "941 Rust + 27 simulation"

**v1 quote (MEMORY.md):** `"941 Rust + 27 simulation + 3 TS + 3 Go passing"`

**Current code shows:** `cargo nextest list --workspace` (build env fixed, see Gap 1):
- `hearth` binary (unit + integration): **2212 tests**
- `hearth-simulation` crate: **33 tests**

The v1 count was accurate when written; a large number of tests have been added since
(required_action suites, cluster_admin, backup, additional simulation tests). The
memory entry is not falsified — just substantially outdated. The simulation count grew
from 27 → 33, confirming new coverage was added.

### 2. Simulation test framework: "27 simulation tests"

**v1 quote (MEMORY.md):** Simulation tests completed; counts implied madsim async tests.

**Current code shows:** `simulation/src/tests/session_crash.rs` uses plain `#[test]`
(not `#[madsim::test]` or `#[tokio::test]`). The comment in the file is honest:
*"Deterministic seed for future madsim integration."* These are real WAL crash recovery
tests via `StorageConfig::dev` + tempdir drop-and-reopen — valid, not fake — but they
do not exercise madsim's fault-injection or async determinism. The four
`cluster_failover.rs` tests do use `#[tokio::test]` and exercise Raft scenarios
via a real in-process cluster.

---

## New Gaps Discovered

### Gap 1 — Build environment: missing scratch target dir

`CARGO_TARGET_DIR=/scratch/cache/target` is set in the environment, but
`/scratch/cache/target` did not exist, causing `cargo nextest list` to fail with
`"couldn't create a temp dir"`. The directory had to be created manually with
`mkdir -p /scratch/cache/target` before the full test list could be enumerated.

**Risk:** CI or a fresh developer environment without this directory will fail to
even list tests, masking whether the suite passes. The project should either create
the directory in `make setup` or document the prerequisite.

**Severity:** Medium — affects build tooling, not runtime correctness.

### Gap 2 — `cluster_admin_endpoints.rs` covers only rejection paths

All 12 tests assert HTTP rejection codes (401, 403, 503). There are zero tests for:
- A successful `GET /admin/cluster/status` response (shape of JSON, fields present)
- A successful `POST /admin/cluster/bootstrap` in a multi-node test context
- A successful `POST /admin/cluster/transfer-leadership` with leadership verification

The system-realm gate from HEA-763 is tested (via `*_returns_403_for_tenant_realm_admin`
cases), but the *happy path* of all three endpoints is untested.

**File:** `tests/cluster_admin_endpoints.rs:1-416`  
**Severity:** Medium — negative paths are correct; positive path correctness is
unverified by automated test.

### Gap 3 — `session_crash.rs` uses synchronous `#[test]`, not madsim

As noted above, the session crash-recovery tests run as deterministic synchronous tests
using a real tempdir. They are correct and passing, but they do not leverage madsim's
fault-injection semantics (simulated I/O failures mid-write, network partitions, etc.).
The comment "Deterministic seed for future madsim integration" acknowledges this but
sets no timeline.

**File:** `simulation/src/tests/session_crash.rs:17-20, 122-125`  
**Severity:** Low — tests are valid; full madsim coverage would increase confidence.

---

## Operational Reachability Matrix

| Feature | Route wired? | Auth enforced? | Tests exist? | Positive-path test? |
|---------|-------------|---------------|-------------|-------------------|
| `UPDATE_PASSWORD` required action | ✅ `http.rs:624` | ✅ required-action JWT only | ✅ `required_action_update_password.rs` (6 tests) | ✅ |
| `VERIFY_EMAIL` required action | ✅ `http.rs:629-633` | ✅ required-action JWT only | ✅ `required_action_verify_email.rs` (11 tests) | ✅ |
| Required-action UI interstitials | ✅ `web/mod.rs:750-766` | ✅ session cookie | ✅ `web_ui_account.rs` (indirect) | ✅ |
| `POST /admin/backup` | ✅ `http.rs:559` | ✅ admin role | ✅ `backup_http.rs` (8 tests) | ✅ |
| `POST /admin/backup/restore` | ✅ `http.rs:561` | ✅ admin role | ✅ `backup_http.rs` | ✅ |
| `POST /admin/cluster/bootstrap` | ✅ `http.rs:566` | ✅ system-realm + admin | ✅ rejection only | ❌ no success-path |
| `GET /admin/cluster/status` | ✅ `http.rs:570` | ✅ system-realm + admin | ✅ rejection only | ❌ no success-path |
| `POST /admin/cluster/transfer-leadership` | ✅ `http.rs:574` | ✅ system-realm + admin | ✅ rejection only | ❌ no success-path |

---

## Recommended Follow-up

1. **Fix build environment:** Add `mkdir -p "$CARGO_TARGET_DIR"` to `make setup` or
   document `CARGO_TARGET_DIR` prerequisite in `docs/specs/TESTING.md`.

2. **Add cluster admin positive-path tests** to `tests/cluster_admin_endpoints.rs`:
   at minimum a single-node `GET /admin/cluster/status` success case asserting the
   response shape (`state`, `leader`, `term` fields).

3. **Update MEMORY.md test counts** (currently shows 941 Rust / 27 sim, actual is
   2212 / 33).
