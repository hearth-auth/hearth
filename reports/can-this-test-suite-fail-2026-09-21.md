# Can this test suite fail?

Tasks 23.3 (re-run P29) and 23.15 (run the mutation spot-check against a green
baseline — the audit brief's "highest-value action").

The audit of 2026-08-28 could not answer the question:

> We therefore cannot say whether this test suite can fail.

It can. This report is the evidence, and every number in it was measured on
2026-09-21 by running the thing, not by reading it.

## 1. The baseline is green

```
cargo nextest run --workspace --test-threads 4 --no-fail-fast
Summary [ 207.576s] 5463 tests run: 5463 passed, 14 skipped
```

A mutation spot-check against a red baseline proves nothing — a test that is
already failing fails again for free. That is why 23.15 was gated on a green
run, and why the runner re-checks each entry's baseline individually before
mutating anything.

## 2. Four security-critical guards were mutated; all four went red

`scripts/mutation-spot-check.sh` against `ci/mutations.toml`, run in full:

```
── wal-fsync-before-ack
   guard: Group commit must propagate the fsync error; discarding it acks a lost write.
   baseline: PASS (the guard's test is green at HEAD)
   mutated:  FAIL — the guard is guarded

── csrf-header-required-on-json-mutations
   guard: RequireCsrf must reject an absent or mismatched X-CSRF-Token on a mutation.
   baseline: PASS   mutated: FAIL — the guard is guarded

── admin-console-requires-hearth-admin
   guard: RequireAdmin must 403 a system-realm session without the hearth.admin permission.
   baseline: PASS   mutated: FAIL — the guard is guarded

── memtable-scan-bounded-to-one-realm
   guard: A realm scan must start at the realm's prefix and stop at its end.
   baseline: PASS   mutated: FAIL — the guard is guarded

entries run: 4   proven: 4   failed: 0
every mutated file was restored byte-identically (SHA-256 verified)
```

`git diff` over `src/storage/wal.rs`, `src/protocol/web/auth.rs` and
`src/storage/memtable.rs` is empty afterwards.

The four are not a sample of convenience. They span the storage durability
invariant, the browser mutation surface, the admin authorization gate and realm
isolation — four different layers, four different test harnesses
(`hearth-simulation`, two integration binaries, the library's own unit tests).

## 3. The instrument found a real gap the first time it was used

The admin entry originally named `non_admin_user_gets_403_on_admin_pages`, and
the mutation **survived**. That test's cookie names a *tenant* realm, so
`RequireAdmin`'s realm gate refuses before the permission lookup ever runs —
the `hearth.admin` check itself had **zero coverage**.

`system_realm_user_without_admin_permission_gets_403`
(`tests/web_ui_admin.rs`) was written to close it, and it is the entry the
manifest names now.

This matters more than the four green lines above: an instrument that finds
nothing on first use is usually not measuring anything.

## 4. A red test could reach `main` through six paths; all six are shut

`scripts/check-red-test-gate.sh`, six rules, verified against HEAD:

```
ok:   R1: the workspace gate runs unfiltered.
ok:   R2: `make check` runs every gate and exits non-zero if any failed.
ok:   R3a: no step of the `quality` job is continue-on-error.
ok:   R3b: no job on the required path is continue-on-error.
ok:   R4: every piped `cargo nextest` invocation sets pipefail.
ok:   R5: required-summary passes only `success` and `skipped`.
ok:   R6: `make loadtest-check` lints the excluded loadtest crate with -D warnings.

✓ red-test gate: a red test cannot reach main through any of the six audited paths.
```

Two of those were open when this pass started:

* **R5 was fail-open by construction.** `required-summary`'s loop was a
  *denylist* of `failure` and `cancelled`, so any other result — including an
  empty one — read as "fine". It is an allowlist of `success|skipped` now.
* **`make test-quality` was RED at HEAD**, and it is a merge gate
  (`Makefile` `check`, and its own step in `ci.yml`'s `quality` job, which is in
  `required-summary`'s `needs`). One violation was real; one was the rule
  reporting itself, because it grepped the literal text `#[ignore` anywhere on
  a line and a prose comment saying a test must *not* be ignored tripped it.

The gate has its own red case for every rule:
`scripts/tests/check-red-test-gate.test.sh`, 12 cases, all passing — including
a cry-wolf case that fails if a rule fires on prose. A guard with no red case is
not a guard; this repository has shipped a "fixed" gate that was a fail-open
no-op before (HEA-2199 / #316).

## 5. Twenty-nine structural guards, not four

`scripts/check-*.sh` numbers 29 at HEAD. Two that were written during this pass
are worth naming because they generalise rather than patch:

* **`tests/audit_discard_guard.rs`** parses the `FailOperation` action list
  **out of** `AuditAction::failure_policy` instead of copying it, so moving an
  action into that list automatically widens the guard. It cannot go stale.
  It found nine sites; four were real defects.
* **`ci/mutations.toml`** refuses a manifest whose anchor string occurs more
  than once in its file — a two-occurrence anchor silently mutates the wrong
  call site and produces a green badge over an untested guard.

## 6. Where the mutation discipline actually ran

Of the 46 commits on this branch in the 24 hours to 2026-09-21, **13 state a
mutation proof in the commit message itself**: the guard was deleted, exactly
the covering test went red, its neighbours stayed green, the file was restored,
and the SHA-256 was re-checked. More proofs than that were performed and
reported in agent summaries; 13 is the number that survives `git log`, so it is
the number quoted here.

## What this does NOT establish

Stated plainly, because a report that only lists successes is the defect this
whole exercise exists to catch.

* **Four entries is a spot-check, not mutation coverage.** It answers "can this
  suite fail?" It does not answer "what fraction of guards are tested?" A real
  mutation-coverage run (`cargo-mutants` over the workspace) has never been
  done here, and would be the honest next step.
* **The four entries were chosen because they already had tests.** They prove
  those tests are load-bearing. A guard with no test at all is invisible to
  this instrument — which is exactly how the `hearth.admin` gap survived until
  an entry was pointed at it.
* **The full run is nightly, not PR-blocking.** Each entry rebuilds the
  `hearth` library twice across four distinct targets: 5m26s warm, 25–40
  minutes cold on a runner. The cheap half — `--check` plus the runner's own
  self-test — does run on every PR.
* **The 5463-test baseline predates the last few commits on this branch.** It
  was measured at the point named above; re-measure before treating it as
  current.

## Verdict

The question the audit could not answer is answered: **yes, this suite can
fail, and the paths by which a failing test could have reached `main` are shut
and have red cases of their own.** What remains unmeasured is how *much* of the
codebase the suite would notice changes to, which is a different question and a
larger instrument.
