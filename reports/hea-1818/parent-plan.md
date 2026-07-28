# HEA-1766 — Test Suite Audit Plan

## Objective

Verify that Hearth's test suite proves the application delivers its full built feature set: (1) every built feature has real test coverage, (2) every test actually asserts what it claims to assert, (3) no broken features, missing functionality, or major vulnerabilities hide behind green checkmarks.

## Why this needs a structured audit

- The suite is large: **224 integration test files** in `tests/`, plus in-crate `#[cfg(test)]` units, proptests, the `hearth-simulation` madsim crate, Playwright UI crawls, and TS/Go/PHP SDK smokes. Nobody can hold the coverage map in one head.
- We have precedent for **checkbox-complete-but-unreachable** work (HEA-720: Raft/cluster sims claimed done but dead) and for stale docs (CLAUDE.md agent-auth banner). Green ✓ in `TEST_SCENARIOS.md` (currently 317/337 checked) must be re-verified, not trusted.
- Test **anti-patterns** (vacuous `is_ok()` asserts, zero-assert bodies, stale `#[ignore]`s — taxonomy A–I in `docs/specs/TESTING.md`) create false confidence; an accuracy pass per test is explicitly requested.

## Phase 1 — Feature inventory (ground truth)

Build a machine-checkable inventory of *built* features from the code itself (not from docs, which can be stale). One subagent per surface:

| Surface | Source of truth |
|---------|----------------|
| REST/admin/OIDC/SAML/SCIM HTTP routes | route registration in `src/protocol/` (axum routers) |
| gRPC methods | `proto/` service definitions + generated servers |
| UI routes + templates | `src/protocol/web/mod.rs` route table, `templates/ui/` |
| Config surface | `hearth.example.yaml` + `docs/specs/CONFIGURATION.md` cross-check |
| CLI flags/subcommands | `src/main.rs` clap definitions |
| SDK surface (TS/Go/PHP) | `docs/specs/SDK_SURFACE.md` vs actual SDK exports |
| Storage/cluster behaviors | WAL/crash-safety, realm isolation, Raft — from `src/storage/`, `src/cluster/` |
| Security behaviors | authz matrix, token lifecycle, MFA, DPoP/RFC 8693, abuse controls — from `docs/specs/` + recent sweeps HEA-1717/[HEA-1749](/HEA/issues/HEA-1749) |

Deliverable: `feature inventory` document on this issue — one row per feature with its surface, entry point, and spec reference.

## Phase 2 — Coverage mapping (inventory × tests)

Cross-reference every inventory row against the test suite:

- Map each feature to the test file(s)/scenario(s) that exercise it (reflex search + subagent fan-out, one agent per feature domain: auth/OIDC, SAML/federation, RBAC/authz, agent-auth/DPoP, storage/WAL, cluster, admin UI, SCIM, abuse, SDKs, orgs, audit).
- Re-verify the 317 checked boxes in `TEST_SCENARIOS.md` actually map to a live, non-ignored test (spot the HEA-720 pattern). Triage the 20 unchecked boxes: still-relevant gap vs obsolete scenario.
- Classify each feature: **covered** (behavioral assertions at the right layer) / **weakly covered** (only happy path, or only unit-level) / **uncovered**.

Deliverable: coverage matrix document; gap list ranked by risk (security-relevant gaps first).

## Phase 3 — Test accuracy audit (per-test verification)

Dispatch subagents over all 224 integration files + simulation + key unit-test modules, batched ~10–15 files per agent by domain. Each agent verifies, per test:

1. The test name/claim matches what the assertions actually prove.
2. Assertions are behavioral, not vacuous (anti-pattern taxonomy A–I from `docs/specs/TESTING.md`).
3. Setup exercises the real code path (server/embedded harness, not a mock of the thing under test).
4. Negative/failure paths asserted where the test claims enforcement (esp. security tests: assert the *reject*, not just the accept).
5. No stale `#[ignore]`, no commented-out asserts, no tests that pass trivially if the feature is deleted.

Verification technique for suspect tests: mutation spot-checks — temporarily invert the guard the test claims to cover and confirm the test fails (done in a scratch worktree, never committed).

Deliverable: per-domain accuracy report; defect list of inaccurate/vacuous tests.

## Phase 4 — Findings triage & remediation dispatch

- Consolidate Phase 2 gaps + Phase 3 defects into a ranked findings report (document on this issue).
- Anything indicating a **broken feature or vulnerability** (not just a missing test) is escalated immediately: security findings → SecurityAuditor + CTO; functional breaks → child fix issue at appropriate priority.
- Create child issues for remediation batches (est. 6–10 children by domain): write missing tests, repair inaccurate tests, delete/replace vacuous ones. Each child follows the TDD workflow and carries its slice of the findings report as spec.
- Update `TEST_SCENARIOS.md` checkboxes to reflect verified reality.

## Verification & exit criteria

The audit issue closes when:

1. Feature inventory + coverage matrix + accuracy report documents exist on this issue.
2. Every inventory feature is either verified-covered or has a linked child issue for its gap.
3. Every accuracy defect is fixed or has a linked child issue.
4. Any discovered broken feature / vulnerability has an escalated, prioritized issue.
5. `make check` + `make test-quality` green on any test changes landed under this audit.

## Sizing & execution notes

- Phases 1–2 are read-only analysis: heavy subagent fan-out, no code changes. Phase 3 uses scratch worktrees for mutation checks only.
- Estimated 3–4 heartbeats of orchestration for Phases 1–3; remediation (Phase 4 children) sized per finding, runs in parallel via child issues.
- Out of scope: rewriting the test architecture, adding new test *layers* (e.g. fuzzing), coverage tooling adoption (`cargo-llvm-cov` can be proposed as a follow-up if the manual matrix shows systemic blind spots).

## Risks

- **Scale**: 224 files × accuracy review is the bulk of the cost; batching by domain keeps each agent's context coherent.
- **False reassurance**: a test can be accurate but the feature still wrong in unspecified ways — the audit proves tests match claims and features match tests, not spec-completeness beyond the documented feature set.
- **Churn**: security remediation branches ([HEA-1750](/HEA/issues/HEA-1750)..[HEA-1757](/HEA/issues/HEA-1757)) recently landed; audit runs against current `main` after those merge to avoid auditing moving targets.
