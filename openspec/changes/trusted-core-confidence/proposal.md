## Why

`scope-trim-trusted-core` shrank Hearth to a trusted core and ships it as 3.0.0. Its proposal
promised the next step: freeze features, then do the confidence work. The audit rounds kept
finding Critical bugs on the joins between features. A smaller core has fewer joins, but
nothing yet proves the joins that remain are correct:

- **External conformance.** One OpenID Foundation plan ran on 2026-09-21 (Config OP), and it
  failed on one condition: discovery did not list RS256. That defect is fixed (RS256 for ID
  tokens, task 26.55 of `production-readiness-remediation`), but no plan has run since. No
  authorization-flow plan (Basic OP, Dynamic OP) has ever run.
- **Invariants across entry points.** Most audit Criticals were one entry point that skipped a
  check its siblings made (a suspended organization, the MFA policy, a disabled client). The
  tests check each entry point on its own. No test fails when a new entry point skips a check.
- **Mutation testing.** `ci/mutations.toml` holds 4 hand-picked mutations, run nightly. Nothing
  measures how many security-relevant mutations the suite misses.
- **Pentest.** `docs/security-audit/pentest-scope.md` is a draft that still names modules and
  routes from before 3.0.0. No external test has been done.

Hearth MUST NOT claim production readiness until this work is done.

## What Changes

- **Feature freeze.** From v3.0.0 until this change is archived, the server accepts no new
  features. Allowed work: defect fixes, removals, tests, docs, tooling, and the
  `sdk-standard-libraries` change.
- **External conformance.** A scripted run of the OpenID Foundation conformance suite (Basic OP,
  Config OP, Dynamic OP) against a production-mode Hearth. Every plan passes with zero failures
  before release. Each warning has a recorded decision.
- **Entry-point invariant tests.** One registry lists every entry point that creates a session
  or issues a token. One table-driven test checks each security invariant on each entry point.
  A guard fails when a route that issues a token or a session is not in the registry.
- **Mutation testing.** `cargo-mutants` runs on the security-critical modules, nightly, with a
  surviving-mutant budget that only goes down. Each kept invariant gets a mutation in
  `ci/mutations.toml`.
- **External pentest.** The scope document is rewritten for the 3.0.0 surface. An external
  firm tests it. Every Critical and High finding is fixed and re-tested before release.
- **Known defects.** The defects found during the scope trim are fixed here (listed in
  `tasks.md` group 1), because the freeze allows fixes.
- **Production-readiness claim.** The README and `docs/STATUS.md` may claim production
  readiness only when every gate above passes.

## Capabilities

### New Capabilities

- `release-assurance`: the feature freeze, the external conformance gate, the entry-point
  invariant registry, the mutation budget, the pentest gate, and the rule for the
  production-readiness claim.

### Modified Capabilities

None.

## Impact

- New: `tests/entry_point_invariants.rs` (registry plus table-driven tests), a
  `make conformance-oidf` target and its script, a nightly `cargo-mutants` workflow and its
  budget file.
- Changed: `ci/mutations.toml`, `docs/security-audit/pentest-scope.md`,
  `docs/dev/TESTING.md` (§7 and the phase checklist), `docs/STATUS.md`, `README.md`,
  `CONTRIBUTING.md` (the freeze rule).
- The defect fixes touch `src/identity/` and `src/protocol/http/` (see `tasks.md` group 1).
- No new runtime dependency. `cargo-mutants` and the conformance suite are tools, not
  dependencies of the binary.
- Order: archive `scope-trim-trusted-core` first. This change can run beside
  `sdk-standard-libraries`.
