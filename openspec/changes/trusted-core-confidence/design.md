## Context

Hearth 3.0.0 is the trusted core that `scope-trim-trusted-core` left behind. The state of each
confidence tool at the start of this change (2026-10-02):

- **OpenID Foundation suite.** `reports/conformance-suite-run-2026-09-21.md` records one run of
  `oidcc-config-certification-test-plan` against `release-v5.3.1`: 38 passed, 1 failed, 1
  warned. The failure (no RS256 in discovery) is fixed: discovery now lists
  `IdTokenSigningAlg::SUPPORTED`. The warning is `resource_indicators_supported`, an
  unregistered metadata name that `docs/specs/AGENT_AUTH.md` requires. The run was manual.
- **In-repo conformance.** `tests/oidc_conformance.rs`, `tests/rfc8693_conformance.rs`,
  `tests/rfc8707_conformance.rs`, `tests/rfc9728_conformance.rs`,
  `tests/federation_conformance.rs`. They are hand-written, not the certifying bodies' suites.
- **SAML.** The XSW1–XSW8 corpus from scope-trim group 3 runs in `tests/saml_sp.rs`. No
  external SAML suite exists to run (the OASIS interop programme is dormant).
- **Mutation.** `.github/workflows/mutation-spot-check.yml` runs `ci/mutations.toml` (4 entries)
  nightly. Each entry names one guard and the one test that must go red.
- **Pentest.** `docs/security-audit/pentest-scope.md` is a draft, pending budget. It still lists
  `/v1/me/permissions`, a legacy password migration path and module paths that no longer exist.

## Goals / Non-Goals

**Goals:**
- Each gate gives a yes/no answer that a script or a CI job computes, except the pentest.
- A new entry point that skips an invariant fails a test without anyone adding a test for it.
- The production-readiness claim depends on recorded evidence, not on judgement.

**Non-Goals:**
- OpenID certification. Certification needs an OIDF membership and a submitted log. That is a
  business decision, out of scope here. This change makes a certification run possible.
- The Raft Jepsen harness. The owner plans it separately.
- SDK confidence work. `sdk-standard-libraries` owns the SDK conformance harness.
- New features of any kind (the freeze).

## Decisions

1. **The freeze lives in `CONTRIBUTING.md` and in this change's spec.** `CONTRIBUTING.md` is what
   a contributor reads. The spec makes the rule reviewable. The freeze ends when this change is
   archived. Alternative considered: a CI check on commit types (`feat:`). Rejected: a commit
   type is easy to mislabel, and the review is the real gate.

2. **OIDF plans: Basic OP, Config OP, Dynamic OP.** Hearth ships the code flow, discovery and
   dynamic registration (RFC 7591). Implicit and Hybrid OP are out: Hearth supports only
   `response_type=code`. The suite runs in Docker from a pinned tag, driven by
   `scripts/conformance-oidf.sh`, against `hearth serve -c` with TLS and a real KEK (never
   `--dev`). The run is per release and on demand, not per PR: it needs a Docker stack and takes
   minutes. Each warning gets a row in the report: fix it, or keep it with a reason.

3. **The `resource_indicators_supported` warning.** Default decision: keep it, record the reason
   (AGENT_AUTH requires it). Open question 1 asks whether to rename it.

4. **The entry-point registry is data, checked against the router.** `tests/entry_point_invariants.rs`
   holds a table: one row per entry point (route, method, kind: session or token). Each
   invariant is a function that sets up a violating state (suspended realm, suspended
   organization, disabled user, disabled client, MFA required and not met, pre-token webhook
   down) and asserts the entry point refuses. A guard test walks the router's route list
   and fails when a route in the token or session family is missing from the table. Rows that do not
   apply to an invariant are marked with a reason, not left out.
   Alternative considered: one test file per entry point. Rejected: that is the current state,
   and it is how a skipped check went unnoticed.

5. **`cargo-mutants` scope.** The scope is `src/identity/` (which holds the SAML SP code), `src/rbac/` and
   `src/protocol/http/`. Storage and Raft are out: their correctness tools are the
   simulation crate and the Jepsen harness. The first run records the number of surviving
   mutants per module in `ci/mutants-budget.toml`. CI fails when a module's count goes up.
   Each reviewed survivor gets a test, or an entry in an exclusion list with a reason.
   `ci/mutations.toml` stays: its entries prove specific guards, which a budget does not.

6. **Pentest gate.** The scope document is rewritten first, from the router and
   `docs/STATUS.md`. The firm tests a tagged build. Every Critical and High finding is
   fixed, with a regression test, and re-tested by the firm. Medium and Low findings get a
   tracked decision.

## Risks / Trade-offs

- [The OIDF Docker stack is heavy and slow] → It runs per release, not per PR. The script pins
  the suite tag, so a suite upgrade is a deliberate change.
- [The router walk can miss an entry point that is not a route, such as a CLI command that mints
  a token] → The registry also lists CLI commands. Task 3.1 surveys them by hand first.
- [`cargo-mutants` on these modules can take hours] → It runs nightly with `--shard`. The budget
  is per module, so a shard can fail on its own.
- [The pentest needs a budget and a vendor] → It is a human task. The release gate waits for it.
  Everything else can finish first.
- [The freeze slows features] → That is the purpose. Fixes are still allowed.

## Open Questions

1. Rename `resource_indicators_supported` to a prefixed name, or keep it (decision 3)?
2. Which pentest firm, and what budget? The owner decides.
3. Does the mutation budget start at the first-run count, or at zero for the identity
   token-issuance code? Default: the first-run count.
