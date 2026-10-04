## Context

`docs/specs/` held 17 prose specs (about 13,500 lines). Some were normative behaviour specs, some were contributor guides, and some were trackers. `openspec/specs/` was empty: four active changes added requirements to capabilities that had no baseline. The repo also carried about 75 historical files (dated audit reports, perf triage notes, one-time reviews) that code comments and CI comments still cited.

## Goals / Non-Goals

**Goals:**
- One home for normative requirements: `openspec/specs/`.
- A baseline that the active changes' deltas apply to cleanly when they archive.
- No broken reference anywhere in the repo after the cleanup.

**Non-Goals:**
- No behaviour change. A conversion that finds a doc/code disagreement records it; it does not fix the code or the spec silently.
- No rewrite of `docs/guides/`, `README.md`, the SDK READMEs or `docs/vision/VISION.md`.
- No archive of the four active changes.

## Decisions

1. **Seed the baseline through a change, archived in the same PR.** The deltas are ADDED-only, so `openspec validate --strict` checks their format, and the archive writes `openspec/specs/`. The alternative, writing `openspec/specs/` by hand, has no validation of delta structure and no record of why.
2. **Convert behaviour, move guidance.** A file is converted when it states what the system does (`AUTHORIZATION`, `OIDC`, `AGENT_AUTH`, `SAML`, `SDK`, `ABUSE`, `UI_ROUTING`, benchmark budgets). A file is moved to `docs/dev/` when it states how contributors work (`ARCHITECTURE`, `TESTING`, `PROTO`, `THEME`). `CONFIGURATION.md` is an operator reference, so it moves to `docs/guides/` and the docs site publishes it.
3. **Port the source as written; list mismatches.** Each requirement was checked against the code. Where the code disagrees, the requirement keeps the source text and the mismatch goes to the owner for a decision before merge. Features removed in v3.0.0 get no requirement.
4. **Shared capability names with active changes.** `saml-sp-profile` and `sdk-support-contract` already have ADDED deltas in `scope-trim-trusted-core` and `sdk-standard-libraries`. The baseline uses the same names, leaves out every rule those deltas state, and reuses none of their requirement names, so their later archive appends cleanly. `sdk-standard-libraries` gets a task to turn its rewrite into MODIFIED/REMOVED deltas against the baseline.
5. **The abuse gate reads the spec.** `scripts/check-abuse-coverage.sh` extracted `A-<n>` ids from `docs/plans/HEA-1114-abuse-prevention.md`. It now reads `openspec/specs/abuse-prevention/spec.md`. The spec carries the union of live ids from the plan and `ABUSE.md`, one requirement per id, and no token for a retired id.
6. **Permalinks for deleted files.** Every reference to a deleted file points to `https://github.com/hearth-auth/hearth/blob/4d9dda1f5b514891e90dadeffb03d1a026af4e51/<path>`, the last `main` commit that has it. Scripts that write to a deleted path as output (`loadtest/scripts/run-scale-sweep.sh`) keep their local path.
7. **One report stays.** `production-readiness-remediation/coverage_check.py` reads `reports/production-readiness-audit-2026-08-28.md` from disk. It is deleted when that change archives.

## Risks / Trade-offs

- [A converted spec states something false] → every requirement was checked against the code; disagreements are listed for the owner, not hidden.
- [Normative content lost in conversion] → each conversion produced a coverage map from every source section to a requirement or a stated reason for dropping it.
- [`configuration-reference.md` breaks the MDX build] → the docs site is built locally before push.
- [The abuse gate silently covers fewer guards] → the id ledger compares the old and new id sets; every dropped id is a retired guard.
