## 1. Delete historical files

- [x] 1.1 Delete 14 dated reports in `reports/` (keep `production-readiness-audit-2026-08-28.md`, which `coverage_check.py` reads)
- [x] 1.2 Delete 51 files in `docs/perf/` (triage notes, dry runs, reports 1.0 and 2.0, unreferenced artifacts); keep `PUBLISHED_FIGURES.md`, `PERFORMANCE_REPORT_2_1.md`, both runbooks, `scripts/c10-artifact-facts.sh` and every artifact a kept file cites
- [x] 1.3 Delete `docs/reviews/`, `docs/specs/IMPLEMENTATION_ORDER.md`, `docs/specs/READINESS_AUDIT_1_0.md`, `docs/sdk-spec.md`, `docs/plans/HEA-2170-pitr-wal-archiving-design.md`
- [x] 1.4 Move the artifact contract and admissibility rules of `PERFORMANCE_REPORT_1_0.md` into `loadtest/README.md`; point `loadtest/src/report.rs`, `examples/argon2_saturation.rs` and `docs/perf/scripts/c10-artifact-facts.sh` at it
- [x] 1.5 Replace every reference to a deleted file with a permalink pinned to `4d9dda1f`; keep the output paths that `loadtest/scripts/run-scale-sweep.sh` writes

## 2. Move contributor docs

- [x] 2.1 `git mv` `ARCHITECTURE.md`, `TESTING.md`, `PROTO.md`, `THEME.md` to `docs/dev/`
- [x] 2.2 `git mv` `CONFIGURATION.md` to `docs/guides/configuration-reference.md`; add it to the docs-site sidebar; `tests/docs_config_snippets.rs` follows the path
- [x] 2.3 Replace `AGENTS.md` with a symlink to `CLAUDE.md`
- [x] 2.4 Rewrite every reference to a moved file

## 3. Convert specs

- [x] 3.1 Write the ADDED delta for each capability in the proposal, checked against the code, with a coverage map from every source section
- [x] 3.2 List every doc/code mismatch for the owner; apply the owner's decisions
- [x] 3.3 Rewrite every reference to a converted doc to its capability; references to content that was not converted get a permalink
- [x] 3.4 Point `scripts/check-abuse-coverage.sh` (`SPEC_DOC`), its CI path filter and `docs/ops/RELEASE_VALIDATION.md` at `openspec/specs/abuse-prevention/spec.md`
- [x] 3.5 Point `loadtest/src/budget.rs` and the benchmark section of `docs/dev/TESTING.md` at `openspec/specs/performance-budgets/spec.md`
- [x] 3.6 Delete the converted sources: `docs/specs/` and `docs/plans/HEA-1114-abuse-prevention.md`

## 4. Project wiring

- [x] 4.1 `CLAUDE.md` "Reference Documents": OpenSpec capabilities table and contributor docs
- [x] 4.2 `openspec/config.yaml`: project context and spec-writing rules
- [x] 4.3 `ci.yml`: drop the path from the `sdk-conformance` display name (`required-summary` needs the job id); update `scripts/ci-required-checks-migrate.sh`
- [x] 4.4 `sdk-standard-libraries`: add task 0.2 to rebase its delta on the new `sdk-support-contract` baseline

## 5. Verify

- [x] 5.1 `openspec validate --all --strict`
- [x] 5.2 `scripts/check-abuse-coverage.sh` passes and its id set covers every live guard (id ledger)
- [x] 5.3 `cargo nextest run --test docs_config_snippets --test docs_cli_invocations`, `scripts/check-bootstrap-quickstart.sh`
- [x] 5.4 No broken relative Markdown link that this change introduced; no reference to a deleted or moved path outside permalinks
- [x] 5.5 `docs-site` builds with `configuration-reference.md`
- [x] 5.6 `cargo fmt --check` and `make clippy`
- [x] 5.7 Archive this change, so the baseline lands in `openspec/specs/`; fill each spec's `## Purpose`
