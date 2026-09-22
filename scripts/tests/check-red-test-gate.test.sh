#!/usr/bin/env bash
# scripts/tests/check-red-test-gate.test.sh — tests for
# scripts/check-red-test-gate.sh (production-readiness task 24.4).
#
# A guard with no red case is not a guard: an `exit 0` stub would pass CI
# forever, which is the same class of defect the audit found. Every rule below
# is fed the shape it exists to refuse.
#
#   case 1  the remediated shape passes
#   case 2  R1 — `make test` carries a -E test filter
#   case 3  R1 — `make test` drops --workspace
#   case 4  R2 — `check:` uses prerequisite chaining (the audited §1/§2.3 shape)
#   case 5  R2 — `make check` reports failures and never exits non-zero
#   case 6  R3 — a continue-on-error step inside the quality job
#   case 7  R3 — prose mentioning continue-on-error must NOT trip the rule
#   case 8  R4 — a piped `cargo nextest` with no pipefail (the `| tee` mask)
#   case 9  R5 — required-summary's denylist of failure/cancelled
#   case 10 R6 — `make loadtest-check` never runs clippy (the audited L-7 shape)
#   case 11 R6 — clippy without -D warnings, so the lint cannot fail the gate
#   case 12 R6 — no loadtest-check target at all
#
# Usage: bash scripts/tests/check-red-test-gate.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-red-test-gate.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

GOOD_TEST_TARGET='test:
	PROTOC=$(PROTOC) cargo nextest run --workspace $(CARGO_FLAGS)
'

GOOD_CHECK_TARGET='check:
	@failed=""; \
	for gate in clippy fmt test-quality test; do \
	  if $(MAKE) --no-print-directory $$gate; then :; else failed="$$failed $$gate"; fi; \
	done; \
	if [ -n "$$failed" ]; then exit 1; fi
'

# R6: the loadtest crate is excluded from the workspace, so this target is the
# only thing in the repository that can lint it.
GOOD_LOADTEST_TARGET='loadtest-check:
	PROTOC=$(PROTOC) cargo check --manifest-path loadtest/Cargo.toml
	PROTOC=$(PROTOC) cargo clippy --manifest-path loadtest/Cargo.toml --all-targets -- -D warnings
	PROTOC=$(PROTOC) cargo nextest run --manifest-path loadtest/Cargo.toml
'

GOOD_CI='name: CI
jobs:
  quality:
    name: quality
    steps:
      - name: make check
        run: make check

  required-summary:
    name: required-summary
    needs: [quality]
    steps:
      - name: Check all jobs passed or were skipped
        run: |
          for result in "$QUALITY"; do
            case "$result" in
              success|skipped) ;;
              *) echo "blocked"; exit 1 ;;
            esac
          done
'

# run_case <name> <expected-exit> <makefile> <ci.yml> [expected-substring]
run_case() {
    local name="$1" want="$2" makefile="$3" ci="$4" expect="${5:-}"
    case_n=$((case_n + 1))
    local dir="${TMP}/case-${case_n}"
    mkdir -p "${dir}/.github/workflows"
    # Every fixture gets a compliant loadtest-check target unless the case is
    # about R6 and supplies its own, so the rules stay independently testable.
    if [[ "$makefile" != *"loadtest-check"* ]]; then
        makefile="${makefile}
${GOOD_LOADTEST_TARGET}"
    fi
    printf '%s' "$makefile" > "${dir}/Makefile"
    printf '%s' "$ci"       > "${dir}/.github/workflows/ci.yml"

    local out got=0
    out="$(REPO_ROOT="$dir" bash "$CHECK" 2>&1)" || got=$?
    if [[ "$got" -ne "$want" ]]; then
        echo "FAIL: ${name} — expected exit ${want}, got ${got}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    if [[ -n "$expect" && "$out" != *"$expect"* ]]; then
        echo "FAIL: ${name} — output missing expected text: ${expect}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${name}"
}

# 1 — the remediated shape.
run_case "the remediated shape passes" 0 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}" "$GOOD_CI" \
    "a red test cannot reach main"

# 2 — R1: a filter in the gate's own command. This is how one inconvenient
#     test stops being gated without anyone deleting it.
run_case "R1 rejects a -E filter on the workspace gate" 1 \
    'test:
	PROTOC=$(PROTOC) cargo nextest run --workspace -E (test(not_the_red_one))
'"
${GOOD_CHECK_TARGET}" "$GOOD_CI" \
    "carries a test-selection filter"

# 3 — R1: --workspace dropped, so the simulation crate (which holds the
#     crash-recovery regression tests) is never run.
run_case "R1 rejects a gate that drops --workspace" 1 \
    'test:
	PROTOC=$(PROTOC) cargo nextest run $(CARGO_FLAGS)
'"
${GOOD_CHECK_TARGET}" "$GOOD_CI" \
    "does not pass --workspace"

# 4 — R2: THE AUDITED SHAPE (§1, §2.3). Prerequisite chaining aborts the whole
#     target on the first failing gate, so a denied clippy lint means the test
#     suite never ran on that commit.
run_case "R2 rejects prerequisite chaining in check" 1 \
    "${GOOD_TEST_TARGET}
check: clippy fmt test-quality test
	@echo done
" "$GOOD_CI" \
    "prerequisite chaining"

# 5 — R2: every gate runs, the result is printed, and nothing ever exits 1.
run_case "R2 rejects a check that never exits non-zero" 1 \
    "${GOOD_TEST_TARGET}
check:
	@for gate in clippy fmt test-quality test; do \\
	  \$(MAKE) \$\$gate || echo \"\$\$gate FAILED\"; \\
	done
" "$GOOD_CI" \
    "never exits non-zero"

# 6 — R3: a continue-on-error step inside the quality job. Audit §4.12#3 found
#     exactly this shape turning a 70-vulnerability scan into a success job.
run_case "R3 rejects a continue-on-error step in the quality job" 1 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}" \
    'name: CI
jobs:
  quality:
    name: quality
    steps:
      - name: make check
        continue-on-error: true
        run: make check

  required-summary:
    name: required-summary
    needs: [quality]
    steps:
      - name: Check all jobs passed or were skipped
        run: |
          for result in "$QUALITY"; do
            case "$result" in
              success|skipped) ;;
              *) exit 1 ;;
            esac
          done
' \
    "contains \`continue-on-error\`"

# 7 — R3 must not cry wolf. The real ci.yml carries a comment explaining why the
#     audited continue-on-error step was removed; a gate that fails on its own
#     rationale gets switched off, which is the fail-open this file guards.
run_case "R3 ignores prose that merely mentions continue-on-error" 0 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}" \
    'name: CI
jobs:
  quality:
    name: quality
    steps:
      # The audit found this step was continue-on-error with no re-raise.
      # Do not re-add a disarmed advisory step here.
      - name: make check
        run: make check

  required-summary:
    name: required-summary
    needs: [quality]
    steps:
      - name: Check all jobs passed or were skipped
        run: |
          for result in "$QUALITY"; do
            case "$result" in
              success|skipped) ;;
              *) exit 1 ;;
            esac
          done
' \
    "a red test cannot reach main"

# 8 — R4: THE PIPE MASK (§4.8#6, §4.12#9). `bash -e {0}` has no pipefail, so
#     tee's exit 0 is what the step reports however red the suite went.
run_case "R4 rejects a piped nextest with no pipefail" 1 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}" \
    'name: CI
jobs:
  quality:
    name: quality
    steps:
      - name: Full workspace test suite
        run: |
          cargo nextest run --workspace --no-fail-fast | tee nextest.log

  required-summary:
    name: required-summary
    needs: [quality]
    steps:
      - name: Check all jobs passed or were skipped
        run: |
          for result in "$QUALITY"; do
            case "$result" in
              success|skipped) ;;
              *) exit 1 ;;
            esac
          done
' \
    "runs without pipefail"

# 9 — R5: the denylist form. Fail-open by construction — an empty result string
#     from an expression that did not evaluate reads as "fine".
run_case "R5 rejects a failure/cancelled denylist" 1 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}" \
    'name: CI
jobs:
  quality:
    name: quality
    steps:
      - name: make check
        run: make check

  required-summary:
    name: required-summary
    needs: [quality]
    steps:
      - name: Check all jobs passed or were skipped
        run: |
          for result in "$QUALITY"; do
            if [ "$result" = "failure" ] || [ "$result" = "cancelled" ]; then
              exit 1
            fi
          done
' \
    "DENYLIST"

# 10 — R6: THE AUDITED SHAPE (L-7). `loadtest-check` ran cargo check + nextest
#      only. The crate is excluded from the workspace, so `make clippy` never
#      reached it and nothing in the repository ever linted it — which is why
#      `SeedClient::revoke` could sit with zero callers behind a documented CLI
#      flag that revoked nothing.
run_case "R6 rejects a loadtest gate that never runs clippy" 1 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}
loadtest-check:
	PROTOC=\$(PROTOC) cargo check --manifest-path loadtest/Cargo.toml
	PROTOC=\$(PROTOC) cargo nextest run --manifest-path loadtest/Cargo.toml
" "$GOOD_CI" \
    "does not run clippy"

# 11 — R6: clippy that cannot fail. Without -D warnings the dead_code finding
#      prints and the gate stays green — the same fail-open shape as R3.
run_case "R6 rejects clippy without -D warnings" 1 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}
loadtest-check:
	PROTOC=\$(PROTOC) cargo clippy --manifest-path loadtest/Cargo.toml --all-targets
	PROTOC=\$(PROTOC) cargo nextest run --manifest-path loadtest/Cargo.toml
" "$GOOD_CI" \
    "without \`-D warnings\`"

# 12 — R6: deleting the target removes the crate's only gate entirely.
run_case "R6 rejects a missing loadtest-check target" 1 \
    "${GOOD_TEST_TARGET}
${GOOD_CHECK_TARGET}
loadtest-check-renamed:
	@echo nothing
" "$GOOD_CI" \
    "no \`loadtest-check:\` target"

echo ""
if [[ $failures -gt 0 ]]; then
    echo "✗ check-red-test-gate self-test: ${failures} case(s) failed"
    exit 1
fi
echo "✓ check-red-test-gate self-test: ${case_n} cases passed"
exit 0
