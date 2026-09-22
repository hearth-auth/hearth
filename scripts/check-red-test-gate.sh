#!/usr/bin/env bash
# scripts/check-red-test-gate.sh — a red test must not be able to reach main.
#
# Production-readiness task 24.4 (audit 2026-08-28 §9 item 3):
#
#   "The tests cannot be trusted to catch regressions of the things that were
#    fixed. [...] Two regression tests for data-integrity defects were
#    committed red and stayed red. A third is red because its own harness
#    starves the request task."
#
# A red test reaches main when SOMETHING between `cargo nextest` and the one
# required context swallows its exit code. This repository has already been bitten
# by four distinct swallowing mechanisms; each rule below holds one of them shut.
# None of these rules needs a Rust build — the whole script is text over the
# Makefile and .github/workflows, and runs in about a second.
#
#   R1  `make test` runs the WHOLE workspace with no test-selection filter.
#       A `-E`, `--skip` or `--exclude` in the gate's own command is how a
#       single inconvenient test stops being a gate at all.
#
#   R2  `make check` runs every gate and exits non-zero if ANY gate failed.
#       The audited shape (§1, §2.3) was prerequisite chaining — `check: clippy
#       fmt test` — which aborted on the first failure, so a denied clippy lint
#       meant the suite never ran on that commit and the gate reported one
#       problem while hiding others. The loop form is the fix; this rule holds it.
#
#   R3  No step of ci.yml's `quality` job, and no job named in
#       `required-summary`'s `needs:`, is `continue-on-error`. Audit §4.8#7 /
#       §4.12#3: an advisory step that is continue-on-error with no re-raise
#       turned a 70-vulnerability scan into a `success` job.
#
#   R4  Every workflow `run:` block that PIPES a `cargo nextest` invocation sets
#       `set -o pipefail` first. Audit §4.8#6 / §4.12#9: `cargo nextest ... |
#       tee nextest.log` reports tee's exit status, which is 0 however red the
#       suite went. GitHub Actions runs `bash -e {0}`, which does NOT include
#       pipefail.
#
#   R6  `make loadtest-check` — the ONLY gate over the `loadtest` crate, which
#       the root Cargo.toml `exclude`s from the workspace — runs clippy with
#       `-D warnings`. Production-readiness task 26.32 / audit
#       reports/subsystem-audit-fuzz-loadtest-2026-09-21.md L-7: `make clippy`
#       is `--all-targets` over the WORKSPACE, so it never reached an excluded
#       crate, and `loadtest-check` ran only `cargo check` + `nextest`. Nothing
#       in the repository had ever linted it. The command was red at HEAD with
#       three `dead_code` errors, one of them `SeedClient::revoke` — the
#       zero-caller function behind a `--revoked-frac` CLI parameter that was
#       stamped into every report's `dataset_shape` and revoked nothing. This
#       is R1's concern ("a crate outside the default members is ungated") for
#       the lint channel rather than the test channel.
#
#   R5  `required-summary`'s results loop is an ALLOWLIST — `success` and
#       `skipped` pass, everything else fails. A denylist of `failure` and
#       `cancelled` is fail-open by construction: an empty expression result,
#       or any result GitHub adds later, reads as "fine".
#
# Usage:  bash scripts/check-red-test-gate.sh
# Env:    REPO_ROOT     tree to inspect (default: this script's repository)
#         WORKFLOW_DIR  workflow directory (default: $REPO_ROOT/.github/workflows)
#         MAKEFILE      makefile to inspect (default: $REPO_ROOT/Makefile)

set -uo pipefail

DEFAULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${REPO_ROOT:-$DEFAULT_ROOT}"
WORKFLOW_DIR="${WORKFLOW_DIR:-${REPO_ROOT}/.github/workflows}"
MAKEFILE="${MAKEFILE:-${REPO_ROOT}/Makefile}"
CI_FILE="${WORKFLOW_DIR}/ci.yml"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}
pass() { echo "ok:   $*"; }

# Prints the body of a make target (the recipe lines following `<name>:`).
make_recipe() {
    awk -v target="$1" '
        $0 ~ "^" target ":" { inside = 1; next }
        inside && /^[^\t ]/  { inside = 0 }
        inside               { print }
    ' "$MAKEFILE"
}

# Prints the lines of one top-level job block in a workflow file.
job_block() {
    awk -v job="$2" '
        $0 ~ "^  " job ":[[:space:]]*$" { inside = 1; next }
        inside && /^  [A-Za-z_-]+:[[:space:]]*$/ { inside = 0 }
        inside { print }
    ' "$1"
}

# ── R1 — the workspace gate has no test-selection filter ─────────────────────
if [[ ! -f "$MAKEFILE" ]]; then
    fail "R1: ${MAKEFILE} not found; there is no test gate to inspect."
else
    test_recipe="$(make_recipe test)"
    if [[ -z "$test_recipe" ]]; then
        fail "R1: no \`test:\` target in ${MAKEFILE}."
    elif ! grep -q -- '--workspace' <<<"$test_recipe"; then
        fail "R1: \`make test\` does not pass --workspace; a crate outside the default members is ungated."
    elif grep -qE -- '(^|[[:space:]])(-E|--filter-expr|--skip|--exclude|--ignore-default-filter)([[:space:]]|=)' <<<"$test_recipe"; then
        fail "R1: \`make test\` carries a test-selection filter. The merge gate must run every test:
      $(tr -d '\t' <<<"$test_recipe" | tr '\n' ' ')"
    else
        pass "R1: \`make test\` runs the whole workspace, unfiltered."
    fi

    # ── R2 — `make check` runs every gate and reports the worst result ───────
    check_recipe="$(make_recipe check)"
    if [[ -z "$check_recipe" ]]; then
        fail "R2: no \`check:\` target in ${MAKEFILE}."
    elif grep -qE '^check:[[:space:]]+[A-Za-z]' "$MAKEFILE"; then
        fail "R2: \`check\` uses prerequisite chaining, which aborts on the first failing gate (audit §1, §2.3). Run every gate and exit on the worst result."
    elif ! grep -q 'test-quality' <<<"$check_recipe" || ! grep -qE '(^|[^-])\btest\b' <<<"$check_recipe"; then
        fail "R2: \`make check\` does not run both the test-quality gate and the test suite."
    elif ! grep -q 'exit 1' <<<"$check_recipe"; then
        fail "R2: \`make check\` never exits non-zero; a failing gate would be reported and then ignored."
    else
        pass "R2: \`make check\` runs every gate and exits non-zero if any failed."
    fi

    # ── R6 — the out-of-workspace loadtest crate is linted by its own gate ───
    loadtest_recipe="$(make_recipe loadtest-check)"
    if [[ -z "$loadtest_recipe" ]]; then
        fail "R6: no \`loadtest-check:\` target in ${MAKEFILE}. The loadtest crate is excluded from the workspace, so this is the only gate that can reach it."
    elif ! grep -q 'cargo clippy' <<<"$loadtest_recipe"; then
        fail "R6: \`make loadtest-check\` does not run clippy. The crate is in the root Cargo.toml's \`exclude\` list, so \`make clippy --workspace\` never reaches it and NOTHING in the repository lints it (task 26.32 / audit L-7)."
    elif ! grep -qE -- '-D warnings' <<<"$loadtest_recipe"; then
        fail "R6: \`make loadtest-check\` runs clippy without \`-D warnings\`. Advisory lint output does not fail a gate; the dead_code error that named \`SeedClient::revoke\` would print and the job would still be green."
    else
        pass "R6: \`make loadtest-check\` lints the excluded loadtest crate with -D warnings."
    fi
fi

# ── R3 — nothing on the required path is continue-on-error ───────────────────
if [[ ! -f "$CI_FILE" ]]; then
    fail "R3: ${CI_FILE} not found; the required context has no home."
else
    quality_block="$(job_block "$CI_FILE" quality)"
    if [[ -z "$quality_block" ]]; then
        fail "R3: no \`quality\` job in ${CI_FILE}."
    # Anchored to a real YAML key. An unanchored grep also fires on the comment
    # in that job explaining why the audited continue-on-error step was removed
    # — and a gate that cries wolf gets switched off, which is the fail-open
    # this script exists to prevent.
    elif grep -qE '^[[:space:]]*-?[[:space:]]*continue-on-error:[[:space:]]*(true|\$\{\{)' <<<"$quality_block"; then
        fail "R3: the \`quality\` job contains \`continue-on-error\`. A step that cannot fail the job cannot fail the merge (audit §4.8#7, §4.12#3)."
    else
        pass "R3a: no step of the \`quality\` job is continue-on-error."
    fi

    # Jobs named in required-summary's `needs:` must not be continue-on-error
    # at job level either.
    needs_line="$(
        awk '/^  required-summary:/ { inside = 1 }
             inside && /needs:/ { print; exit }' "$CI_FILE"
    )"
    if [[ -z "$needs_line" ]]; then
        fail "R3: required-summary declares no \`needs:\`."
    else
        needed="$(sed 's/.*needs:[[:space:]]*\[//; s/\].*//; s/,/ /g' <<<"$needs_line")"
        soft=""
        for job in $needed; do
            block="$(job_block "$CI_FILE" "$job")"
            [[ -n "$block" ]] || continue   # reusable-workflow calls have no steps here
            if grep -qE '^    continue-on-error:[[:space:]]*true' <<<"$block"; then
                soft="${soft} ${job}"
            fi
        done
        if [[ -n "$soft" ]]; then
            fail "R3: job(s) in required-summary's needs are continue-on-error:${soft}"
        else
            pass "R3b: no job on the required path is continue-on-error."
        fi
    fi

    # ── R5 — the results loop is an allowlist ────────────────────────────────
    summary_block="$(
        awk '/^  required-summary:/ { inside = 1 } inside { print }' "$CI_FILE"
    )"
    if grep -qE '\$result"?[[:space:]]*=[[:space:]]*"?(failure|cancelled)' <<<"$summary_block"; then
        fail "R5: required-summary's results loop is a DENYLIST of failure/cancelled. Any other result — including an empty string — passes. Use an allowlist of success|skipped."
    elif grep -qE 'success\|skipped|success\)[[:space:]]*;;' <<<"$summary_block"; then
        pass "R5: required-summary passes only \`success\` and \`skipped\`."
    else
        fail "R5: required-summary's results loop does not allowlist success|skipped; a job result other than success may pass the gate."
    fi
fi

# ── R4 — a piped nextest invocation must set pipefail ────────────────────────
if [[ ! -d "$WORKFLOW_DIR" ]]; then
    fail "R4: ${WORKFLOW_DIR} not found."
else
    piped_unguarded=""
    while IFS= read -r wf; do
        # For each line that pipes a nextest run, look back up to 25 lines for
        # `set -o pipefail` (or `set -eo pipefail` etc.) in the same run block.
        hits="$(
            awk -v file="$wf" '
                { history[NR] = $0 }
                /cargo nextest/ && /\|/ && !/\|\|/ {
                    guarded = 0
                    for (i = NR; i > NR - 25 && i > 0; i--) {
                        if (history[i] ~ /set[[:space:]]+-[a-zA-Z]*o?[a-zA-Z]*[[:space:]]+pipefail/ ||
                            history[i] ~ /set[[:space:]]+-o[[:space:]]+pipefail/ ||
                            history[i] ~ /pipefail/) { guarded = 1; break }
                        if (history[i] ~ /^[[:space:]]*-[[:space:]]*name:/) break
                    }
                    if (!guarded) print file ":" NR ": " $0
                }
            ' "$wf"
        )"
        [[ -n "$hits" ]] && piped_unguarded="${piped_unguarded}${hits}"$'\n'
    done < <(find "$WORKFLOW_DIR" -maxdepth 1 -name '*.yml' -o -maxdepth 1 -name '*.yaml' | sort)

    if [[ -n "${piped_unguarded//[$'\n' ]/}" ]]; then
        fail "R4: a piped \`cargo nextest\` runs without pipefail — the pipe's exit status, not the suite's, reaches the job (audit §4.8#6, §4.12#9):"
        printf '%s' "$piped_unguarded" | sed '/^$/d; s/^/      /'
    else
        pass "R4: every piped \`cargo nextest\` invocation sets pipefail."
    fi
fi

echo ""
if [[ $failures -gt 0 ]]; then
    echo "✗ red-test gate: ${failures} rule(s) failed — a red test could reach main."
    exit 1
fi
echo "✓ red-test gate: a red test cannot reach main through any of the six audited paths."
exit 0
