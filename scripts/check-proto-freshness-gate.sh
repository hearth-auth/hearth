#!/usr/bin/env bash
# scripts/check-proto-freshness-gate.sh — the generated-SDK freshness check must
# be reachable from every path that can cause drift.
#
# Audit 2026-08-28 finding §4.8#8 (MEDIUM):
#
#   Generated SDK types can drift from `proto/` past the PR gate; the freshness
#   check runs only where the paths filter does not reach.
#
# `make proto-check` regenerates the TypeScript and Go types and fails if the
# committed output differs. It used to be the last step of ci.yml's `quality`
# job, which left two holes:
#
#   1. `quality` is gated on the `rust` filter. That filter names codegen's
#      INPUTS (`proto/**`) but never its OUTPUTS, so a PR that touched only
#      sdks/typescript/src/generated or sdks/go/generated — a hand-edit, a bad
#      merge resolution, a revert — ran no freshness check at all.
#   2. The step ran after `make check`. A clippy or test failure ended the job
#      first, so the freshness verdict was never produced.
#
# The check now lives in its own `proto-freshness` job, gated on the `proto`
# filter. This guard keeps that arrangement honest: it fails if the filter stops
# naming a codegen input or output, if the job stops gating on that filter, or
# if the job stops running `make proto-check`.
#
# Usage:  bash scripts/check-proto-freshness-gate.sh
# Env:    CI_WORKFLOW  (default .github/workflows/ci.yml)
#         MAKEFILE     (default Makefile)

set -uo pipefail

CI_WORKFLOW="${CI_WORKFLOW:-.github/workflows/ci.yml}"
MAKEFILE="${MAKEFILE:-Makefile}"

JOB="proto-freshness"

for f in "$CI_WORKFLOW" "$MAKEFILE"; do
    [[ -f "$f" ]] || { echo "FAIL: ${f} not found."; exit 1; }
done

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# ── 1. The `proto` filter must name every codegen input and output ───────────
#
# Outputs are read from the Makefile's proto-check recipe rather than hardcoded,
# so adding a third generated language cannot quietly escape the gate.
filter_block="$(awk '
    /^            proto:$/     { inblock = 1; next }
    inblock && /^            [a-z][a-z0-9-]*:$/ { inblock = 0 }
    inblock                    { print }
' "$CI_WORKFLOW")"

if [[ -z "$filter_block" ]]; then
    fail "no 'proto:' filter in ${CI_WORKFLOW}; the ${JOB} job has nothing to gate on."
fi

# The directories `make proto-check` diffs, taken from the recipe itself.
generated_dirs="$(awk '
    /^proto-check:/        { inrecipe = 1; next }
    inrecipe && /^[^\t]/   { inrecipe = 0 }
    inrecipe && /git diff/ { print }
' "$MAKEFILE" | grep -oE '[A-Za-z0-9_./-]*generated[A-Za-z0-9_./-]*' | sort -u)"

if [[ -z "$generated_dirs" ]]; then
    fail "could not read the generated directories from ${MAKEFILE}'s proto-check recipe."
fi

# Inputs: everything buf reads lives under proto/ (buf.yaml, buf.gen.yaml,
# buf.lock and the .proto sources themselves).
required_patterns=("proto/**")
while IFS= read -r dir; do
    [[ -n "$dir" ]] && required_patterns+=("${dir}/**")
done <<< "$generated_dirs"

for pattern in "${required_patterns[@]}"; do
    if ! printf '%s\n' "$filter_block" | grep -qF "'${pattern}'"; then
        fail "the 'proto:' filter in ${CI_WORKFLOW} does not name '${pattern}'. A PR that changes only that path would skip the freshness check."
    fi
done

# ── 2. The job must exist and gate on that filter ────────────────────────────
# Comment lines are dropped: the block runs up to the next job header, which
# means it also swallows that job's leading comment banner, and a banner that
# mentions `continue-on-error` must not be read as configuration.
job_block="$(awk -v job="  ${JOB}:" '
    $0 == job              { inblock = 1; next }
    inblock && /^  [a-z][a-z0-9-]*:$/ { inblock = 0 }
    inblock                { print }
' "$CI_WORKFLOW" | grep -vE '^[[:space:]]*(#|$)')"

if [[ -z "$job_block" ]]; then
    fail "no '${JOB}' job in ${CI_WORKFLOW}."
else
    if ! printf '%s\n' "$job_block" | grep -q "needs.filter.outputs.proto == 'true'"; then
        fail "the '${JOB}' job does not gate on the 'proto' filter output."
    fi
    # HEA-685: a filter-job failure must fail this job, not skip it — branch
    # protection treats `skipped` as passing.
    if ! printf '%s\n' "$job_block" | grep -q "needs.filter.result == 'success'"; then
        fail "the '${JOB}' job's 'if:' does not require the filter job to have succeeded; a filter failure would skip it, which branch protection reads as a pass."
    fi
    if ! printf '%s\n' "$job_block" | grep -q 'make proto-check'; then
        fail "the '${JOB}' job does not run 'make proto-check'."
    fi
    if printf '%s\n' "$job_block" | grep -q 'continue-on-error'; then
        fail "the '${JOB}' job has a continue-on-error step; a disarmed freshness gate reports success on drift."
    fi
fi

# ── 3. The job must be able to fail the required check ───────────────────────
summary_block="$(awk '
    /^  required-summary:$/ { inblock = 1; next }
    inblock && /^  [a-z][a-z0-9-]*:$/ { inblock = 0 }
    inblock                 { print }
' "$CI_WORKFLOW" | grep -vE '^[[:space:]]*(#|$)')"

if [[ -z "$summary_block" ]]; then
    fail "no 'required-summary' job in ${CI_WORKFLOW}."
else
    if ! printf '%s\n' "$summary_block" | grep -q "needs:.*${JOB}"; then
        fail "'required-summary' does not need '${JOB}', so a drift failure cannot block a merge."
    fi
    if ! printf '%s\n' "$summary_block" | grep -q 'PROTO_FRESHNESS'; then
        fail "'required-summary' does not read the '${JOB}' result, so a drift failure cannot block a merge."
    fi
fi

if [[ "$failures" -gt 0 ]]; then
    echo
    echo "${failures} problem(s) with the generated-SDK freshness gate (audit §4.8#8)."
    exit 1
fi

echo "OK: the generated-SDK freshness check is reachable from every codegen input and output."
