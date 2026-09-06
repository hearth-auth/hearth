#!/usr/bin/env bash
# scripts/check-advisory-gates.sh — dependency-advisory gates must be armed.
#
# Audit 2026-08-28 findings §4.8#7 and §4.12#3 (HIGH):
#
#   Both dependency-advisory gates were `continue-on-error` with no re-raise;
#   the observed result was a `success` job on a 70-vulnerability scan, one of
#   them the unpatched HTTP/2 DoS advisory that v1.6.11 ships. The cargo-deny
#   job was skipped on every PR that did not touch the lockfile, so a week-old
#   advisory failure never blocked a merge.
#
# Spec (build-release-integrity): advisory gates SHALL be able to fail a run;
# `continue-on-error` MUST NOT be used without a re-raise; `cargo deny check`
# and `cargo audit` are required contexts that run on every PR.
#
# Three rules:
#
#   R1  ci.yml carries a `cargo-deny` job that runs BOTH `cargo deny check`
#       and `cargo audit`, is not scoped by any paths filter (`if:` must not
#       reference `filter.outputs`), and contains no `continue-on-error`.
#   R2  ci.yml's `required-summary` job lists `cargo-deny` in its `needs:`,
#       so an advisory failure fails the one required context.
#   R3  In every workflow, no step that invokes an advisory scanner
#       (`cargo deny`, `cargo audit`, `osv-scanner`) is `continue-on-error`,
#       and no job containing one is job-level `continue-on-error`.
#
# Usage:  bash scripts/check-advisory-gates.sh
# Env:    WORKFLOW_DIR   directory to scan (default .github/workflows)

set -uo pipefail

WORKFLOW_DIR="${WORKFLOW_DIR:-.github/workflows}"

ADVISORY_MARKERS='cargo deny|cargo-deny|cargo audit|cargo-audit|osv-scanner'

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

# split_jobs <workflow-file> <outdir> — write one <outdir>/<job>.block per job.
# Same parser as check-publish-gating.sh: a job header is a two-space-indented
# bare key under `jobs:`.
split_jobs() {
    awk -v outdir="$2" '
        /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
        !in_jobs { next }
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            name = $1
            sub(/:$/, "", name)
            out = outdir "/" name ".block"
            print name >> (outdir "/.jobs")
            next
        }
        out { print >> out }
    ' "$1"
}

# check_steps <block-file> <label> — R3 step scan: an advisory step must not
# be continue-on-error. A step starts at a dash followed by a step key.
check_steps() {
    local block="$1" label="$2"
    awk -v markers="$ADVISORY_MARKERS" -v label="$label" '
        function flush() {
            if (step != "" && step ~ markers && step ~ /continue-on-error:[[:space:]]*true/) {
                print label ": advisory step is continue-on-error — " first_line
                bad = 1
            }
            step = ""; first_line = ""
        }
        /^[[:space:]]*-[[:space:]]+(name|uses|run|id|if|env|with|continue-on-error):/ {
            flush()
            first_line = $0
            sub(/^[[:space:]]*/, "", first_line)
        }
        { if (first_line != "") step = step "\n" $0 }
        END { flush(); exit bad }
    ' "$block"
}

if [[ ! -d "$WORKFLOW_DIR" ]]; then
    echo "FAIL: workflow directory not found: ${WORKFLOW_DIR}"
    exit 1
fi

# ── R1 + R2: the ci.yml gate shape. ──────────────────────────────────────────
CI_FILE="${WORKFLOW_DIR}/ci.yml"
if [[ ! -f "$CI_FILE" ]]; then
    fail "ci.yml not found in ${WORKFLOW_DIR}; the advisory gate has no home."
else
    tmp="$(mktemp -d)"
    split_jobs "$CI_FILE" "$tmp"
    deny_block="$tmp/cargo-deny.block"
    if [[ ! -f "$deny_block" ]]; then
        fail "ci.yml: no 'cargo-deny' job. Advisories cannot fail any PR (§4.8#7)."
    else
        grep -qE 'cargo deny check' "$deny_block" \
            || fail "ci.yml: the cargo-deny job does not run 'cargo deny check'."
        grep -qE 'cargo audit' "$deny_block" \
            || fail "ci.yml: the cargo-deny job does not run 'cargo audit' (§4.12#3)."
        if grep -qE '^[[:space:]]*if:.*filter\.outputs' "$deny_block"; then
            fail "ci.yml: the cargo-deny job is scoped by a paths filter." \
                $'\n      A PR that does not touch the lockfile must still meet the gate:' \
                $'\n      the advisory database moves while the tree stands still (§4.8#7).'
        fi
        if grep -qE 'continue-on-error:[[:space:]]*true' "$deny_block"; then
            fail "ci.yml: the cargo-deny job carries continue-on-error (§4.12#3)."
        fi
    fi
    summary_block="$tmp/required-summary.block"
    if [[ ! -f "$summary_block" ]]; then
        fail "ci.yml: no 'required-summary' job — nothing aggregates the gates."
    elif ! grep -qE '^[[:space:]]*needs:.*cargo-deny|^[[:space:]]*-[[:space:]]*cargo-deny[[:space:]]*$' "$summary_block"; then
        fail "ci.yml: required-summary does not need cargo-deny, so an advisory" \
            $'\n      failure cannot block a merge (§4.8#7).'
    fi
    rm -rf "$tmp"
fi

# ── R3: no disarmed advisory step anywhere. ──────────────────────────────────
for wf in "${WORKFLOW_DIR}"/*.yml "${WORKFLOW_DIR}"/*.yaml; do
    [[ -f "$wf" ]] || continue
    base="$(basename "$wf")"
    tmp="$(mktemp -d)"
    split_jobs "$wf" "$tmp"
    [[ -f "$tmp/.jobs" ]] || { rm -rf "$tmp"; continue; }
    while IFS= read -r job; do
        [[ -n "$job" && -f "$tmp/$job.block" ]] || continue
        block="$tmp/$job.block"
        if grep -qE "$ADVISORY_MARKERS" "$block"; then
            # Job-level continue-on-error swallows every step in the job.
            if grep -qE '^    continue-on-error:[[:space:]]*true' "$block"; then
                fail "${base}: job '${job}' runs an advisory scanner under a" \
                    $'\n      job-level continue-on-error (§4.12#3).'
            fi
            out="$(check_steps "$block" "${base}: job '${job}'")" || fail "$out"
        fi
    done < "$tmp/.jobs"
    rm -rf "$tmp"
done

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} advisory-gate violation(s)."
    echo "See scripts/check-advisory-gates.sh for the rules and the audit citation."
    exit 1
fi
echo "OK: every dependency-advisory gate runs on every PR and can fail it."
exit 0
