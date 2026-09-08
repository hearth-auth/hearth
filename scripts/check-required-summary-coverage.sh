#!/usr/bin/env bash
# scripts/check-required-summary-coverage.sh — a verification job that cannot
# fail the required check is not a gate.
#
# Audit 2026-08-28 finding §4.12#12 (MEDIUM):
#
#   `required-summary` in ci.yml is the ONLY required context on main
#   (scripts/check-branch-protection.sh asserts exactly that). A job blocks a
#   merge if and only if it reaches that job. Two ways things did not:
#
#     1. Three of ci.yml's own SDK jobs — sdk-kotlin, sdk-go, sdk-typescript —
#        were absent from `required-summary`'s `needs:`. They ran, went red, and
#        merged.
#     2. Five other workflows ran on their own `pull_request:` trigger. GitHub
#        cannot express `needs:` across workflows, so nothing they did could
#        fail the one required context. They are now reusable workflows called
#        from ci.yml.
#
#   There is a third way, which the fix itself could reintroduce: a job added to
#   `needs:` but not to the shell loop that reads the results. `needs:` only
#   makes required-summary WAIT; the loop is what makes it FAIL.
#
# Four rules:
#
#   R1  Every job in ci.yml is in `required-summary`'s `needs:`, except
#       `filter` (it is in `needs:` too, but is the fail-closed router),
#       `required-summary` itself, and the jobs named in ADVISORY_JOBS below —
#       each of which must carry a comment saying why.
#   R2  Every job in that `needs:` list appears in the results loop. A job in
#       `needs:` but not the loop is waited on and then ignored.
#   R3  Each folded workflow (FOLDED_WORKFLOWS) declares `workflow_call:` and
#       does NOT declare its own `pull_request:` trigger. A pull_request trigger
#       there is a run that cannot fail the required check.
#   R4  ci.yml calls each folded workflow with `uses: ./.github/workflows/<f>`.
#
# Usage:  bash scripts/check-required-summary-coverage.sh
# Env:    WORKFLOW_DIR  directory to scan (default .github/workflows)

set -uo pipefail

WORKFLOW_DIR="${WORKFLOW_DIR:-.github/workflows}"
CI_FILE="${WORKFLOW_DIR}/ci.yml"

# Jobs deliberately outside the required check. Each needs a reason in ci.yml.
#   pr-head-ancestor-guard — HEA-2106 holds the switch until the false-positive
#     rate against stacked PRs is measured clean; the job is continue-on-error.
ADVISORY_JOBS="pr-head-ancestor-guard"

# Workflows whose pull_request entry point moved into ci.yml (§4.12#12).
FOLDED_WORKFLOWS="commit-lint.yml proto.yml sdk-smoke.yml security.yml pr-head-ancestor-guard.yml"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

if [[ ! -f "$CI_FILE" ]]; then
    echo "FAIL: ${CI_FILE} not found; the required check has no home."
    exit 1
fi

# Every top-level job id in ci.yml.
mapfile -t CI_JOBS < <(awk '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    !in_jobs { next }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { n = $1; sub(/:$/, "", n); print n }
' "$CI_FILE")

if [[ "${#CI_JOBS[@]}" -eq 0 ]]; then
    fail "${CI_FILE}: no jobs parsed. The guard cannot check anything."
fi

# The required-summary block, and the `needs:` list inside it.
summary_block="$(awk '
    /^  required-summary:[[:space:]]*$/ { in_b = 1; print; next }
    in_b && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { in_b = 0 }
    in_b { print }
' "$CI_FILE")"

if [[ -z "$summary_block" ]]; then
    fail "${CI_FILE}: no 'required-summary' job. Nothing aggregates the gates."
    echo ""
    echo "1 required-summary coverage violation(s)."
    exit 1
fi

needs_line="$(grep -m1 '^[[:space:]]*needs:[[:space:]]*\[' <<<"$summary_block")"
if [[ -z "$needs_line" ]]; then
    fail "${CI_FILE}: required-summary has no inline 'needs: [...]' list."
    NEEDS=""
else
    NEEDS="$(sed -E 's/.*\[//; s/\].*//; s/,/ /g' <<<"$needs_line")"
fi

# The loop that actually reads the results.
loop_line="$(grep -m1 'for result in ' <<<"$summary_block")"
[[ -n "$loop_line" ]] || fail "${CI_FILE}: required-summary has no results loop."

# ── R1: every job reaches the required check. ────────────────────────────────
for job in "${CI_JOBS[@]}"; do
    [[ "$job" == "required-summary" ]] && continue
    if [[ " ${ADVISORY_JOBS} " == *" ${job} "* ]]; then
        # An advisory job must say so where a reader will see it.
        if ! grep -qiE "ADVISORY|advisory" <<<"$(awk -v j="  ${job}:" '
            index($0, j) == 1 { found = NR }
            found && NR >= found - 8 && NR <= found + 3
        ' "$CI_FILE")" && ! grep -qi "advisory" "$CI_FILE"; then
            fail "${CI_FILE}: '${job}' is on the advisory list but nothing in the" \
                $'\n      file says why. An unexplained exemption is how a gate gets lost.'
        fi
        continue
    fi
    if [[ " ${NEEDS} " != *" ${job} "* ]]; then
        fail "${CI_FILE}: job '${job}' is not in required-summary's needs:." \
            $'\n      It runs, it can go red, and the merge is not blocked (§4.12#12).'
    fi
done

# ── R2: everything waited on is also read. ───────────────────────────────────
for job in $NEEDS; do
    [[ "$job" == "filter" ]] && continue
    var="$(tr '[:lower:]-' '[:upper:]_' <<<"$job")"
    if [[ "$loop_line" != *"\$${var}"* ]]; then
        fail "${CI_FILE}: '${job}' is in required-summary's needs: but its result" \
            $'\n      is not read by the loop. needs: only makes the job WAIT; the loop is' \
            $'\n      what makes it FAIL (§4.12#12).'
    fi
done

# ── R3 + R4: the folded workflows stay folded. ───────────────────────────────
for wf in $FOLDED_WORKFLOWS; do
    path="${WORKFLOW_DIR}/${wf}"
    if [[ ! -f "$path" ]]; then
        fail "${path} not found; it was folded into ci.yml and must still exist."
        continue
    fi
    trigger_block="$(awk '
        /^on:[[:space:]]*$/ { in_on = 1; next }
        in_on && /^[A-Za-z]/ { in_on = 0 }
        in_on { print }
    ' "$path")"
    grep -qE '^  workflow_call:' <<<"$trigger_block" \
        || fail "${path}: no 'workflow_call:' trigger, so ci.yml cannot call it (§4.12#12)."
    if grep -qE '^  pull_request:' <<<"$trigger_block"; then
        fail "${path}: declares its own 'pull_request:' trigger." \
            $'\n      That run reports a check no ruleset requires, so it cannot fail a' \
            $'\n      merge. The PR entry point is ci.yml (§4.12#12).'
    fi
    # GitHub requires the literal ./.github/workflows/ path in a `uses:`, so
    # this is not built from WORKFLOW_DIR (which the self-test overrides).
    grep -qF "uses: ./.github/workflows/${wf}" "$CI_FILE" \
        || fail "${CI_FILE}: nothing calls ${wf}. It now runs on no pull request at all."
done

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} required-summary coverage violation(s)."
    echo "See scripts/check-required-summary-coverage.sh for the rules and the audit citation."
    exit 1
fi
echo "OK: every verification job reaches the one required check."
exit 0
