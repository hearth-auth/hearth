#!/usr/bin/env bash
# scripts/tests/check-required-summary-coverage.test.sh — tests for
# scripts/check-required-summary-coverage.sh (audit 2026-08-28 §4.12#12).
#
# The guard is the deliverable, so it must be shown to FAIL on each audited
# shape, not merely to pass on the remediated tree:
#
#   case 2  a ci.yml job absent from required-summary's needs   (the SDK defect)
#   case 3  a job in needs: but not in the results loop         (the fail-open)
#   case 4  a folded workflow that regains a pull_request trigger
#   case 5  a folded workflow with no workflow_call trigger
#   case 6  ci.yml no longer calling a folded workflow
#
# Usage: bash scripts/tests/check-required-summary-coverage.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-required-summary-coverage.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

FOLDED="commit-lint proto sdk-smoke security pr-head-ancestor-guard"

# write_folded <dir> [extra-trigger]
# Writes every folded workflow in its correct (reusable) shape.
write_folded() {
    local dir="$1"
    for f in $FOLDED; do
        cat > "${dir}/${f}.yml" <<'EOF'
on:
  workflow_call:

jobs:
  work:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
EOF
    done
}

# write_ci <dir> <needs-list> <loop-vars> [omit-call]
write_ci() {
    local dir="$1" needs="$2" loop="$3" omit="${4:-}"
    {
        cat <<EOF
on:
  pull_request:
    branches: [main]

jobs:
  filter:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok

  quality:
    runs-on: ubuntu-latest
    steps:
      - run: make check

  sdk-kotlin:
    runs-on: ubuntu-latest
    steps:
      - run: echo kotlin

EOF
        for f in $FOLDED; do
            [[ "$f" == "$omit" ]] && continue
            local jobname="$f"
            [[ "$f" == "pr-head-ancestor-guard" ]] && echo "  # ADVISORY — HEA-2106 holds the switch."
            cat <<EOF
  ${jobname}:
    uses: ./.github/workflows/${f}.yml

EOF
        done
        cat <<EOF
  required-summary:
    if: always()
    needs: [${needs}]
    runs-on: ubuntu-latest
    steps:
      - name: Check all jobs passed or were skipped
        env:
          QUALITY: \${{ needs.quality.result }}
        run: |
          for result in ${loop}; do
            if [ "\$result" = "failure" ]; then exit 1; fi
          done
EOF
    } > "${dir}/ci.yml"
}

# run_case <name> <expected-exit> <needs> <loop> [omit-call] [pr-trigger-on] [no-call-on] [expect]
run_case() {
    local name="$1" want="$2" needs="$3" loop="$4"
    local omit="${5:-}" pr_on="${6:-}" nocall_on="${7:-}" expect="${8:-}"
    case_n=$((case_n + 1))
    local dir="$TMP/case-${case_n}/.github/workflows"
    mkdir -p "$dir"
    write_folded "$dir"
    write_ci "$dir" "$needs" "$loop" "$omit"

    if [[ -n "$pr_on" ]]; then
        cat > "${dir}/${pr_on}.yml" <<'EOF'
on:
  workflow_call:
  pull_request:
    branches: [main]

jobs:
  work:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
EOF
    fi
    if [[ -n "$nocall_on" ]]; then
        cat > "${dir}/${nocall_on}.yml" <<'EOF'
on:
  push:
    branches: [main]

jobs:
  work:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
EOF
    fi

    local out got=0
    out="$(WORKFLOW_DIR="$dir" bash "$CHECK" 2>&1)" || got=$?
    if [[ "$got" -ne "$want" ]]; then
        echo "FAIL: ${name} — expected exit ${want}, got ${got}"
        echo "$out" | sed 's/^/    /'
        failures=$((failures + 1))
        return
    fi
    if [[ -n "$expect" && "$out" != *"$expect"* ]]; then
        echo "FAIL: ${name} — output missing expected text: ${expect}"
        echo "$out" | sed 's/^/    /'
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${name}"
}

FULL_NEEDS="filter, quality, sdk-kotlin, commit-lint, proto, sdk-smoke, security"
FULL_LOOP='"$QUALITY" "$SDK_KOTLIN" "$COMMIT_LINT" "$PROTO" "$SDK_SMOKE" "$SECURITY"'

# 1 — the remediated shape passes.
run_case "every job reaches the required check" 0 "$FULL_NEEDS" "$FULL_LOOP" "" "" "" \
    "OK: every verification job reaches the one required check"

# 2 — THE REGRESSION (§4.12#12, first half): a ci.yml job outside needs:.
#     This is sdk-kotlin / sdk-go / sdk-typescript, byte for byte.
run_case "a ci.yml job absent from needs: is rejected" 1 \
    "filter, quality, commit-lint, proto, sdk-smoke, security" \
    '"$QUALITY" "$COMMIT_LINT" "$PROTO" "$SDK_SMOKE" "$SECURITY"' "" "" "" \
    "job 'sdk-kotlin' is not in required-summary's needs:"

# 3 — THE FAIL-OPEN the fix itself could introduce: waited on, never read.
run_case "a job in needs: but not in the loop is rejected" 1 \
    "$FULL_NEEDS" '"$QUALITY" "$COMMIT_LINT" "$PROTO" "$SDK_SMOKE" "$SECURITY"' "" "" "" \
    "is not read by the loop"

# 4 — THE REGRESSION (§4.12#12, second half): a folded workflow that gets its
#     own pull_request trigger back reports a check nothing requires.
run_case "a folded workflow regaining pull_request is rejected" 1 \
    "$FULL_NEEDS" "$FULL_LOOP" "" "security" "" \
    "declares its own 'pull_request:' trigger"

# 5 — without workflow_call, ci.yml cannot call it at all.
run_case "a folded workflow with no workflow_call is rejected" 1 \
    "$FULL_NEEDS" "$FULL_LOOP" "" "" "proto" \
    "no 'workflow_call:' trigger"

# 6 — dropping the call leaves the workflow running on no pull request at all.
run_case "ci.yml not calling a folded workflow is rejected" 1 \
    "filter, quality, sdk-kotlin, commit-lint, proto, security" \
    '"$QUALITY" "$SDK_KOTLIN" "$COMMIT_LINT" "$PROTO" "$SECURITY"' "sdk-smoke" "" "" \
    "nothing calls sdk-smoke.yml"

# 7 — the checked-in ci.yml passes.
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    echo "ok: the repository's own ci.yml passes"
else
    echo "FAIL: the checked-in ci.yml does not pass"
    echo "$out" | sed 's/^/    /'
    failures=$((failures + 1))
fi

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} guard self-test failure(s)."
    exit 1
fi
echo "OK: guard self-tests passed."
exit 0
