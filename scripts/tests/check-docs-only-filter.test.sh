#!/usr/bin/env bash
# scripts/tests/check-docs-only-filter.test.sh — tests for
# scripts/check-docs-only-filter.sh (GA audit 2026-09-28, M19).
#
# The guard is the deliverable, so it must be shown to FAIL on the pre-fix
# workflow (docs-only as an any-match filter) and on each partial regression,
# not merely pass on today's ci.yml.
#
# Usage: bash scripts/tests/check-docs-only-filter.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-docs-only-filter.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# run_case <name> <expected-exit> <workflow> [expected-substring]
run_case() {
    local name="$1" want="$2" wf="$3" expect="${4:-}" out rc
    out="$(CI_WORKFLOW="$wf" bash "$CHECK" 2>&1)"
    rc=$?
    if [[ "$rc" != "$want" ]]; then
        fail "${name}: exit ${rc}, want ${want}"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    if [[ -n "$expect" ]] && ! printf '%s\n' "$out" | grep -qF -- "$expect"; then
        fail "${name}: output does not mention '${expect}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    pass "$name"
}

# make_workflow <path> <docs-only output line> <docs step quantifier line>
#               <non-docs patterns> [extra filter in the main step]
make_workflow() {
    local path="$1" output="$2" quant="$3" patterns="$4" extra="${5:-}"
    {
        cat <<'EOF'
jobs:
  filter:
    name: filter (paths-filter)
    outputs:
      rust: ${{ steps.filter.outputs.rust }}
EOF
        printf '%s\n' "$output"
        cat <<'EOF'
    steps:
      - name: Compute changed paths
        id: filter
        with:
          filters: |
            rust:
              - 'src/**'
EOF
        [[ -n "$extra" ]] && printf '%s\n' "$extra"
        cat <<'EOF'

      - name: Compute non-documentation changes
        id: docs
        with:
EOF
        [[ -n "$quant" ]] && printf '%s\n' "$quant"
        cat <<'EOF'
          filters: |
            non-docs:
EOF
        printf '%s\n' "$patterns"
        cat <<'EOF'

      - name: Summarize filter results
        run: echo done

  security:
    if: needs.filter.outputs.docs-only != 'true'
EOF
    } > "$path"
}

GOOD_OUTPUT="      docs-only: \${{ steps.docs.outputs.non-docs == 'false' && 'true' || 'false' }}"
GOOD_QUANT="          predicate-quantifier: 'every'"
GOOD_PATTERNS="              - '**'
              - '!docs/**'
              - '!**/*.md'"

echo "check-docs-only-filter.sh"

# Today's real workflow must pass.
run_case "repository ci.yml passes" 0 "${REPO_ROOT}/.github/workflows/ci.yml"

make_workflow "${TMP}/good.yml" "$GOOD_OUTPUT" "$GOOD_QUANT" "$GOOD_PATTERNS"
run_case "fixed shape passes" 0 "${TMP}/good.yml"

# The pre-fix defect: docs-only as an any-match filter in the main step.
make_workflow "${TMP}/prefix.yml" \
    "      docs-only: \${{ steps.filter.outputs.docs-only }}" "" "              - '**'" \
    "            docs-only:
              - 'docs/**'
              - '**.md'"
run_case "pre-fix any-match docs-only filter fails" 1 "${TMP}/prefix.yml" \
    "a 'docs-only:' paths-filter filter is back"

make_workflow "${TMP}/noquant.yml" "$GOOD_OUTPUT" "" "$GOOD_PATTERNS"
run_case "missing predicate-quantifier fails" 1 "${TMP}/noquant.yml" \
    "predicate-quantifier: 'every'"

make_workflow "${TMP}/some.yml" "$GOOD_OUTPUT" "          predicate-quantifier: 'some'" \
    "$GOOD_PATTERNS"
run_case "predicate-quantifier some fails" 1 "${TMP}/some.yml" \
    "predicate-quantifier: 'every'"

make_workflow "${TMP}/nomd.yml" "$GOOD_OUTPUT" "$GOOD_QUANT" "              - '**'
              - '!docs/**'"
run_case "dropped !**/*.md pattern fails" 1 "${TMP}/nomd.yml" "'!**/*.md'"

make_workflow "${TMP}/noinclude.yml" "$GOOD_OUTPUT" "$GOOD_QUANT" "              - '!docs/**'
              - '!**/*.md'"
run_case "dropped '**' include fails" 1 "${TMP}/noinclude.yml" "'**'"

# Fail-open output form: an empty non-docs output would read as docs-only.
make_workflow "${TMP}/failopen.yml" \
    "      docs-only: \${{ steps.docs.outputs.non-docs != 'true' && 'true' || 'false' }}" \
    "$GOOD_QUANT" "$GOOD_PATTERNS"
run_case "fail-open negation fails" 1 "${TMP}/failopen.yml" "non-docs == 'false'"

make_workflow "${TMP}/nooutput.yml" "      rust: \${{ steps.filter.outputs.rust }}" \
    "$GOOD_QUANT" "$GOOD_PATTERNS"
run_case "missing docs-only output fails" 1 "${TMP}/nooutput.yml" "exports no 'docs-only' output"

if (( failures > 0 )); then
    echo "${failures} case(s) failed."
    exit 1
fi
echo "All cases passed."
