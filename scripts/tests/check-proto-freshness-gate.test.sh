#!/usr/bin/env bash
# scripts/tests/check-proto-freshness-gate.test.sh — tests for
# scripts/check-proto-freshness-gate.sh (audit 2026-08-28 §4.8#8).
#
# The guard is the deliverable, so it needs a test that proves it FAILS on the
# pre-fix arrangement — not just that it passes on the fixed one, which an
# `exit 0` stub would also satisfy.
#
# The defect: the only generated-SDK freshness check was the last step of the
# `quality` job, gated on the `rust` filter. That filter names codegen's inputs
# (`proto/**`) but not its outputs, so a PR that touched only
# sdks/typescript/src/generated or sdks/go/generated ran no freshness check at
# all — generated types could drift from proto/ straight past the PR gate.
#
# Usage: bash scripts/tests/check-proto-freshness-gate.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-proto-freshness-gate.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# The real Makefile recipe every fixture shares: the guard reads the generated
# directories from it rather than hardcoding them.
make_makefile() {
    cat > "$1" <<'EOF'
proto-check:
	@echo "Checking generated code is up-to-date..."
	cd proto && buf generate
	@if git diff --quiet sdks/typescript/src/generated sdks/go/generated; then \
		echo "Generated code is up-to-date."; \
	else \
		exit 1; \
	fi
EOF
}

# make_workflow <path> <proto-filter-body> <job-body>
# Assembles a ci.yml-shaped fixture: a `proto:` filter, one job under test, a
# following job (so the block boundary is exercised), and required-summary.
make_workflow() {
    local path="$1" filter_body="$2" job_body="$3"
    {
        cat <<'EOF'
jobs:
  filter:
    name: filter (paths-filter)
    steps:
      - name: Compute changed paths
        id: filter
        with:
          filters: |
            rust:
              - 'src/**'
              - 'proto/**'
EOF
        printf '            proto:\n'
        printf '%s\n' "$filter_body"
        cat <<'EOF'
            docs-only:
              - 'docs/**'

  quality:
    name: quality (clippy + fmt + nextest)
    steps:
      - name: make check
        run: make check
EOF
        printf '%s\n' "$job_body"
        cat <<'EOF'

  # ── UI tests ────────────────────────────────────────────────────────────
  # Only the exploratory step is non-blocking (continue-on-error: true).
  ui:
    name: ui
    steps:
      - name: ui
        run: make ui-test

  required-summary:
    name: required-summary
    needs: [filter, quality, proto-freshness, ui]
    steps:
      - name: Check all jobs passed or were skipped
        env:
          QUALITY: ${{ needs.quality.result }}
          PROTO_FRESHNESS: ${{ needs.proto-freshness.result }}
        run: |
          for result in "$QUALITY" "$PROTO_FRESHNESS"; do
            if [ "$result" = "failure" ]; then exit 1; fi
          done
EOF
    } > "$path"
}

GOOD_FILTER="              - 'proto/**'
              - 'sdks/typescript/src/generated/**'
              - 'sdks/go/generated/**'"

GOOD_JOB="
  proto-freshness:
    name: proto-freshness (generated SDK types match proto/)
    needs: filter
    if: (needs.filter.result == 'success' && needs.filter.outputs.proto == 'true') || github.ref == 'refs/heads/main'
    steps:
      - name: make proto-check
        run: make proto-check"

# run_case <name> <expected-exit> <workflow> <makefile> [expected-substring]
run_case() {
    local name="$1" want="$2" wf="$3" mk="$4" expect="${5:-}" out rc
    out="$(CI_WORKFLOW="$wf" MAKEFILE="$mk" bash "$CHECK" 2>&1)"
    rc=$?
    if [[ "$rc" != "$want" ]]; then
        fail "${name}: exit ${rc}, want ${want}"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    if [[ -n "$expect" ]] && ! printf '%s\n' "$out" | grep -qF "$expect"; then
        fail "${name}: output does not mention '${expect}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    pass "$name"
}

MK="${TMP}/Makefile"
make_makefile "$MK"

echo "== the fixed arrangement passes =="
make_workflow "${TMP}/good.yml" "$GOOD_FILTER" "$GOOD_JOB"
run_case "inputs and outputs both gated, job wired into required-summary" \
    0 "${TMP}/good.yml" "$MK" "OK:"

echo "== the pre-fix arrangement fails (the defect) =="
# The audited shape: no proto-freshness job at all; the check lived inside the
# `quality` job, and the `proto` filter named inputs only.
make_workflow "${TMP}/prefix.yml" "              - 'proto/**'" ""
run_case "no freshness job, filter names inputs only" \
    1 "${TMP}/prefix.yml" "$MK" "does not name 'sdks/typescript/src/generated/**'"

echo "== each hole is caught on its own =="
make_workflow "${TMP}/no-ts.yml" \
    "              - 'proto/**'
              - 'sdks/go/generated/**'" "$GOOD_JOB"
run_case "a dropped TypeScript output directory" \
    1 "${TMP}/no-ts.yml" "$MK" "does not name 'sdks/typescript/src/generated/**'"

make_workflow "${TMP}/no-go.yml" \
    "              - 'proto/**'
              - 'sdks/typescript/src/generated/**'" "$GOOD_JOB"
run_case "a dropped Go output directory" \
    1 "${TMP}/no-go.yml" "$MK" "does not name 'sdks/go/generated/**'"

make_workflow "${TMP}/no-input.yml" \
    "              - 'sdks/typescript/src/generated/**'
              - 'sdks/go/generated/**'" "$GOOD_JOB"
run_case "a dropped proto/ input" \
    1 "${TMP}/no-input.yml" "$MK" "does not name 'proto/**'"

make_workflow "${TMP}/wrong-gate.yml" "$GOOD_FILTER" "
  proto-freshness:
    name: proto-freshness
    needs: filter
    if: needs.filter.result == 'success' && needs.filter.outputs.rust == 'true'
    steps:
      - name: make proto-check
        run: make proto-check"
run_case "the job gated on the wrong filter" \
    1 "${TMP}/wrong-gate.yml" "$MK" "does not gate on the 'proto' filter output"

make_workflow "${TMP}/skip-on-filter-failure.yml" "$GOOD_FILTER" "
  proto-freshness:
    name: proto-freshness
    needs: filter
    if: needs.filter.outputs.proto == 'true'
    steps:
      - name: make proto-check
        run: make proto-check"
run_case "a filter failure would skip the job (branch protection reads that as a pass)" \
    1 "${TMP}/skip-on-filter-failure.yml" "$MK" "would skip it"

make_workflow "${TMP}/no-check.yml" "$GOOD_FILTER" "
  proto-freshness:
    name: proto-freshness
    needs: filter
    if: (needs.filter.result == 'success' && needs.filter.outputs.proto == 'true')
    steps:
      - name: nothing
        run: echo ok"
run_case "the job no longer runs make proto-check" \
    1 "${TMP}/no-check.yml" "$MK" "does not run 'make proto-check'"

make_workflow "${TMP}/disarmed.yml" "$GOOD_FILTER" "
  proto-freshness:
    name: proto-freshness
    needs: filter
    if: (needs.filter.result == 'success' && needs.filter.outputs.proto == 'true')
    steps:
      - name: make proto-check
        continue-on-error: true
        run: make proto-check"
run_case "a disarmed (continue-on-error) freshness step" \
    1 "${TMP}/disarmed.yml" "$MK" "continue-on-error"

echo "== required-summary must be able to fail on drift =="
make_workflow "${TMP}/unwired.yml" "$GOOD_FILTER" "$GOOD_JOB"
# Drop the job from required-summary's needs and env.
sed -i 's/needs: \[filter, quality, proto-freshness, ui\]/needs: [filter, quality, ui]/' "${TMP}/unwired.yml"
sed -i '/PROTO_FRESHNESS:/d' "${TMP}/unwired.yml"
run_case "the job is not wired into required-summary" \
    1 "${TMP}/unwired.yml" "$MK" "required-summary"

echo "== a third generated language is picked up from the Makefile =="
cat > "${TMP}/Makefile.three" <<'EOF'
proto-check:
	cd proto && buf generate
	@if git diff --quiet sdks/typescript/src/generated sdks/go/generated sdks/kotlin/generated; then \
		echo ok; \
	else \
		exit 1; \
	fi
EOF
run_case "a new generated directory must be added to the filter" \
    1 "${TMP}/good.yml" "${TMP}/Makefile.three" "does not name 'sdks/kotlin/generated/**'"

echo "== the real repository passes =="
run_case "the checked-in ci.yml and Makefile" \
    0 "${REPO_ROOT}/.github/workflows/ci.yml" "${REPO_ROOT}/Makefile" "OK:"

echo
if [[ "$failures" -eq 0 ]]; then
    echo "check-proto-freshness-gate: all checks passed"
    exit 0
fi
echo "check-proto-freshness-gate: ${failures} check(s) failed"
exit 1
