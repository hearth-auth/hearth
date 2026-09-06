#!/usr/bin/env bash
# scripts/tests/check-advisory-gates.test.sh — tests for check-advisory-gates.sh.
#
# The guard exists to stop audit findings §4.8#7 / §4.12#3 recurring, so it
# must be shown to FAIL on both audited shapes: a continue-on-error advisory
# step (case 2) and a paths-filtered cargo-deny job (case 3).
#
# Usage: bash scripts/tests/check-advisory-gates.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-advisory-gates.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0

# run_case <name> <expected-exit> <ci-yml-body> [extra-file:name] [extra-body] [expected-substring]
run_case() {
    local name="$1" want="$2" ci_body="$3" extra_name="${4:-}" extra_body="${5:-}" expect="${6:-}"
    local dir="$TMP/case-$((RANDOM))-$$"
    mkdir -p "$dir"
    printf '%s\n' "$ci_body" > "$dir/ci.yml"
    [[ -n "$extra_name" ]] && printf '%s\n' "$extra_body" > "$dir/$extra_name"
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

GOOD_CI='on:
  pull_request:
jobs:
  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - name: cargo deny check
        run: cargo deny check
      - name: cargo audit
        run: cargo audit --deny warnings
  required-summary:
    needs: [quality, cargo-deny]
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
'

# 1 — the remediated shape passes.
run_case "armed unconditional gate passes" 0 "$GOOD_CI" "" "" \
    "OK: every dependency-advisory gate runs on every PR and can fail it"

# 2 — THE REGRESSION (§4.12#3): a continue-on-error advisory step. This is the
#     quality-job shape that turned a 70-vulnerability scan into a success job.
run_case "continue-on-error advisory step is rejected" 1 'on:
  pull_request:
jobs:
  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - name: cargo deny check
        run: cargo deny check
      - name: cargo audit
        run: cargo audit --deny warnings
  quality:
    runs-on: ubuntu-latest
    steps:
      - name: Security audit (cargo audit --deny warnings)
        continue-on-error: true
        run: cargo audit --deny warnings
  required-summary:
    needs: [quality, cargo-deny]
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
' "" "" "advisory step is continue-on-error"

# 3 — THE OTHER REGRESSION (§4.8#7): the cargo-deny job scoped by a paths
#     filter, so a PR that does not touch the lockfile never meets the gate.
run_case "paths-filtered cargo-deny job is rejected" 1 'on:
  pull_request:
jobs:
  cargo-deny:
    needs: filter
    if: (needs.filter.result == '"'"'success'"'"' && needs.filter.outputs.deny == '"'"'true'"'"')
    runs-on: ubuntu-latest
    steps:
      - name: cargo deny check
        run: cargo deny check
      - name: cargo audit
        run: cargo audit --deny warnings
  required-summary:
    needs: [cargo-deny]
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
' "" "" "scoped by a paths filter"

# 4 — a cargo-deny job that dropped cargo audit fails.
run_case "missing cargo audit is rejected" 1 'on:
  pull_request:
jobs:
  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - name: cargo deny check
        run: cargo deny check
  required-summary:
    needs: [cargo-deny]
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
' "" "" "does not run 'cargo audit'"

# 5 — no cargo-deny job at all fails.
run_case "absent cargo-deny job is rejected" 1 'on:
  pull_request:
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - run: make check
  required-summary:
    needs: [quality]
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
' "" "" "no 'cargo-deny' job"

# 6 — required-summary that does not need cargo-deny fails: the gate exists
#     but cannot block a merge.
run_case "summary without cargo-deny is rejected" 1 'on:
  pull_request:
jobs:
  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - name: cargo deny check
        run: cargo deny check
      - name: cargo audit
        run: cargo audit --deny warnings
  required-summary:
    needs: [quality]
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
' "" "" "required-summary does not need cargo-deny"

# 7 — a disarmed scanner in ANOTHER workflow fails (the security.yml shape).
run_case "continue-on-error osv-scanner is rejected" 1 "$GOOD_CI" "security.yml" 'on:
  pull_request:
jobs:
  osv-scanner:
    runs-on: ubuntu-latest
    steps:
      - name: Run OSV-Scanner
        uses: google/osv-scanner-action/osv-scanner-action@abc123
        continue-on-error: true
        with:
          scan-args: --lockfile=Cargo.lock
' "advisory step is continue-on-error"

# 8 — job-level continue-on-error over an advisory scanner fails.
run_case "job-level continue-on-error is rejected" 1 "$GOOD_CI" "security.yml" 'on:
  pull_request:
jobs:
  osv-scanner:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - name: Run OSV-Scanner
        uses: google/osv-scanner-action/osv-scanner-action@abc123
' "job-level continue-on-error"

# 9 — continue-on-error on a NON-advisory step stays legal: the guard must not
#     fire on informational UI or coverage steps, or it gets disabled.
run_case "unrelated continue-on-error passes" 0 "$GOOD_CI" "ui-nightly.yml" 'on:
  schedule:
jobs:
  ui-exploratory:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - name: Deep crawl
        run: npm run explore
' "OK: every dependency-advisory gate"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "OK: all check-advisory-gates.sh cases passed."
exit 0
