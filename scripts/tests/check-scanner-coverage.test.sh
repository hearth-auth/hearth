#!/usr/bin/env bash
# scripts/tests/check-scanner-coverage.test.sh — tests for check-scanner-coverage.sh.
#
# The guard exists to stop audit findings §4.8#16 / §4.12#15 recurring, so it
# must be shown to FAIL on each of the four audited shapes, not merely to pass
# on the remediated tree:
#
#   case 2  a schedule condition in a workflow with no schedule: trigger
#   case 3  a Trivy step with no exit-code (advisory-only)
#   case 4  a docker.yml with no scan-type: image
#   case 5  a suppression with no guard annotation
#   case 6  a suppression whose package is absent from the lockfile it names
#   case 7  a suppression naming a lockfile security.yml does not scan
#
# Usage: bash scripts/tests/check-scanner-coverage.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-scanner-coverage.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

GOOD_CI='on:
  pull_request:
    branches: [main]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - run: make check
'

GOOD_SECURITY='on:
  schedule:
    - cron: "0 6 * * 1"
jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.29.0
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
          exit-code: "1"
          format: sarif
          output: trivy.sarif
  osv-scanner:
    runs-on: ubuntu-latest
    steps:
      - name: Run OSV-Scanner
        uses: google/osv-scanner-action/osv-scanner-action@9a498708959aeaef5ef730655706c5a1df1edbc2 # v2.3.8
        with:
          scan-args: |-
            --lockfile=Cargo.lock
'

GOOD_DOCKER='on:
  push:
    tags: ["v*"]
jobs:
  merge-and-sign:
    runs-on: ubuntu-latest
    steps:
      - name: Scan the published image
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.29.0
        with:
          scan-type: image
          severity: CRITICAL,HIGH
          exit-code: "1"
'

GOOD_OSV='# guard: package=serde lockfile=Cargo.lock
[[IgnoredVulns]]
id = "RUSTSEC-0000-0001"
reason = "Test fixture."
'

GOOD_LOCK='name = "serde"
version = "1.0.0"
'

# run_case <name> <expected-exit> <ci> <security> <docker> <osv> <lock> [expected-substring]
run_case() {
    local name="$1" want="$2" ci="$3" security="$4" docker="$5" osv="$6" lock="$7"
    local expect="${8:-}"
    case_n=$((case_n + 1))
    local dir="$TMP/case-${case_n}"
    mkdir -p "$dir/.github/workflows"
    printf '%s\n' "$ci"       > "$dir/.github/workflows/ci.yml"
    printf '%s\n' "$security" > "$dir/.github/workflows/security.yml"
    printf '%s\n' "$docker"   > "$dir/.github/workflows/docker.yml"
    printf '%s\n' "$osv"      > "$dir/osv-scanner.toml"
    printf '%s\n' "$lock"     > "$dir/Cargo.lock"

    local out got=0
    out="$(cd "$dir" && WORKFLOW_DIR=".github/workflows" OSV_CONFIG="osv-scanner.toml" \
        bash "$CHECK" 2>&1)" || got=$?
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

# 1 — the remediated shape passes.
run_case "remediated configuration passes" 0 \
    "$GOOD_CI" "$GOOD_SECURITY" "$GOOD_DOCKER" "$GOOD_OSV" "$GOOD_LOCK" \
    "OK: scanner configuration describes the coverage it actually has"

# 2 — THE REGRESSION (§4.8#16, part 1): a schedule condition with no trigger.
#     This is the ci.yml shape: fifteen jobs claimed a scheduled full-matrix run
#     on a workflow that only ever ran on pull_request and push.
run_case "dead schedule condition is rejected" 1 'on:
  pull_request:
    branches: [main]
jobs:
  quality:
    if: needs.filter.outputs.rust == '"'"'true'"'"' || github.event_name == '"'"'schedule'"'"'
    runs-on: ubuntu-latest
    steps:
      - run: make check
' "$GOOD_SECURITY" "$GOOD_DOCKER" "$GOOD_OSV" "$GOOD_LOCK" \
    "declares no on.schedule: trigger"

# 2b — the same condition IS allowed once the trigger exists.
run_case "schedule condition with a real trigger passes" 0 'on:
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * *"
jobs:
  quality:
    if: github.event_name == '"'"'schedule'"'"'
    runs-on: ubuntu-latest
    steps:
      - run: make check
' "$GOOD_SECURITY" "$GOOD_DOCKER" "$GOOD_OSV" "$GOOD_LOCK" \
    "OK: scanner configuration"

# 3 — THE REGRESSION (§4.8#16, part 2): Trivy with no exit-code. The audited
#     job scanned at CRITICAL,HIGH and reported success on every finding.
run_case "advisory-only Trivy step is rejected" 1 "$GOOD_CI" 'on:
  schedule:
    - cron: "0 6 * * 1"
jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.29.0
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
          format: sarif
          output: trivy.sarif
' "$GOOD_DOCKER" "$GOOD_OSV" "$GOOD_LOCK" \
    "Trivy step is advisory-only"

# 4 — THE REGRESSION (§4.8#16, part 3): no image scan. The filesystem scan read
#     the checkout; nothing read the layers operators pull.
run_case "unscanned published image is rejected" 1 \
    "$GOOD_CI" "$GOOD_SECURITY" 'on:
  push:
    tags: ["v*"]
jobs:
  merge-and-sign:
    runs-on: ubuntu-latest
    steps:
      - name: Create and push multi-arch manifest
        run: docker buildx imagetools create --tag ghcr.io/x/y a b
' "$GOOD_OSV" "$GOOD_LOCK" \
    "nothing runs a Trivy scan-type: image"

# 5 — an unannotated suppression cannot be checked at all, so it is rejected.
run_case "unannotated suppression is rejected" 1 \
    "$GOOD_CI" "$GOOD_SECURITY" "$GOOD_DOCKER" '[[IgnoredVulns]]
id = "RUSTSEC-0000-0001"
reason = "Test fixture."
' "$GOOD_LOCK" \
    'has no'

# 6 — THE REGRESSION (§4.12#15): the suppressed package is not in the tree the
#     rationale names. This is the `rsa` and `esbuild` shape exactly.
run_case "suppression for an absent package is rejected" 1 \
    "$GOOD_CI" "$GOOD_SECURITY" "$GOOD_DOCKER" '# guard: package=esbuild lockfile=Cargo.lock
[[IgnoredVulns]]
id = "GHSA-0000-0000-0000"
reason = "Test fixture."
' "$GOOD_LOCK" \
    "which is absent from"

# 7 — a suppression aimed at a lockfile the scanner never reads can never fire.
#     sdks/go/go.mod is absent from GOOD_SECURITY's --lockfile list.
run_case "suppression naming an unscanned lockfile is rejected" 1 \
    "$GOOD_CI" "$GOOD_SECURITY" "$GOOD_DOCKER" '# guard: package=serde lockfile=sdks/go/go.mod
[[IgnoredVulns]]
id = "RUSTSEC-0000-0001"
reason = "Test fixture."
' "$GOOD_LOCK" \
    "does not exist"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} guard self-test failure(s)."
    exit 1
fi
echo "OK: ${case_n} guard self-tests passed."
exit 0
