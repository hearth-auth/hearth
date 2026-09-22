#!/usr/bin/env bash
# scripts/tests/check-nextest-profile-live.test.sh — tests for
# scripts/check-nextest-profile-live.sh (audit 2026-08-28 §4.12#18).
#
#   case 1  THE REGRESSION: [profile.ci] declared, nothing selects it
#   case 2  selected by NEXTEST_PROFILE in a workflow
#   case 3  selected by a --profile argument
#   case 4  `default` and `default-miri` need no selector
#   case 5  a near-miss name does not count as a selector
#
# Usage: bash scripts/tests/check-nextest-profile-live.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-nextest-profile-live.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

# run_case <name> <expected-exit> <nextest.toml> <selector-file-contents> [expect]
run_case() {
    local name="$1" want="$2" toml="$3" sel="$4" expect="${5:-}"
    case_n=$((case_n + 1))
    local dir="$TMP/case-${case_n}"
    mkdir -p "$dir/.config" "$dir/.github/workflows"
    printf '%s\n' "$toml" > "$dir/.config/nextest.toml"
    printf '%s\n' "$sel"  > "$dir/.github/workflows/ci.yml"

    local out got=0
    out="$(cd "$dir" && SEARCH_ROOT="." NEXTEST_CONFIG=".config/nextest.toml" \
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

CI_TOML='[profile.default]
retries = 0
fail-fast = true

[profile.ci]
retries = 2
fail-fast = false'

# 1 — THE REGRESSION (§4.12#18): the audited shape exactly.
run_case "an unselected profile is rejected" 1 "$CI_TOML" \
    'jobs:
  quality:
    steps:
      - run: make check' \
    "is declared but never selected"

# 2 — NEXTEST_PROFILE in a workflow selects it. This is the fix.
run_case "NEXTEST_PROFILE selects the profile" 0 "$CI_TOML" \
    'jobs:
  quality:
    steps:
      - env:
          NEXTEST_PROFILE: ci
        run: make check' \
    "OK: every declared nextest profile is selected somewhere"

# 3 — an explicit --profile argument selects it too.
run_case "--profile selects the profile" 0 "$CI_TOML" \
    'jobs:
  quality:
    steps:
      - run: cargo nextest run --workspace --profile ci' \
    "OK: every declared nextest profile is selected somewhere"

# 4 — `default` and the tool-owned `default-*` need no selector.
run_case "default profiles need no selector" 0 '[profile.default]
retries = 0

[profile.default-miri]
retries = 0' \
    'jobs:
  quality:
    steps:
      - run: make check' \
    "OK: no selectable nextest profiles are declared"

# 5 — a longer name that merely starts with the profile name is not a selector.
run_case "a near-miss selector does not count" 1 "$CI_TOML" \
    'jobs:
  quality:
    steps:
      - run: cargo nextest run --profile cirrus' \
    "never selected"

# 6 — the repository itself passes.
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    echo "ok: the repository's own nextest profiles are all selected"
else
    echo "FAIL: the repository does not pass"
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
