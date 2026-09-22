#!/usr/bin/env bash
# scripts/tests/check-production-deps.test.sh — tests for
# scripts/check-production-deps.sh (audit 2026-08-28 §4.8#9).
#
# The guard is the deliverable, so it needs a case that proves it goes RED.
# The red case uses the real dependency graph and a crate that is genuinely in
# it (`ring`), so the test cannot pass against an `exit 0` stub.
#
# Usage: bash scripts/tests/check-production-deps.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-production-deps.sh"

failures=0

# run_case <name> <expected-exit> <banned-list> [expected-substring]
run_case() {
    local name="$1" want="$2" banned="$3" expect="${4:-}"
    local out got
    out="$(cd "$REPO_ROOT" && PRODUCTION_BANNED="$banned" bash "$CHECK" 2>&1)"
    got=$?
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

# 1 — RED: `ring` is genuinely in the production graph, so banning it must fail.
#     This is what an `exit 0` stub cannot satisfy.
run_case "a crate that IS in the production graph is rejected" 1 "ring" \
    "reaches the published hearth binary"

# 2 — the real ban list passes on the current tree.
run_case "the default ban list passes" 0 \
    "reqwest openssl native-tls hyper-tls boring curl isahc" \
    "OK: no banned crate"

# 3 — a crate absent from the lockfile entirely is not a failure.
run_case "a crate absent from the lockfile passes" 0 \
    "definitely-not-a-real-crate-name-xyzzy" \
    "ok:"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "all check-production-deps.sh test cases passed."
exit 0
