#!/usr/bin/env bash
# scripts/tests/check-dev-server-config-isolation.test.sh — tests for
# scripts/check-dev-server-config-isolation.sh (audit 2026-08-28 §4.12#13).
#
# The guard exists to stop the finding recurring, so it must be shown to FAIL on
# the audited shape — a bare `serve --dev` launched from whatever directory the
# caller happened to be in — not merely to pass on the fixed scripts.
#
#   case 2  THE REGRESSION: bare `serve --dev`, no --config, no cd
#   case 3  a cd into a directory the script did NOT create (no mktemp)
#   case 4  --config makes it fine
#   case 5  a cd into a mktemp directory makes it fine
#   case 6  prose mentioning the pattern is not a launch
#
# Usage: bash scripts/tests/check-dev-server-config-isolation.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-dev-server-config-isolation.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

# run_case <name> <expected-exit> <script-body> [expected-substring]
run_case() {
    local name="$1" want="$2" body="$3" expect="${4:-}"
    case_n=$((case_n + 1))
    local dir="$TMP/case-${case_n}"
    mkdir -p "$dir"
    printf '%s\n' "$body" > "$dir/boot.sh"

    local out got=0
    out="$(SEARCH_ROOT="$dir" bash "$CHECK" 2>&1)" || got=$?
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

# 1 — THE REGRESSION (§4.12#13): the exact pre-fix line from sdk-smoke-local.sh.
run_case "bare serve --dev is rejected" 1 '#!/usr/bin/env bash
cd "$REPO_ROOT"
"$HEARTH_BIN" serve --dev --port "$HEARTH_PORT" &
HEARTH_PID=$!' \
    "with neither an explicit"

# 2 — a cd is not enough on its own: the directory must be one this script made,
#     or it is just another directory that may hold a hearth.yaml.
run_case "cd into a directory the script did not create is rejected" 1 '#!/usr/bin/env bash
( cd "$REPO_ROOT/examples" && exec "$BIN" serve --dev --port 8420 ) &' \
    "nor a cd into a directory the script created"

# 3 — an explicit --config states which file is read. That is the whole rule.
run_case "explicit --config passes" 0 '#!/usr/bin/env bash
"$BIN" serve --dev --config "$HERE/hearth.yaml" --port 8420 &' \
    "OK: every"

# 4 — the shape the fix uses.
run_case "cd into a mktemp directory passes" 0 '#!/usr/bin/env bash
RUN_DIR="$(mktemp -d)"
( cd "$RUN_DIR" && exec "$BIN" serve --dev --port 8420 ) &' \
    "OK: every"

# 5 — a comment or an echo about a launch is not a launch.
run_case "prose about serve --dev is not a launch" 1 '#!/usr/bin/env bash
# Boot it with: hearth serve --dev --port 8420
echo "==> Starting hearth serve --dev"' \
    "has nothing to check"

# 6 — the repository itself passes.
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    echo "ok: every launcher in the repository is isolated"
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
