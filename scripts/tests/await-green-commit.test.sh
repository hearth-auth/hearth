#!/usr/bin/env bash
# scripts/tests/await-green-commit.test.sh — tests for scripts/await-green-commit.sh.
#
# The gate is the deliverable for audit blockers B2 and B6, so it needs a test that
# proves it REFUSES. A gate that only ever exits 0 is the state the audit found:
# v1.6.11's image and chart published 37 minutes before the verdict said no.
#
# Cases 3-5 are the fail-closed cases. Each is a state where the old pipeline
# published: no verdict yet, verdict still running, verdict unreadable.
#
# Usage: bash scripts/tests/await-green-commit.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${SCRIPT_DIR}/await-green-commit.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq is not installed."; exit 0; }

failures=0

# stub_gh <name> <body> — write a fake `gh` that prints <body> on stdout.
stub_gh() {
    local path="$TMP/$1"
    printf '#!/usr/bin/env bash\ncat <<'\''JSON'\''\n%s\nJSON\n' "$2" > "$path"
    chmod +x "$path"
    echo "$path"
}

# stub_gh_failing <name> — a fake `gh` that always errors, like a missing token.
stub_gh_failing() {
    local path="$TMP/$1"
    printf '#!/usr/bin/env bash\necho "gh: authentication required" >&2\nexit 1\n' > "$path"
    chmod +x "$path"
    echo "$path"
}

# run_case <name> <expected-exit> <gh-stub-path> <timeout> [expected-substring]
run_case() {
    local name="$1" want="$2" gh="$3" timeout="$4" expect="${5:-}"
    local out got=0
    out="$(CHECK_NAME="required-summary" COMMIT_SHA="deadbeef" REPO="acme/widget" \
        TIMEOUT_SECONDS="$timeout" POLL_SECONDS=0 GH_BIN="$gh" \
        bash "$GATE" 2>&1)" || got=$?
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

green='{"check_runs":[{"name":"required-summary","status":"completed","conclusion":"success","started_at":"2026-09-01T10:00:00Z"}]}'
red='{"check_runs":[{"name":"required-summary","status":"completed","conclusion":"failure","started_at":"2026-09-01T10:00:00Z"}]}'
running='{"check_runs":[{"name":"required-summary","status":"in_progress","conclusion":null,"started_at":"2026-09-01T10:00:00Z"}]}'
other='{"check_runs":[{"name":"some-other-check","status":"completed","conclusion":"success","started_at":"2026-09-01T10:00:00Z"}]}'
empty='{"check_runs":[]}'
rerun_green_last='{"check_runs":[
  {"name":"required-summary","status":"completed","conclusion":"failure","started_at":"2026-09-01T10:00:00Z"},
  {"name":"required-summary","status":"completed","conclusion":"success","started_at":"2026-09-01T12:00:00Z"}]}'
rerun_red_last='{"check_runs":[
  {"name":"required-summary","status":"completed","conclusion":"success","started_at":"2026-09-01T10:00:00Z"},
  {"name":"required-summary","status":"completed","conclusion":"failure","started_at":"2026-09-01T12:00:00Z"}]}'

# 1 — the only pass: the named check completed and succeeded on this commit.
run_case "green verdict clears publishing" 0 "$(stub_gh gh-green "$green")" 60 \
    "Publishing is cleared"

# 2 — B2: the suite is red. The old pipeline signed and published here.
run_case "red verdict refuses publishing" 1 "$(stub_gh gh-red "$red")" 60 \
    "not cleared to publish"

# 3 — B6: the verdict has not been written yet. The old pipeline published anyway.
run_case "absent verdict refuses publishing" 1 "$(stub_gh gh-empty "$empty")" 0 \
    "No verdict from 'required-summary'"

# 4 — the verdict is still running. Waiting out the deadline must not pass.
run_case "in-progress verdict refuses publishing at the deadline" 1 \
    "$(stub_gh gh-running "$running")" 0 "No verdict from 'required-summary'"

# 5 — a different check is green. A name mismatch must not be read as a pass.
run_case "a different green check is not this check" 1 "$(stub_gh gh-other "$other")" 0 \
    "No verdict from 'required-summary'"

# 6 — an unreadable API is a refusal, not a silent pass (the HEA-2203 lesson).
run_case "unreadable API refuses publishing" 1 "$(stub_gh_failing gh-broken)" 0 \
    "never reached"

# 7 — re-run: an older failure superseded by a newer success clears.
run_case "newest verdict wins (green after red)" 0 \
    "$(stub_gh gh-rerun-green "$rerun_green_last")" 60 "Publishing is cleared"

# 8 — re-run: a stale success must not clear a newer failure.
run_case "newest verdict wins (red after green)" 1 \
    "$(stub_gh gh-rerun-red "$rerun_red_last")" 60 "not cleared to publish"

# 9 — a missing check name is a configuration error, not a pass.
{
    _out="$(COMMIT_SHA="deadbeef" REPO="acme/widget" GH_BIN="$(stub_gh gh-green2 "$green")" \
        bash "$GATE" 2>&1)"
    _ec=$?
    if [[ "$_ec" -eq 0 ]]; then
        echo "FAIL: missing CHECK_NAME — expected non-zero, got 0"
        failures=$((failures + 1))
    else
        echo "ok: missing CHECK_NAME is refused with exit ${_ec}"
    fi
    unset _out _ec
}

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "all await-green-commit.sh test cases passed."
exit 0
