#!/usr/bin/env bash
# scripts/tests/check-go-module-major.test.sh — tests for
# scripts/check-go-module-major.sh (OpenSpec change `sdk-go-module-major`).
#
# The guard is the deliverable, so it needs a test that proves it FAILS on the
# defect it exists for — not just that it passes on a correct module, which an
# `exit 0` stub would also satisfy.
#
# The defect: the Go SDK's go.mod declared `github.com/hearth-auth/hearth/sdks/go`
# while its tags were `sdks/go/v3.x.y`. Go resolves a v2+ tag only for a module
# path that ends in `/vN`, so `go get .../sdks/go@latest` stopped at v1.6.11.
#
# Usage: bash scripts/tests/check-go-module-major.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-go-module-major.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0

# Writes a go.mod with this module path under $TMP/<name> and echoes its path.
# make_go_mod <name> <module-path>
make_go_mod() {
    local name="$1" module="$2"
    mkdir -p "$TMP/$name"
    printf 'module %s\n\ngo 1.26.3\n' "$module" > "$TMP/$name/go.mod"
    echo "$TMP/$name/go.mod"
}

# run_case <name> <expected-exit> <go.mod path> <version> [expected-substring]
run_case() {
    local name="$1" want="$2" go_mod="$3" version="$4" expect="${5:-}"
    local out got
    out="$(GO_MOD="$go_mod" bash "$CHECK" "$version" 2>&1)"
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

BASE='github.com/hearth-auth/hearth/sdks/go'

# 1 — a module path that carries the release's major passes.
run_case "a /v3 module releases 3.5.9" 0 "$(make_go_mod v3 "$BASE/v3")" 3.5.9 "OK:"

# 2 — REGRESSION: the unsuffixed module path with a v3 release. This is the
#     exact shape that kept `go get` on v1.6.11.
run_case "an unsuffixed module cannot release 3.5.9" 1 \
    "$(make_go_mod bare "$BASE")" 3.5.9 "must end in /v3"

# 3 — a major bump without a module path change (the next breaking release).
run_case "a /v3 module cannot release 4.0.0" 1 \
    "$(make_go_mod bump "$BASE/v3")" 4.0.0 "must end in /v4"

# 4 — v0 and v1 take no suffix.
run_case "an unsuffixed module releases 1.6.12" 0 "$(make_go_mod v1 "$BASE")" 1.6.12 "OK:"
run_case "a /v2 module cannot release 1.2.0" 1 \
    "$(make_go_mod v2low "$BASE/v2")" 1.2.0 "must not end in a /vN suffix"

# 5 — a prerelease version keeps its major.
run_case "a /v4 module releases 4.0.0-rc.1" 0 "$(make_go_mod rc "$BASE/v4")" 4.0.0-rc.1 "OK:"

# 6 — a version that is not semver, and a missing version, are refused.
run_case "a non-semver version is refused" 2 "$(make_go_mod junk "$BASE/v3")" v3 "usage"
run_case "a missing version is refused" 2 "$(make_go_mod none "$BASE/v3")" "" "usage"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "all check-go-module-major.sh test cases passed."
exit 0
