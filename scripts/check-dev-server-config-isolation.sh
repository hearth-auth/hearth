#!/usr/bin/env bash
# scripts/check-dev-server-config-isolation.sh — a script that boots `serve --dev`
# must control which config file the server reads.
#
# Audit 2026-08-28 finding §4.12#13 (MEDIUM):
#
#   `make sdk-smoke-local` booted `hearth serve --dev` with the repository root
#   as its working directory and no `--config`. `load_config` in src/main.rs
#   auto-detects a `hearth.yaml` in the working directory, and CLAUDE.md's first
#   instruction to every contributor is `cp hearth.example.yaml hearth.yaml`.
#
#   Measured on 2026-09-08 against the same binary, changing only the working
#   directory:
#
#     empty directory (what CI has, hearth.yaml being gitignored):
#       iss = http://127.0.0.1:<port>/realms/dev-realm
#     directory holding a copy of the shipped hearth.example.yaml:
#       iss = https://auth.example.com/realms/dev-realm
#
#   The example sets `oidc.issuer: https://auth.example.com`, so every token the
#   smoke mints points its JWKS lookup at a host that is not the server under
#   test. The script's own comments already worked around one symptom of this
#   ("avoid following hearth.yaml (port 8420) rather than the randomly selected
#   smoke-test port") without fixing the cause. CI passed throughout, because a
#   fresh checkout has no hearth.yaml.
#
#   Three sibling launchers had the same shape: examples/agent-auth-smoke,
#   examples/rbac-smoke-test, and scripts/check-cluster-routes.sh — the first of
#   which sdk-smoke-local.sh calls.
#
# One rule:
#
#   R1  Every `serve --dev` launch in a tracked shell script must EITHER pass an
#       explicit `--config`/`-c`, OR run inside a `cd` to a directory the script
#       created (mktemp). Anything else reads whatever hearth.yaml the operator
#       happens to have.
#
# Usage:  bash scripts/check-dev-server-config-isolation.sh
# Env:    SEARCH_ROOT  directory to scan (default: repo root)

set -uo pipefail

SEARCH_ROOT="${SEARCH_ROOT:-.}"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

mapfile -t SCRIPTS < <(
    find "$SEARCH_ROOT" \
        -path '*/node_modules' -prune -o \
        -path '*/target' -prune -o \
        -path '*/.git' -prune -o \
        -path '*/.claude' -prune -o \
        -type f -name '*.sh' -print
)

launches_found=0

for sh in "${SCRIPTS[@]}"; do
    rel="${sh#./}"
    # This file documents the pattern it forbids; scanning itself is noise.
    [[ "$(basename "$sh")" == "check-dev-server-config-isolation.sh" ]] && continue
    # Guard self-tests build fixture text containing the pattern on purpose.
    [[ "$sh" == */scripts/tests/* ]] && continue
    # A launch line runs the binary with `serve` and `--dev` on the same line.
    # Comment lines are prose about a launch, not a launch.
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        lineno="${line%%:*}"
        text="${line#*:}"
        launches_found=$((launches_found + 1))

        # Explicit config wins: the script said which file to read.
        if [[ "$text" == *"--config"* || "$text" == *" -c "* ]]; then
            continue
        fi
        # Otherwise the launch must be wrapped in a cd to a directory this
        # script made. `mktemp` anywhere in the file plus a `cd` on the launch
        # line is the shape the fix uses.
        if [[ "$text" == *"cd "* ]] && grep -q 'mktemp' "$sh"; then
            continue
        fi
        fail "${rel}:${lineno}: boots 'serve --dev' with neither an explicit" \
            $'\n      --config nor a cd into a directory the script created.' \
            $'\n      It reads whatever hearth.yaml the operator has, and CLAUDE.md tells' \
            $'\n      every contributor to make one (§4.12#13).' \
            $'\n      Line: '"$(sed -E 's/^[[:space:]]+//' <<<"$text")"
    done < <(grep -nE 'serve[[:space:]].*--dev' "$sh" \
        | grep -vE ':[[:space:]]*#' \
        | grep -vE ':[[:space:]]*(echo|printf|fail|die|cat|return)[[:space:]]')
done

if [[ "$launches_found" -eq 0 ]]; then
    fail "no 'serve --dev' launch found under ${SEARCH_ROOT}; the rule has nothing to check."
fi

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} dev-server config-isolation violation(s)."
    echo "See scripts/check-dev-server-config-isolation.sh for the rule and the audit citation."
    exit 1
fi
echo "OK: every 'serve --dev' launch controls which config the server reads."
exit 0
