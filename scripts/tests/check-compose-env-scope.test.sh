#!/usr/bin/env bash
# scripts/tests/check-compose-env-scope.test.sh — tests for check-compose-env-scope.sh.
#
# The guard exists to stop audit finding §4.8#17 recurring, so it must be shown
# to FAIL on the audited shape (`- path: ../.env`), not merely to pass on the
# remediated file.
#
#   case 2  the audited shape: a `..` path reaching the repository-root .env
#   case 3  the same escape written in the short list form
#   case 4  a bare `.env` beside the compose file — in scope by path, but still
#           the project catch-all, so still rejected
#   case 5  an env_file with no committed .example — no schema, no scope
#   case 6  an example declaring a key Hearth does not read
#
# Usage: bash scripts/tests/check-compose-env-scope.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-compose-env-scope.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

GOOD_EXAMPLE='# Hearth container environment overrides.
HEARTH_BIND_ADDRESS=0.0.0.0
RUST_LOG=info,hearth=debug
'

# run_case <name> <expected-exit> <compose-body> <example-name|""> <example-body> [expect]
run_case() {
    local name="$1" want="$2" compose="$3" ex_name="${4:-}" ex_body="${5:-}" expect="${6:-}"
    case_n=$((case_n + 1))
    local dir="$TMP/case-${case_n}"
    mkdir -p "$dir/deploy"
    printf '%s\n' "$compose" > "$dir/deploy/docker-compose.yml"
    [[ -n "$ex_name" ]] && printf '%s\n' "$ex_body" > "$dir/deploy/$ex_name"

    local out got=0
    out="$(cd "$dir" && COMPOSE_GLOB_DIR="." bash "$CHECK" 2>&1)" || got=$?
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
run_case "scoped env file with a committed example passes" 0 'services:
  hearth:
    image: ghcr.io/hearth-auth/hearth:latest
    env_file:
      - path: ./hearth.env
        required: false
' "hearth.env.example" "$GOOD_EXAMPLE" \
    "OK: every shipped compose file sources only an env file this repo defines"

# 2 — THE REGRESSION (§4.8#17): the long form reaching the repo-root .env.
#     This is the audited line, byte for byte.
run_case "long-form ../.env is rejected" 1 'services:
  hearth:
    image: ghcr.io/hearth-auth/hearth:latest
    env_file:
      - path: ../.env
        required: false
' "" "" \
    "reaches outside deploy/"

# 3 — the same escape in the short list form must not slip past the parser.
run_case "short-form ../.env is rejected" 1 'services:
  hearth:
    image: ghcr.io/hearth-auth/hearth:latest
    env_file:
      - ../.env
' "" "" \
    "reaches outside deploy/"

# 4 — a .env beside the compose file is in scope by path but is still the
#     ecosystem catch-all, whose keys nothing in this repo constrains.
run_case "in-directory bare .env is rejected" 1 'services:
  hearth:
    image: ghcr.io/hearth-auth/hearth:latest
    env_file:
      - ./.env
' "" "" \
    "is a bare .env"

# 5 — no committed example means no schema, so no stated scope.
run_case "env file without an example is rejected" 1 'services:
  hearth:
    image: ghcr.io/hearth-auth/hearth:latest
    env_file:
      - ./hearth.env
' "" "" \
    "has no committed"

# 6 — an example that declares an out-of-scope key is exactly the leak the
#     finding describes, only written down.
run_case "out-of-scope key in the example is rejected" 1 'services:
  hearth:
    image: ghcr.io/hearth-auth/hearth:latest
    env_file:
      - ./hearth.env
' "hearth.env.example" '# Overrides.
HEARTH_BIND_ADDRESS=0.0.0.0
AWS_SECRET_ACCESS_KEY=
' \
    "which Hearth does not read"

# 7 — a compose file with no env_file at all is fine.
run_case "compose without env_file passes" 0 'services:
  hearth:
    image: ghcr.io/hearth-auth/hearth:latest
    environment:
      RUST_LOG: "info"
' "" "" \
    "OK: every shipped compose file"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} guard self-test failure(s)."
    exit 1
fi
echo "OK: ${case_n} guard self-tests passed."
exit 0
