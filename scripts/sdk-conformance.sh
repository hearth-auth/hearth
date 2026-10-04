#!/usr/bin/env bash
# sdk-conformance.sh — run the shared SDK conformance scenarios
# (sdks/conformance/) against live `hearth serve --dev` servers.
#
# Usage:
#   bash scripts/sdk-conformance.sh [--sdk <name>]...
#
#   HEARTH_BIN=<path>   use this hearth binary (built with dev-endpoints)
#                       instead of building one
#
# Boots three servers from empty directories (so no contributor hearth.yaml is
# picked up — see sdk-smoke-local.sh step 2):
#   main      realm `conformance` with a client-credentials client `m2m` (also
#             allowed token exchange) and the protected resource
#             https://api.example.com
#   expiry    the same, with 1 s access tokens (the `expired` scenario; the
#             server's per-realm TTL does not reach client-credentials tokens)
#   audience  the same, minting access tokens for audience `other-api` (the
#             default-audience scenario)
# then hands over to scripts/sdk_conformance.py.
# Called by: make sdk-conformance, scripts/sdk-smoke-local.sh, CI.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDS=()
DIRS=()

cleanup() {
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    for dir in "${DIRS[@]}"; do rm -rf "$dir"; done
}
trap cleanup EXIT

free_port() {
    python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"
}

if [[ -z "${HEARTH_BIN:-}" ]]; then
    echo "==> Building hearth (debug, dev-endpoints)"
    (cd "$REPO_ROOT" && PROTOC="${PROTOC:-protoc}" cargo build --features dev-endpoints)
    HEARTH_BIN="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/hearth"
fi

# Writes a config into a fresh directory and boots `serve --dev` from it.
# Sets BOOT_URL. Not run in a subshell, so PIDS and DIRS reach cleanup().
boot() {
    local name="$1" token_block="$2"
    local dir port
    dir="$(mktemp -d)"
    DIRS+=("$dir")
    port="$(free_port)"
    cat > "$dir/conformance.yaml" <<EOF
${token_block}
realms:
  conformance:
    auth:
      mfa_required: false
    applications:
      m2m:
        name: "Conformance M2M"
        confidential: true
        client_secret: "conformance-secret-not-for-production"
        grant_types:
          - client_credentials
          - "urn:ietf:params:oauth:grant-type:token-exchange"
    protected_resources:
      - resource_uri: "https://api.example.com"
        display_name: "Conformance API"
EOF
    ( cd "$dir" && exec "$HEARTH_BIN" serve --dev --bind "127.0.0.1:$port" \
        --config "$dir/conformance.yaml" ) > "$dir/hearth.log" 2>&1 &
    PIDS+=("$!")
    for _ in $(seq 1 120); do
        if python3 -c "import urllib.request,sys; urllib.request.urlopen(sys.argv[1], timeout=1)" \
            "http://127.0.0.1:$port/health" 2>/dev/null; then
            BOOT_URL="http://127.0.0.1:$port"
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $name server did not become healthy; log:" >&2
    tail -40 "$dir/hearth.log" >&2
    return 1
}

echo "==> Booting hearth servers"
boot main ""
MAIN_URL="$BOOT_URL"
boot expiry 'token:
  access_token_ttl: "1s"'
EXPIRY_URL="$BOOT_URL"
boot audience 'token:
  audience: "other-api"'
AUDIENCE_URL="$BOOT_URL"
echo "    main=$MAIN_URL expiry=$EXPIRY_URL audience=$AUDIENCE_URL"

PY=(python3)
if ! python3 -c "import yaml" 2>/dev/null; then
    PY=(uv run --quiet --with pyyaml python3)
fi
"${PY[@]}" "$REPO_ROOT/scripts/sdk_conformance.py" \
    --main-url "$MAIN_URL" --expiry-url "$EXPIRY_URL" --audience-url "$AUDIENCE_URL" "$@"
