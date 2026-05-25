#!/usr/bin/env bash
# CI gate: verify every cluster admin route documented in docs/guides/clustering.md
# is registered in the built binary.
#
# Routes return 503 in single-node --dev mode (expected — the cluster engine is
# absent but the routes ARE wired up). The gate fails if any route returns 404,
# which would mean the route is missing from the router entirely.
#
# Usage:
#   ./scripts/check-cluster-routes.sh            # auto-builds debug binary
#   BINARY=./target/release/hearth ./scripts/check-cluster-routes.sh

set -euo pipefail

BINARY=${BINARY:-./target/debug/hearth}
HOST=127.0.0.1
PORT=18420  # non-standard port to avoid conflicts with a running dev server

DATA_DIR=$(mktemp -d)
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT INT TERM

echo "=== Cluster Admin Route Presence Gate ==="
echo ""

if [ ! -f "$BINARY" ]; then
    echo "Binary not found at $BINARY — building (debug)..."
    cargo build 2>&1 | tail -5
fi

echo "Starting hearth in single-node dev mode on port $PORT..."
"$BINARY" serve --dev --port "$PORT" --data-dir "$DATA_DIR" \
    2>"$DATA_DIR/server.log" &
SERVER_PID=$!

echo -n "Waiting for server health check"
for i in $(seq 1 30); do
    if curl -sf "http://$HOST:$PORT/health" >/dev/null 2>&1; then
        echo " — ready."
        break
    fi
    echo -n "."
    sleep 1
    if [ "$i" -eq 30 ]; then
        echo " TIMED OUT" >&2
        echo "Server log:" >&2
        tail -20 "$DATA_DIR/server.log" >&2
        exit 1
    fi
done

echo "Bootstrapping dev realm to obtain admin credentials..."
BOOTSTRAP=$(curl -sf -X POST "http://$HOST:$PORT/admin/bootstrap")
TOKEN=$(echo "$BOOTSTRAP" | jq -r '.access_token')
REALM_ID=$(echo "$BOOTSTRAP" | jq -r '.realm_id')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "ERROR: failed to obtain admin token from bootstrap response." >&2
    echo "Bootstrap response: $BOOTSTRAP" >&2
    exit 1
fi

echo "Testing documented cluster admin routes..."
echo ""

PASS=0
FAIL=0

check_route() {
    local method=$1
    local path=$2
    local http_status
    http_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X "$method" \
        -H "Authorization: Bearer $TOKEN" \
        -H "X-Realm-ID: $REALM_ID" \
        "http://$HOST:$PORT$path")
    if [ "$http_status" = "404" ]; then
        printf "  FAIL  %-6s %-45s HTTP %s (route not registered)\n" \
            "$method" "$path" "$http_status" >&2
        FAIL=$((FAIL + 1))
    else
        printf "  pass  %-6s %-45s HTTP %s\n" "$method" "$path" "$http_status"
        PASS=$((PASS + 1))
    fi
}

check_route POST /admin/cluster/bootstrap
check_route GET  /admin/cluster/status
check_route POST /admin/cluster/transfer-leadership

echo ""
echo "Results: $PASS passed, $FAIL failed."
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "FAILED: $FAIL cluster admin route(s) returned 404." >&2
    echo "" >&2
    echo "Routes are not registered in the binary. To fix:" >&2
    echo "  - If the route was added: re-run after 'cargo build'" >&2
    echo "  - If the route was removed: update docs/guides/clustering.md" >&2
    echo "    to remove or label it as planned." >&2
    exit 1
fi

echo "All documented cluster admin routes are registered in the binary."
