#!/usr/bin/env bash
# Start a Hearth dev server for SDK integration tests.
#
# Usage:
#   ./start-server.sh [PORT]
#
# Builds the hearth binary, starts it in dev mode, waits for the health check,
# then prints the PID, port, URL and the server's working directory.
# Kill the server with: kill $PID    then: rm -rf $DATA_DIR
#
# Environment:
#   CARGO_TARGET_DIR — if set, the hearth binary is read from $CARGO_TARGET_DIR/debug/hearth

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Resolve binary path
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
HEARTH_BIN="$TARGET_DIR/debug/hearth"

# Build if needed
echo "Building hearth..." >&2
cargo build --bin hearth --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1 >/dev/null

# Find a free port or use the provided one
PORT="${1:-0}"
if [ "$PORT" = "0" ]; then
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
fi

# Start the server.
#
# RUN_DIR is the server's working directory. This script exits while the server
# keeps running, so it cannot remove RUN_DIR itself — it prints the path and the
# caller removes it after `kill $pid`.
RUN_DIR="$(mktemp -d -t hearth-sdk-server-XXXXXX)"
# Audit 2026-08-28 §4.12#13: launch from a directory this script created.
# `serve --dev` with no `--config` auto-detects a `hearth.yaml` in the working
# directory, and CLAUDE.md tells every contributor to make one. The shipped
# example sets `oidc.issuer: https://auth.example.com`, so tokens then carry
# `iss=https://auth.example.com/...` instead of the local port and JWKS lookups
# leave the machine.
( cd "$RUN_DIR" && RUST_LOG=warn exec "$HEARTH_BIN" serve --dev --port "$PORT" ) &
SERVER_PID=$!

# Wait for health check
MAX_WAIT=15
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  if curl -sf "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then
    echo "port=$PORT"
    echo "pid=$SERVER_PID"
    echo "url=http://127.0.0.1:$PORT"
    echo "data_dir=$RUN_DIR"
    exit 0
  fi
  sleep 0.1
  WAITED=$((WAITED + 1))
done

echo "ERROR: Hearth server did not start within ${MAX_WAIT}s" >&2
kill "$SERVER_PID" 2>/dev/null || true
rm -rf "$RUN_DIR"
exit 1
