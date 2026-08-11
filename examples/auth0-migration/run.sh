#!/usr/bin/env bash
# run.sh — End-to-end Auth0 migration smoke test.
#
# 1. Migrates sample-bundle.json into a fresh temp directory.
# 2. Boots hearth --dev pointing at that directory.
# 3. Runs verify.mjs to confirm migrated users, permissions, and JWKS.
# 4. Tears down the server and temp directory on exit (pass or fail).
#
# Prerequisites: cargo, node (≥18), curl, jq
#
# Usage:
#   cd examples/auth0-migration
#   ./run.sh
#
# Or from the repo root:
#   bash examples/auth0-migration/run.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# ── Sanity: required toolchain ─────────────────────────────────────────────────

for bin in cargo node curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required tool: $bin" >&2
    exit 1
  fi
done

NODE_MAJOR="$(node -e 'process.stdout.write(process.version.replace(/^v/, "").split(".")[0])')"
if (( NODE_MAJOR < 18 )); then
  echo "Node.js 18+ required (found $(node --version))" >&2
  exit 1
fi

# ── Temp directory + server state ─────────────────────────────────────────────

DATA_DIR="$(mktemp -d -t hearth-auth0-migration-XXXXXX)"
PORT="${HEARTH_PORT:-8431}"   # avoid clashing with the default 8420 dev port
BASE="http://127.0.0.1:${PORT}"
# Resolve the target directory rather than assuming ./target — a repo-wide
# CARGO_TARGET_DIR (or a workspace target override) puts the binary elsewhere,
# and a hardcoded path fails with a bare "command not found" (HEA-2143).
TARGET_DIR="$(cd "$REPO_ROOT" && \
  cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' \
  2>/dev/null || echo "$REPO_ROOT/target")"
HEARTH_BIN="$TARGET_DIR/release/hearth"

cleanup() {
  if [[ -n "${HEARTH_PID:-}" ]] && kill -0 "$HEARTH_PID" 2>/dev/null; then
    kill "$HEARTH_PID" 2>/dev/null || true
    wait "$HEARTH_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

# ── Build ──────────────────────────────────────────────────────────────────────

echo "▸ building hearth (release)"
(cd "$REPO_ROOT" && cargo build --release --bin hearth --quiet)

# ── Migrate ───────────────────────────────────────────────────────────────────

echo "▸ running auth0 migration (data dir: $DATA_DIR)"
MIGRATE_OUTPUT="$(
  "$HEARTH_BIN" migrate auth0 \
    --file "$HERE/sample-bundle.json" \
    --data-dir "$DATA_DIR" 2>&1
)"
echo "$MIGRATE_OUTPUT"

# Parse the realm UUID printed by `print_migration_report`. The line carries a
# tracing timestamp/level prefix and the id renders with a `realm_` prefix:
#   00:51:23  INFO hearth:   realm:   realm_7b5d9f26-3c8a-4b1e-a6f2-2d08e7c81045
# Positional awk picked up "INFO" instead, so match the UUID shape directly.
MIGRATED_REALM_ID="$(
  echo "$MIGRATE_OUTPUT" \
    | grep -E 'realm:' \
    | grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' \
    | head -n 1
)"
if [[ -z "$MIGRATED_REALM_ID" ]]; then
  echo "ERROR: could not parse realm UUID from migration output" >&2
  echo "Full output:" >&2
  echo "$MIGRATE_OUTPUT" >&2
  exit 1
fi
echo "  migrated realm UUID: $MIGRATED_REALM_ID"

# ── Boot server ────────────────────────────────────────────────────────────────

echo "▸ starting hearth --dev on port $PORT"
# HEARTH_DEV_DATA_DIR tells hearth serve --dev to use our migrated data dir
# instead of the default ephemeral temp directory.
# Run from the data dir, NOT from this example directory. `hearth.yaml` here is
# an annotated *production* reference for the migration guide (0.0.0.0 bind, TLS
# paths under /etc) — config auto-discovery picks it up from the working
# directory and then refuses to boot under --dev. --dev plus the flags below
# fully specify this server, so keep discovery away from it (HEA-2143).
(
  cd "$DATA_DIR" || exit 1
  HEARTH_DEV_DATA_DIR="$DATA_DIR" \
    exec "$HEARTH_BIN" serve \
      --dev \
      --bind 127.0.0.1 \
      --port "$PORT" \
      >"$DATA_DIR/hearth.log" 2>&1
) &
HEARTH_PID=$!

# Wait for the server to become healthy (up to 30 s).
for _ in {1..300}; do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if ! curl -sf "$BASE/health" >/dev/null 2>&1; then
  echo "ERROR: hearth did not become healthy in time" >&2
  tail -n 50 "$DATA_DIR/hearth.log" >&2 || true
  exit 1
fi
echo "  server is healthy"

# ── Verify ────────────────────────────────────────────────────────────────────

echo "▸ running verify.mjs"
BASE="$BASE" \
  MIGRATED_REALM_ID="$MIGRATED_REALM_ID" \
  node "$HERE/verify.mjs"

echo
echo "▸ smoke test passed"
