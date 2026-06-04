#!/usr/bin/env bash
# End-to-end Keycloak migration example.
#
#   ./run.sh
#
# What happens:
#   1. `cargo build` (release profile) — may take a while on first run.
#   2. Creates a fresh temp data dir via mktemp -d (cleaned up on exit).
#   3. Runs `hearth migrate keycloak` to import sample-export.json.
#   4. Starts Hearth in the background (--dev, HTTP 8420).
#   5. Runs verify.mjs: logs in as a migrated user, checks roles + JWKS.
#   6. Kills Hearth and exits with the verify script's status code.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
HEARTH_LOG="$HERE/.hearth.log"
HEARTH_PID=""
DATA_DIR=""

cleanup() {
  if [[ -n "$HEARTH_PID" ]] && kill -0 "$HEARTH_PID" 2>/dev/null; then
    kill "$HEARTH_PID" 2>/dev/null || true
    wait "$HEARTH_PID" 2>/dev/null || true
  fi
  if [[ -n "$DATA_DIR" && -d "$DATA_DIR" ]]; then
    rm -rf "$DATA_DIR"
  fi
}
trap cleanup EXIT INT TERM

wait_for() {
  local url="$1" attempts=60
  until curl -sfo /dev/null "$url"; do
    ((attempts--)) || {
      echo "✖ timed out waiting for $url"
      [[ -f "$HEARTH_LOG" ]] && tail -n 40 "$HEARTH_LOG"
      exit 1
    }
    sleep 0.5
  done
}

echo "▸ cargo build (hearth binary)"
(cd "$REPO_ROOT" && cargo build --release --quiet --bin hearth)

# Resolve the target directory — respects CARGO_TARGET_DIR if set.
TARGET_DIR="$(cd "$REPO_ROOT" && \
  cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' \
  2>/dev/null || echo "$REPO_ROOT/target")"
HEARTH_BIN="$TARGET_DIR/release/hearth"
if [[ ! -x "$HEARTH_BIN" ]]; then
  echo "✖ expected hearth binary at $HEARTH_BIN — did cargo build actually produce one?"
  exit 1
fi

echo "▸ creating temp data dir"
DATA_DIR="$(mktemp -d)"

echo "▸ running Keycloak migration"
"$HEARTH_BIN" migrate keycloak \
  --file "$HERE/sample-export.json" \
  --data-dir "$DATA_DIR"

echo "▸ starting Hearth (--dev, HTTP 8420)"
# HEARTH_DEV_DATA_DIR tells the server to use the migrated store instead
# of its default ephemeral tempdir. --dev enables the bootstrap endpoint
# (A-6), dev-mode JWKS rate limiting (A-10), and skips the 30-day slug
# cooldown (A-5) that would otherwise block re-importing the same realm.
(
  cd "$HERE"
  HEARTH_DEV_DATA_DIR="$DATA_DIR" \
    "$HEARTH_BIN" serve --dev --config "$HERE/hearth.yaml" \
    >"$HEARTH_LOG" 2>&1 &
  echo $! >"$HERE/.hearth.pid"
)
HEARTH_PID="$(cat "$HERE/.hearth.pid")"
rm -f "$HERE/.hearth.pid"
wait_for "http://127.0.0.1:8420/health"

echo "▸ running verify.mjs"
(cd "$HERE" && node verify.mjs)
