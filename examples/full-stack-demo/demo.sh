#!/usr/bin/env bash
# demo.sh — One command to start the Hearth full-stack demo.
#
# What it does:
#   1. Builds the Hearth binary (release) if needed.
#   2. Starts Hearth on :8420 in --dev mode (in-memory storage).
#   3. Bootstraps the system realm and obtains an admin token.
#   4. Resolves the "demo" realm ID configured in hearth.yaml.
#   5. Writes .env files for frontend and backend.
#   6. Installs frontend dependencies (npm install) if node_modules is absent.
#   7. Starts the Go API backend on :8421.
#   8. Starts the Vite dev server on :5173.
#   9. Opens http://localhost:5173 — log in and explore.
#
# Demo users (viewer, editor, admin) are seeded by Hearth at startup via
# the seed_users block in hearth.yaml — no shell-side user creation needed.
#
# Idempotent: safe to re-run. Bootstrap is a no-op if Hearth is already up;
# user creation skips on 409; env files are overwritten with fresh values.
#
# Prerequisites: cargo, go, node, npm, curl, jq
#
# Usage:
#   cd examples/full-stack-demo && ./demo.sh
#   # or from repo root:
#   bash examples/full-stack-demo/demo.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# Respect CARGO_TARGET_DIR if set (common for shared build caches).
_cargo_target="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
HEARTH_BIN="$_cargo_target/release/hearth"
CONFIG="$HERE/hearth.yaml"

HEARTH_PORT="${HEARTH_PORT:-8420}"
BACKEND_PORT="${BACKEND_PORT:-8421}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
BASE="http://127.0.0.1:${HEARTH_PORT}"

HEARTH_PID=""
BACKEND_PID=""
FRONTEND_PID=""

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
  echo
  echo "▸ shutting down…"
  for pid_var in FRONTEND_PID BACKEND_PID HEARTH_PID; do
    local pid="${!pid_var:-}"
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  echo "  ✓ stopped"
}
trap cleanup EXIT

# ── Prerequisites ─────────────────────────────────────────────────────────────

for bin in cargo go node npm curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "✗ missing required tool: $bin" >&2
    exit 1
  fi
done

# ── Build ─────────────────────────────────────────────────────────────────────

echo "▸ building hearth (release)…"
(cd "$REPO_ROOT" && cargo build --release --bin hearth --quiet)
if [[ ! -f "$HEARTH_BIN" ]]; then
  echo "✗ binary not found at $HEARTH_BIN" >&2
  echo "  CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-<unset, expected $REPO_ROOT/target>}" >&2
  echo "  Run 'cargo build --release --bin hearth' in $REPO_ROOT" >&2
  exit 1
fi
echo "  ✓ build complete"

# ── Start Hearth ──────────────────────────────────────────────────────────────
# If a Hearth instance is already running, verify it was started with the demo
# config (i.e. the "demo" realm exists). If not — e.g. a leftover dev server
# from another session — kill it and restart with hearth.yaml.

start_hearth() {
  echo "▸ starting hearth on $BASE"
  "$HEARTH_BIN" serve \
    --dev \
    --config "$CONFIG" \
    --bind 127.0.0.1 \
    --port "$HEARTH_PORT" \
    >"$HERE/.hearth.log" 2>&1 &
  HEARTH_PID=$!

  echo -n "  waiting for server"
  for _ in {1..300}; do
    if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
    echo -n "."
    sleep 0.1
  done
  echo
  if ! curl -sf "$BASE/health" >/dev/null 2>&1; then
    echo "✗ hearth did not become healthy in 30 s — check .hearth.log" >&2
    exit 1
  fi
  echo "  ✓ server is healthy"
}

if curl -sf "$BASE/health" >/dev/null 2>&1; then
  # Running — check whether it has the demo realm (config-defined realms only
  # exist when started with the right hearth.yaml).
  _tmp=$(curl -sf -X POST "$BASE/admin/bootstrap" 2>/dev/null || echo '{}')
  _tok=$(echo "$_tmp" | jq -r '.access_token // empty' 2>/dev/null || true)
  _sys=$(echo "$_tmp" | jq -r '.realm_id // empty' 2>/dev/null || true)
  _has_demo=""
  if [[ -n "$_tok" && -n "$_sys" ]]; then
    _has_demo=$(
      curl -sf -H "Authorization: Bearer $_tok" -H "X-Realm-ID: $_sys" \
        "$BASE/admin/realms" 2>/dev/null \
      | jq -r '.items[]? | select(.name == "demo") | .id' \
      2>/dev/null || true
    )
  fi

  if [[ -n "$_has_demo" && "$_has_demo" != "null" ]]; then
    echo "▸ hearth already running on $BASE (demo realm present)"
  else
    echo "▸ hearth running without demo realm — restarting with demo config…"
    pkill -x hearth 2>/dev/null || pkill -f "hearth serve" 2>/dev/null || true
    # Wait for the port to free up.
    for _ in {1..40}; do
      curl -sf "$BASE/health" >/dev/null 2>&1 || break
      sleep 0.25
    done
    start_hearth
  fi
else
  start_hearth
fi

# ── Bootstrap ─────────────────────────────────────────────────────────────────

echo "▸ bootstrapping…"
BOOTSTRAP=$(curl -sf -X POST "$BASE/admin/bootstrap")
ADMIN_TOKEN=$(echo "$BOOTSTRAP" | jq -r '.access_token')
# The system realm ID is required as X-Realm-ID on admin API calls.
SYS_REALM_ID=$(echo "$BOOTSTRAP" | jq -r '.realm_id')

if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
  echo "✗ could not obtain admin token" >&2
  echo "Response: $BOOTSTRAP" >&2
  exit 1
fi
echo "  ✓ admin token acquired"

# ── Resolve demo realm ────────────────────────────────────────────────────────

echo "▸ resolving demo realm…"

# GET /admin/realms requires X-Realm-ID (system realm UUID) for auth context.
# The response uses the "items" field, not "realms".
REALM_ID=""
for _ in {1..20}; do
  REALM_ID=$(
    curl -sf \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "X-Realm-ID: $SYS_REALM_ID" \
      "$BASE/admin/realms" \
    | jq -r '.items[] | select(.name == "demo") | .id // empty' \
    2>/dev/null || true
  )
  [[ -n "$REALM_ID" && "$REALM_ID" != "null" ]] && break
  sleep 0.5
done

if [[ -z "$REALM_ID" || "$REALM_ID" == "null" ]]; then
  echo "✗ could not find 'demo' realm — is hearth.yaml in $HERE?" >&2
  echo "  Raw realm list:" >&2
  curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" -H "X-Realm-ID: $SYS_REALM_ID" \
    "$BASE/admin/realms" | jq . >&2 || true
  exit 1
fi
echo "  ✓ realm id: $REALM_ID"

# ── Write env files ───────────────────────────────────────────────────────────

echo "▸ writing env files…"

cat > "$HERE/frontend/.env" <<EOF
VITE_HEARTH_URL=http://localhost:${HEARTH_PORT}
VITE_REALM_SLUG=demo
VITE_REALM_ID=${REALM_ID}
VITE_CLIENT_ID=hearth-hub
VITE_API_URL=http://localhost:${BACKEND_PORT}
EOF
echo "  ✓ frontend/.env"

cat > "$HERE/backend/.env" <<EOF
HEARTH_URL=http://localhost:${HEARTH_PORT}
REALM_ID=demo
PORT=${BACKEND_PORT}
EOF
echo "  ✓ backend/.env"

# ── Frontend dependencies ─────────────────────────────────────────────────────

if [[ ! -d "$HERE/frontend/node_modules" ]]; then
  echo "▸ installing frontend dependencies…"
  (cd "$HERE/frontend" && npm install --silent)
  echo "  ✓ installed"
fi

# ── Start Go backend ──────────────────────────────────────────────────────────

echo "▸ starting Go backend on :${BACKEND_PORT}…"
# shellcheck disable=SC1091  # .env sourced at runtime, not present at lint time
(cd "$HERE/backend" && set -a && source .env && set +a && go run . >"$HERE/.backend.log" 2>&1) &
BACKEND_PID=$!

echo -n "  waiting for backend"
for _ in {1..100}; do
  if curl -sf "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null 2>&1; then break; fi
  echo -n "."
  sleep 0.2
done
echo
if ! curl -sf "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null 2>&1; then
  echo "✗ backend did not start — check .backend.log" >&2
  exit 1
fi
echo "  ✓ backend is healthy"

# ── Start Vite dev server ─────────────────────────────────────────────────────

echo "▸ starting frontend on :${FRONTEND_PORT}…"
(cd "$HERE/frontend" && npm run dev -- --port "${FRONTEND_PORT}" >"$HERE/.frontend.log" 2>&1) &
FRONTEND_PID=$!

echo -n "  waiting for frontend"
for _ in {1..100}; do
  if curl -sf "http://127.0.0.1:${FRONTEND_PORT}" >/dev/null 2>&1; then break; fi
  echo -n "."
  sleep 0.2
done
echo
if ! curl -sf "http://127.0.0.1:${FRONTEND_PORT}" >/dev/null 2>&1; then
  echo "✗ frontend did not start — check .frontend.log" >&2
  exit 1
fi
echo "  ✓ frontend is up"

# ── Ready ─────────────────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Hearth Hub is ready →  http://localhost:${FRONTEND_PORT}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "  Demo users (password: HearthTest123!)"
echo "  viewer@hearth.test  — read-only"
echo "  editor@hearth.test  — can create notes"
echo "  admin@hearth.test   — full access + users tab"
echo
echo "  Hearth admin:  http://localhost:${HEARTH_PORT}/ui/admin/login"
echo "  Mail catcher:  http://localhost:${HEARTH_PORT}/dev/mail"
echo "  Logs:          .hearth.log  .backend.log  .frontend.log"
echo
echo "  Press Ctrl-C to stop everything."
echo

# Wait for any child to exit (Ctrl-C triggers cleanup via trap).
wait
