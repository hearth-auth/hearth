#!/usr/bin/env bash
# demo.sh — One command to start the Hearth full-stack demo.
#
# What it does:
#   1. Builds the Hearth binary (release) if needed.
#   2. Starts Hearth on :8420 in --dev mode (in-memory storage).
#   3. Bootstraps the system realm and obtains an admin token.
#   4. Resolves the "demo" realm ID configured in hearth.yaml.
#   5. Seeds three demo users with roles (viewer, editor, admin).
#   6. Writes .env files for frontend and backend.
#   7. Installs frontend dependencies (npm install) if node_modules is absent.
#   8. Starts the Go API backend on :8421.
#   9. Starts the Vite dev server on :5173.
#  10. Opens http://localhost:5173 — log in and explore.
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
  _has_demo=""
  if [[ -n "$_tok" ]]; then
    _has_demo=$(
      curl -sf -H "Authorization: Bearer $_tok" "$BASE/admin/realms" 2>/dev/null \
      | jq -r '.realms[]? | select(.name == "demo" or .slug == "demo") | .id' \
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

if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
  echo "✗ could not obtain admin token" >&2
  echo "Response: $BOOTSTRAP" >&2
  exit 1
fi
echo "  ✓ admin token acquired"

# ── Resolve demo realm ────────────────────────────────────────────────────────

echo "▸ resolving demo realm…"

# Retry a few times — the realm is created from hearth.yaml on startup but
# may not be visible immediately if the server just started.
REALM_ID=""
for _ in {1..20}; do
  REALM_ID=$(
    curl -sf \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      "$BASE/admin/realms" \
    | jq -r '.realms[] | select(.name == "demo" or .slug == "demo") | .id // empty' \
    2>/dev/null || true
  )
  [[ -n "$REALM_ID" && "$REALM_ID" != "null" ]] && break
  sleep 0.5
done

if [[ -z "$REALM_ID" || "$REALM_ID" == "null" ]]; then
  echo "✗ could not find 'demo' realm — is hearth.yaml in $HERE?" >&2
  echo "  Raw realm list:" >&2
  curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE/admin/realms" | jq . >&2 || true
  exit 1
fi
echo "  ✓ realm id: $REALM_ID"

# ── Seed users ────────────────────────────────────────────────────────────────

create_user() {
  local email="$1" display_name="$2"
  local body
  body=$(jq -n \
    --arg email "$email" --arg name "$display_name" --arg pw "HearthTest123!" \
    '{email: $email, display_name: $name, password: $pw, email_verified: true}')
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" -d "$body" \
    "$BASE/admin/realms/$REALM_ID/users")
  case "$status" in
    200|201) echo "  ✓ created $email" ;;
    409)     echo "  · $email already exists" ;;
    *)       echo "✗ HTTP $status creating $email" >&2; exit 1 ;;
  esac
}

echo "▸ seeding users…"
create_user "viewer@hearth.test" "Vera Viewer"
create_user "editor@hearth.test" "Ed Editor"
create_user "admin@hearth.test"  "Ada Admin"

# ── Assign roles ──────────────────────────────────────────────────────────────

assign_role() {
  local email="$1" role="$2"
  local user_id
  user_id=$(curl -sf \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE/admin/realms/$REALM_ID/users?email=$( \
      python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
        "$email" 2>/dev/null || printf '%s' "$email")" \
    | jq -r '.users[0].id // empty')
  [[ -z "$user_id" ]] && { echo "✗ user not found: $email" >&2; exit 1; }
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg r "$role" '{role: $r}')" \
    "$BASE/admin/realms/$REALM_ID/users/$user_id/roles")
  case "$status" in
    200|201|204|409) echo "  ✓ $email → $role" ;;
    *)               echo "✗ HTTP $status assigning $role to $email" >&2; exit 1 ;;
  esac
}

echo "▸ assigning roles…"
assign_role "viewer@hearth.test" "viewer"
assign_role "editor@hearth.test" "editor"
assign_role "admin@hearth.test"  "admin"

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
(cd "$HERE/backend" && go run . >"$HERE/.backend.log" 2>&1) &
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
