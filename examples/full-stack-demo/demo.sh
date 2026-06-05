#!/usr/bin/env bash
# Full-stack Hearth demo — single-command bootstrap + start.
#
#   ./demo.sh
#
# What happens:
#   1. Builds the Hearth binary (release profile).
#   2. Starts Hearth in the background on :8420, using hearth.yaml.
#   3. Bootstraps the demo realm and retrieves the admin token.
#   4. Creates the OAuth client and seeds three demo users.
#   5. Starts the Go backend on :8080.
#   6. Starts the Vite frontend on :5173.
#
# Pre-requisites: go (1.21+), node (18+), npm, cargo.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
HEARTH_PORT="${HEARTH_PORT:-8420}"
HEARTH_URL="http://localhost:${HEARTH_PORT}"
BACKEND_PORT="${BACKEND_PORT:-8080}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
HEARTH_LOG="$HERE/.hearth.log"
BACKEND_LOG="$HERE/.backend.log"
FRONTEND_LOG="$HERE/.frontend.log"

HEARTH_PID=""
BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  for pid in "$HEARTH_PID" "$BACKEND_PID" "$FRONTEND_PID"; do
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

wait_for() {
  local url="$1" label="$2" attempts=60
  echo -n "  waiting for $label"
  until curl -sfo /dev/null "$url"; do
    ((attempts--)) || {
      echo " ✖ timed out"
      exit 1
    }
    echo -n "."
    sleep 0.5
  done
  echo " ✔"
}

# ── 1. Build Hearth ──────────────────────────────────────────────────────────
echo "==> Building Hearth binary…"
(cd "$REPO_ROOT" && cargo build --release -q)
HEARTH_BIN="$REPO_ROOT/target/release/hearth"

# ── 2. Start Hearth ──────────────────────────────────────────────────────────
echo "==> Starting Hearth on :${HEARTH_PORT}…"
DATA_DIR="$HERE/data"
mkdir -p "$DATA_DIR"
HEARTH_DATA_DIR="$DATA_DIR" "$HEARTH_BIN" serve --dev --config "$HERE/hearth.yaml" \
  >"$HEARTH_LOG" 2>&1 &
HEARTH_PID=$!
wait_for "$HEARTH_URL/health" "Hearth"

# ── 3. Bootstrap realm + get admin token ─────────────────────────────────────
echo "==> Bootstrapping demo realm…"
BOOTSTRAP=$(curl -sf -X POST "$HEARTH_URL/admin/bootstrap")
ADMIN_TOKEN=$(echo "$BOOTSTRAP" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
REALM_ID=$(echo "$BOOTSTRAP"   | python3 -c "import json,sys; print(json.load(sys.stdin)['realm_id'])")

echo "  realm_id: $REALM_ID"

# ── 4. Seed demo users ───────────────────────────────────────────────────────
echo "==> Seeding demo users…"
seed_user() {
  local email="$1" display="$2" role="$3"
  local password="HearthTest123!"
  local resp
  resp=$(curl -sf -X POST "$HEARTH_URL/admin/realms/$REALM_ID/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"display_name\":\"$display\",\"password\":\"$password\"}" \
    2>/dev/null || true)
  local uid
  uid=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || true)
  if [[ -z "$uid" ]]; then
    echo "  [skip] $email (already exists)"
    return
  fi
  # assign role
  curl -sf -X POST "$HEARTH_URL/admin/realms/$REALM_ID/users/$uid/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"role\":\"$role\"}" >/dev/null 2>&1 || true
  echo "  created $email ($role)"
}

seed_user "viewer@hearth.test"  "Viewer User"  "viewer"
seed_user "editor@hearth.test"  "Editor User"  "editor"
seed_user "admin@hearth.test"   "Admin User"   "admin"

# ── 5. Write backend .env ────────────────────────────────────────────────────
echo "==> Writing backend/.env…"
cat >"$HERE/backend/.env" <<ENV
HEARTH_URL=${HEARTH_URL}
REALM_ID=${REALM_ID}
PORT=${BACKEND_PORT}
ENV

# ── 6. Write frontend .env ───────────────────────────────────────────────────
echo "==> Writing frontend/.env…"
cat >"$HERE/frontend/.env" <<ENV
VITE_HEARTH_URL=${HEARTH_URL}
VITE_REALM=${REALM_ID}
VITE_CLIENT_ID=hearth-hub
ENV

# ── 7. Build + start Go backend ──────────────────────────────────────────────
echo "==> Building Go backend…"
(cd "$HERE/backend" && go build -o hearth-demo-backend .)
echo "==> Starting backend on :${BACKEND_PORT}…"
"$HERE/backend/hearth-demo-backend" >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
wait_for "http://localhost:${BACKEND_PORT}/health" "backend"

# ── 8. Install + start Vite frontend ────────────────────────────────────────
echo "==> Installing frontend dependencies…"
(cd "$HERE/frontend" && npm install --silent)
echo "==> Starting frontend on :${FRONTEND_PORT}…"
(cd "$HERE/frontend" && npm run dev -- --port "$FRONTEND_PORT" --host 127.0.0.1) \
  >"$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!
wait_for "http://localhost:${FRONTEND_PORT}" "frontend"

# ── 9. Open browser ──────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Hearth Full-Stack Demo is running!                  ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Frontend  http://localhost:${FRONTEND_PORT}                   ║"
echo "║  Backend   http://localhost:${BACKEND_PORT}                    ║"
echo "║  Hearth    ${HEARTH_URL}                  ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Demo credentials (password: HearthTest123!)         ║"
echo "║    viewer@hearth.test  — viewer role                 ║"
echo "║    editor@hearth.test  — editor role                 ║"
echo "║    admin@hearth.test   — admin role                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Press Ctrl-C to stop all services."

# Keep running until interrupted
wait "$HEARTH_PID"
