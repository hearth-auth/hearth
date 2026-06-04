#!/usr/bin/env bash
# demo.sh — Bootstrap and start the Hearth full-stack demo.
#
# What it does:
#   1. Builds the Hearth binary (release).
#   2. Starts Hearth on :8420 with --dev (in-memory storage).
#   3. Bootstraps the system realm and obtains an admin token.
#   4. Seeds three demo users with roles (viewer, editor, admin).
#   5. Leaves Hearth running for Phase 2/3 frontend + backend development.
#      Press Ctrl-C to stop.
#
# Idempotent: safe to run more than once. Bootstrap is a no-op if already done;
# user-creation skips (HTTP 409) and role-assignment is re-applied harmlessly.
#
# Prerequisites: cargo, curl, jq
#
# Usage:
#   cd examples/full-stack-demo
#   ./demo.sh
#
# Or from the repo root:
#   bash examples/full-stack-demo/demo.sh
#
# Ports:
#   Hearth     http://localhost:8420
#   Frontend   http://localhost:5173  (Phase 2 — Vite dev server)
#   Backend    http://localhost:8421  (Phase 3 — API server)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
HEARTH_BIN="$REPO_ROOT/target/release/hearth"
CONFIG="$HERE/hearth.yaml"

HEARTH_PORT="${HEARTH_PORT:-8420}"
BASE="http://127.0.0.1:${HEARTH_PORT}"

# ── Prerequisites ─────────────────────────────────────────────────────────────

for bin in cargo curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "✗ missing required tool: $bin" >&2
    exit 1
  fi
done

# ── Build ─────────────────────────────────────────────────────────────────────

echo "▸ building hearth (release)…"
(cd "$REPO_ROOT" && cargo build --release --bin hearth --quiet)
echo "  ✓ build complete"

# ── Start server ──────────────────────────────────────────────────────────────

# Check whether a Hearth instance is already listening so the script is safe
# to run again without killing the existing server.
if curl -sf "$BASE/health" >/dev/null 2>&1; then
  echo "▸ hearth already running on $BASE — skipping start"
  HEARTH_ALREADY_RUNNING=1
else
  HEARTH_ALREADY_RUNNING=0
  echo "▸ starting hearth on $BASE"
  "$HEARTH_BIN" serve \
    --dev \
    --config "$CONFIG" \
    --bind 127.0.0.1 \
    --port "$HEARTH_PORT" &
  HEARTH_PID=$!

  # Graceful shutdown on Ctrl-C / script exit (only when we started the server).
  cleanup() {
    echo
    echo "▸ stopping hearth (pid $HEARTH_PID)…"
    kill "$HEARTH_PID" 2>/dev/null || true
    wait "$HEARTH_PID" 2>/dev/null || true
    echo "  ✓ stopped"
  }
  trap cleanup EXIT

  # Wait up to 30 s for the server to become healthy.
  echo -n "  waiting for server"
  for _ in {1..300}; do
    if curl -sf "$BASE/health" >/dev/null 2>&1; then
      break
    fi
    echo -n "."
    sleep 0.1
  done
  echo
  if ! curl -sf "$BASE/health" >/dev/null 2>&1; then
    echo "✗ hearth did not become healthy in 30 s" >&2
    exit 1
  fi
  echo "  ✓ server is healthy"
fi

# ── Bootstrap ─────────────────────────────────────────────────────────────────

echo "▸ bootstrapping system realm…"
BOOTSTRAP=$(curl -sf -X POST "$BASE/admin/bootstrap" || true)

if [[ -z "$BOOTSTRAP" ]]; then
  echo "  ✓ already bootstrapped — fetching stored admin token via re-bootstrap"
  # Bootstrap is idempotent: calling it again returns the existing token.
  BOOTSTRAP=$(curl -sf -X POST "$BASE/admin/bootstrap")
fi

ADMIN_TOKEN=$(echo "$BOOTSTRAP" | jq -r '.access_token')

if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
  echo "✗ could not obtain admin token from bootstrap response" >&2
  echo "Response: $BOOTSTRAP" >&2
  exit 1
fi

echo "  ✓ admin token acquired"

# ── Resolve demo realm ID ──────────────────────────────────────────────────────

echo "▸ resolving demo realm…"
REALM_ID=$(
  curl -sf \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE/admin/realms" \
  | jq -r '.realms[] | select(.name == "demo") | .id'
)

if [[ -z "$REALM_ID" || "$REALM_ID" == "null" ]]; then
  echo "✗ could not find 'demo' realm — check hearth.yaml realms config" >&2
  exit 1
fi

echo "  ✓ demo realm id: $REALM_ID"

# ── Seed users ────────────────────────────────────────────────────────────────
# Creates three demo users. HTTP 409 (already exists) is treated as success so
# repeated runs are safe.

create_user() {
  local email="$1"
  local display_name="$2"
  local password="HearthTest123!"

  local body
  body=$(jq -n \
    --arg email "$email" \
    --arg name "$display_name" \
    --arg pw "$password" \
    '{email: $email, display_name: $name, password: $pw, email_verified: true}')

  local http_status
  http_status=$(
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "$BASE/admin/realms/$REALM_ID/users"
  )

  case "$http_status" in
    200|201) echo "  ✓ created $email" ;;
    409)     echo "  · $email already exists — skipping" ;;
    *)
      echo "✗ unexpected HTTP $http_status creating $email" >&2
      exit 1
      ;;
  esac
}

echo "▸ seeding demo users…"
create_user "viewer@hearth.test"  "Vera Viewer"
create_user "editor@hearth.test"  "Ed Editor"
create_user "admin@hearth.test"   "Ada Admin"

# ── Assign roles ──────────────────────────────────────────────────────────────

assign_role() {
  local email="$1"
  local role="$2"

  # Resolve user ID from email.
  local user_id
  user_id=$(
    curl -sf \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      "$BASE/admin/realms/$REALM_ID/users?email=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$email" 2>/dev/null || echo "$email")" \
    | jq -r '.users[0].id // empty'
  )

  if [[ -z "$user_id" ]]; then
    echo "✗ could not resolve user id for $email" >&2
    exit 1
  fi

  local body
  body=$(jq -n --arg role "$role" '{role: $role}')

  local http_status
  http_status=$(
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "$BASE/admin/realms/$REALM_ID/users/$user_id/roles"
  )

  case "$http_status" in
    200|201|204|409) echo "  ✓ $email → $role" ;;
    *)
      echo "✗ unexpected HTTP $http_status assigning role $role to $email" >&2
      exit 1
      ;;
  esac
}

echo "▸ assigning roles…"
assign_role "viewer@hearth.test"  "viewer"
assign_role "editor@hearth.test"  "editor"
assign_role "admin@hearth.test"   "admin"

# ── Summary ───────────────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Hearth full-stack demo is ready"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "  Hearth URL:   $BASE"
echo "  Admin UI:     $BASE/ui/admin/login"
echo "  Mail UI:      $BASE/dev/mail"
echo "  OIDC issuer:  $BASE"
echo
echo "  Demo users (password: HearthTest123!)"
echo "  ┌──────────────────────────┬────────┐"
echo "  │ Email                    │ Role   │"
echo "  ├──────────────────────────┼────────┤"
echo "  │ viewer@hearth.test       │ viewer │"
echo "  │ editor@hearth.test       │ editor │"
echo "  │ admin@hearth.test        │ admin  │"
echo "  └──────────────────────────┴────────┘"
echo
echo "  Frontend (Phase 2):  cd frontend && npm install && npm run dev"
echo "  Backend  (Phase 3):  cd backend  && cargo run"
echo

if [[ "$HEARTH_ALREADY_RUNNING" -eq 0 ]]; then
  echo "  Press Ctrl-C to stop Hearth."
  echo
  # Keep running so the dev can interact with the live server.
  wait "$HEARTH_PID" 2>/dev/null || true
fi
