#!/usr/bin/env bash
# run-integration.sh — boot the full-stack demo and run the HEA-2056
# reference-integration Playwright suite against it, then tear everything down.
#
# It REUSES the demo's own launcher (examples/full-stack-demo/demo.sh) to bring
# up Hearth (:8420 --dev), the Go backend (:8421), and Vite (:5173) exactly the
# way a developer would — no forked boot logic. It only layers on the env the
# tests need (a known mailcatcher password, the global-setup skip flag) and a
# clean shutdown.
#
# Usage:
#   bash tests/ui/integration/run-integration.sh                 # all flows
#   bash tests/ui/integration/run-integration.sh 01-login        # grep subset
#
# Any extra args are forwarded to `playwright test` after `--project=integration`.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$UI_DIR/../.." && pwd)"
DEMO_DIR="$REPO_ROOT/examples/full-stack-demo"
DEMO_LOG="${DEMO_LOG:-$HERE/.demo-stack.log}"

# ── Port configuration ──────────────────────────────────────────────────────
# All three ports are overridable. The defaults match the demo's own defaults.
# When a port is already in use (e.g. 5173 held by another container), set the
# matching env var to a free port before running this script.
HEARTH_PORT="${HEARTH_PORT:-8420}"
BACKEND_PORT="${BACKEND_PORT:-8421}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
export HEARTH_PORT BACKEND_PORT FRONTEND_PORT

# ── Env the suite depends on ────────────────────────────────────────────────
# Fixed mailcatcher password so flow 2 (email verification) is deterministic.
export HEARTH_MAILCATCHER_PASSWORD="${HEARTH_MAILCATCHER_PASSWORD:-integration-mailcatcher-pw}"
# The integration project boots its own stack; skip the shared admin/dev-realm
# global setup meant for the other Playwright projects.
export HEARTH_SKIP_GLOBAL_SETUP=1
# Use localhost (not 127.0.0.1) so the browser origin matches the issuer and the
# registered redirect_uri.
export HEARTH_URL="${HEARTH_URL:-http://localhost:${HEARTH_PORT}}"
# Tell the Playwright config where each tier lives (config.ts already reads these).
export DEMO_FRONTEND_URL="${DEMO_FRONTEND_URL:-http://localhost:${FRONTEND_PORT}}"
export DEMO_BACKEND_URL="${DEMO_BACKEND_URL:-http://localhost:${BACKEND_PORT}}"
# Disable the sccache RUSTC wrapper — it fails in this sandbox (exit 254);
# demo.sh's `cargo build --release` must not go through it.
export RUSTC_WRAPPER=""
export PROTOC="${PROTOC:-$(command -v protoc || true)}"
# Resolve a launchable Chromium. Playwright's bundled Chromium can't run on
# NixOS (missing RPATH-patched libs); prefer a system/nixpkgs chromium when one
# exists. On a Debian/CI box none is found → stays unset → pw-run.sh installs the
# bundled browser (which works there). The config reads CHROMIUM_EXECUTABLE_PATH.
if [[ -z "${CHROMIUM_EXECUTABLE_PATH:-}" ]]; then
  _chromium="$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || true)"
  if [[ -z "$_chromium" ]]; then
    _chromium="$(ls -d /nix/store/*chromium*/bin/chromium 2>/dev/null | sort -V | tail -1 || true)"
  fi
  if [[ -n "$_chromium" ]]; then
    export CHROMIUM_EXECUTABLE_PATH="$_chromium"
    # We resolved a working Chromium ourselves — tell pw-run.sh to skip its
    # nix-shell re-exec (whose shellHook would overwrite this) and just run.
    export IN_NIX_SHELL="${IN_NIX_SHELL:-1}"
  fi
fi
[[ -n "${CHROMIUM_EXECUTABLE_PATH:-}" ]] && echo "  using Chromium: $CHROMIUM_EXECUTABLE_PATH"
# The demo backend's go.mod is pinned to slightly older transitive versions than
# a current Go toolchain resolves, so bare `go run .` errors with "updates to
# go.mod needed". `-mod=mod` lets the build proceed (and transiently rewrites
# go.mod/go.sum, which cleanup restores). NOTE: the demo not building headless
# from a clean tree is itself a finding reported on HEA-2056.
export GOFLAGS="${GOFLAGS:--mod=mod}"

DEMO_PID=""
cleanup() {
  local code=$?
  if [[ -n "$DEMO_PID" ]] && kill -0 "$DEMO_PID" 2>/dev/null; then
    echo "▸ stopping demo stack (pid $DEMO_PID)…"
    kill -TERM "$DEMO_PID" 2>/dev/null || true
    wait "$DEMO_PID" 2>/dev/null || true
  fi
  # Belt-and-suspenders: demo.sh's own trap frees :8421/:5173; make sure Hearth
  # started by this run is gone too.
  pkill -f "hearth serve .*full-stack-demo" 2>/dev/null || true
  # Restore any go.mod/go.sum churn from the -mod=mod build so the tree is clean.
  git -C "$REPO_ROOT" checkout -- \
    examples/full-stack-demo/backend/go.mod \
    examples/full-stack-demo/backend/go.sum 2>/dev/null || true
  exit "$code"
}
trap cleanup EXIT INT TERM

# ── Guard against occupied ports ─────────────────────────────────────────────
# Kill any leftover `hearth` binary (safe — scoped to the binary name), then
# REFUSE if any of the three demo ports is still held.  We must not
# unconditionally kill arbitrary PIDs: on a shared host the occupant could be
# an unrelated service (e.g. a long-running container on :5173).
check_port() {
  local port="$1"
  local pids
  pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  if [[ -z "$pids" ]]; then return 0; fi
  echo "✗ port $port is already in use (pid: $pids)" >&2
  echo "  Stop that process first, or override the port with an env var:" >&2
  echo "    HEARTH_PORT=NNNN BACKEND_PORT=NNNN FRONTEND_PORT=NNNN bash $0" >&2
  exit 1
}
pkill -x hearth 2>/dev/null || true
check_port "${HEARTH_PORT}"
check_port "${BACKEND_PORT}"
check_port "${FRONTEND_PORT}"
# Clear Vite's dep-optimize cache. demo.sh rewrites frontend/.env on every run,
# which makes Vite log "config has changed" and RESTART its dev server mid-boot;
# with --strictPort that restart can't rebind :5173 and dies. A clean cache
# optimizes once at startup with no restart.
rm -rf "$DEMO_DIR/frontend/node_modules/.vite" 2>/dev/null || true
sleep 1

# ── Boot the stack via demo.sh (backgrounded) ───────────────────────────────
echo "▸ booting full-stack demo via demo.sh (log: $DEMO_LOG)…"
( cd "$DEMO_DIR" && exec bash demo.sh ) >"$DEMO_LOG" 2>&1 &
DEMO_PID=$!

echo -n "  waiting for stack to be ready"
ready=""
for _ in $(seq 1 600); do          # up to ~120s (release build + boot)
  if ! kill -0 "$DEMO_PID" 2>/dev/null; then
    echo; echo "✗ demo stack exited early — see $DEMO_LOG" >&2
    tail -20 "$DEMO_LOG" >&2 || true
    exit 1
  fi
  if grep -q "Hearth Hub is ready" "$DEMO_LOG" 2>/dev/null; then ready=1; break; fi
  echo -n "."; sleep 0.2
done
echo
if [[ -z "$ready" ]]; then
  echo "✗ demo stack did not become ready in time — see $DEMO_LOG" >&2
  tail -20 "$DEMO_LOG" >&2 || true
  exit 1
fi
echo "  ✓ stack is up (Hearth :${HEARTH_PORT}, backend :${BACKEND_PORT}, frontend :${FRONTEND_PORT})"

# ── Plumb the admin token written by demo.sh ────────────────────────────────
# demo.sh writes .hearth-run-env after its own (first, unauthenticated) bootstrap.
# Sourcing it here exports HEARTH_ADMIN_TOKEN / HEARTH_SYSTEM_REALM_ID so the
# suite's bootstrapAdmin() helper can return them directly instead of calling
# POST /admin/bootstrap again — which would 401 because the realm already exists.
DEMO_RUN_ENV="$DEMO_DIR/.hearth-run-env"
if [[ -f "$DEMO_RUN_ENV" ]]; then
  # shellcheck source=/dev/null
  source "$DEMO_RUN_ENV"
  export HEARTH_ADMIN_TOKEN HEARTH_SYSTEM_REALM_ID
  echo "  ✓ admin credentials loaded from stack boot"
else
  echo "  ⚠ .hearth-run-env not found — bootstrapAdmin() will attempt a live bootstrap call" >&2
fi

# ── Run the suite (reuse pw-run.sh for the cross-platform browser launch) ────
echo "▸ running integration suite…"
cd "$UI_DIR"
bash ./pw-run.sh test --project=integration "$@"
