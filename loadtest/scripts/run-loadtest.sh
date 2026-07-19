#!/usr/bin/env bash
#
# One-shot load-test pipeline for Hearth (HEA-1787).
#
# Boots a fresh, isolated, dev-only Hearth on loopback, seeds a deterministic
# corpus, runs the Goose journeys, and writes the JSON + HTML reports — then
# tears the server down. This is the "just run it" entrypoint behind
# `make loadtest` (no ARGS). For advanced/attach usage, call the binary
# directly via `make loadtest ARGS="..."` (see loadtest/README.md).
#
# Everything is overridable via environment variables (defaults in brackets):
#   PORT              [auto]   loopback port the throwaway server binds
#                             (default: a free ephemeral port; never collides)
#   MODE              [steady] steady | ramp | soak
#   USERS             [20]     concurrent Goose users
#   RUN_TIME          [90s]    per-run duration
#   HATCH_RATE        [50]     users spawned per second
#   THROTTLE          [0]      cap total req/s; 0 = unthrottled (the default —
#                             all server-side rate limits are disabled via
#                             security.load_test_unthrottled, so there is no
#                             limiter to stay under). Set >0 only to pin a
#                             specific offered load for a controlled ramp.
#   USERS_PER_REALM   [80]     seeded user records per realm
#   SESSIONS_FRAC     [0.5]    fraction of users given a live token
#   REVOKED_FRAC      [0.1]    fraction of live tokens pre-revoked
#   SEED              [1]      determinism seed
#   SETTLE            [0]      seconds to wait after seeding before the run.
#                             Default 0: with rate limits disabled there is no
#                             admin-write window to wait out.
#   EXTRA_RUN_ARGS    []       extra flags appended to the `run` subcommand
#
# Loopback / dev only — the server boots with `--dev` (bootstrap enabled,
# relaxed security), an in-memory store, and `security.load_test_unthrottled`
# which disables ALL request-rate limiters so the run saturates the hot path
# instead of a limiter. That flag is refused on any non-loopback bind. Never
# point this at shared infra.
set -euo pipefail

# ── Resolve paths ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOADTEST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${LOADTEST_DIR}/.." && pwd)"
PROTOC="${PROTOC:-$(command -v protoc || true)}"
if [[ -z "${PROTOC}" ]]; then
  echo "error: protoc not found on PATH; set PROTOC=/path/to/protoc" >&2
  exit 1
fi
export PROTOC

# ── Parameters ───────────────────────────────────────────────────────────────
# Auto-pick a free loopback port unless one is pinned via PORT=. This keeps
# bare `make loadtest` a true zero-requirement command: it never collides with
# a running `make dev` (8420) or a stale throwaway from a prior run.
pick_free_port() {
  python3 - <<'PY' 2>/dev/null || echo 0
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
if [[ -z "${PORT:-}" ]]; then
  PORT="$(pick_free_port)"
  [[ "${PORT}" == "0" || -z "${PORT}" ]] && PORT="8420"
fi
MODE="${MODE:-steady}"
USERS="${USERS:-200}"
RUN_TIME="${RUN_TIME:-90s}"
HATCH_RATE="${HATCH_RATE:-50}"
THROTTLE="${THROTTLE:-0}"
USERS_PER_REALM="${USERS_PER_REALM:-80}"
SESSIONS_FRAC="${SESSIONS_FRAC:-0.5}"
REVOKED_FRAC="${REVOKED_FRAC:-0.1}"
SEED="${SEED:-1}"
SETTLE="${SETTLE:-0}"
EXTRA_RUN_ARGS="${EXTRA_RUN_ARGS:-}"

HOST="http://127.0.0.1:${PORT}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/hearth-loadtest.XXXXXX")"
CONFIG="${WORKDIR}/hearth-loadtest.yaml"
SEED_HANDLE="${LOADTEST_DIR}/reports/seed-handle.json"
SERVER_LOG="${WORKDIR}/server.log"
SERVER_PID=""

# ── Teardown ─────────────────────────────────────────────────────────────────
cleanup() {
  local code=$?
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
  exit "${code}"
}
trap cleanup EXIT INT TERM

# ── 1. Build the release binaries ────────────────────────────────────────────
echo "==> Building release hearth + loadtest binaries"
cargo build --release --manifest-path "${REPO_ROOT}/Cargo.toml"
cargo build --release --manifest-path "${LOADTEST_DIR}/Cargo.toml"

HEARTH_BIN="$(cargo metadata --format-version 1 --no-deps \
  --manifest-path "${REPO_ROOT}/Cargo.toml" \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/release/hearth"
LOADTEST_BIN="$(cargo metadata --format-version 1 --no-deps \
  --manifest-path "${LOADTEST_DIR}/Cargo.toml" \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/release/hearth-loadtest"

# ── 2. Loopback-only config with all rate limiters disabled ──────────────────
# security.load_test_unthrottled disables the token, admin, export, and per-IP/
# per-realm request-shaper limiters so the run measures the hot path, not a
# limiter. The flag is refused unless the bind is loopback (it is: 127.0.0.1).
# See loadtest/README.md "Rate limits".
cat >"${CONFIG}" <<YAML
server:
  bind_address: "127.0.0.1"
  port: ${PORT}
security:
  load_test_unthrottled: true
YAML

# ── 3. Boot the throwaway server (in-memory, dev mode) ───────────────────────
echo "==> Booting throwaway hearth on ${HOST} (dev, in-memory)"
"${HEARTH_BIN}" serve --dev --config "${CONFIG}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

echo "==> Waiting for health check"
for _ in $(seq 1 60); do
  if curl -sf "${HOST}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "error: server exited during startup; log:" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
  fi
  sleep 0.5
done
if ! curl -sf "${HOST}/health" >/dev/null 2>&1; then
  echo "error: server did not become healthy within 30s; log:" >&2
  cat "${SERVER_LOG}" >&2
  exit 1
fi

# ── 4. Seed a deterministic corpus (fresh instance → anonymous bootstrap) ────
echo "==> Seeding corpus (${USERS_PER_REALM} users, seed=${SEED})"
"${LOADTEST_BIN}" seed \
  --target-host "${HOST}" \
  --users-per-realm "${USERS_PER_REALM}" \
  --sessions-frac "${SESSIONS_FRAC}" \
  --revoked-frac "${REVOKED_FRAC}" \
  --seed "${SEED}" \
  --seed-out "${SEED_HANDLE}"

# ── 5. Let the admin-write rate window reset before the run ───────────────────
if [[ "${SETTLE}" != "0" ]]; then
  echo "==> Settling ${SETTLE}s for the admin-write rate window to reset"
  sleep "${SETTLE}"
fi

# ── 6. Run the Goose journeys ────────────────────────────────────────────────
# THROTTLE=0 (the default) means unthrottled: omit --throttle entirely so goose
# offers as much load as USERS can generate. A positive THROTTLE pins a specific
# offered request rate, e.g. for a controlled ramp to find the p99 knee.
THROTTLE_ARG=""
if [[ -n "${THROTTLE}" && "${THROTTLE}" != "0" ]]; then
  THROTTLE_ARG="--throttle ${THROTTLE}"
fi
echo "==> Running load (mode=${MODE}, users=${USERS}, run-time=${RUN_TIME}, throttle=${THROTTLE:-0})"
# shellcheck disable=SC2086
"${LOADTEST_BIN}" run \
  --seed-handle "${SEED_HANDLE}" \
  --mode "${MODE}" \
  --users "${USERS}" \
  --run-time "${RUN_TIME}" \
  --hatch-rate "${HATCH_RATE}" \
  ${THROTTLE_ARG} \
  ${EXTRA_RUN_ARGS}

echo "==> Done. Reports in ${LOADTEST_DIR}/reports/ (report.json + *.html)"
