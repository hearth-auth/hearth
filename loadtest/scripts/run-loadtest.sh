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
#   PORT              [8420]   loopback port the throwaway server binds
#   MODE              [steady] steady | ramp | soak
#   USERS             [20]     concurrent Goose users
#   RUN_TIME          [90s]    per-run duration
#   HATCH_RATE        [5]      users spawned per second
#   THROTTLE          [3]      cap total req/s (stays under dev rate limits)
#   USERS_PER_REALM   [80]     seeded user records (<= admin-write budget/boot)
#   SESSIONS_FRAC     [0.5]    fraction of users given a live token
#   REVOKED_FRAC      [0.1]    fraction of live tokens pre-revoked
#   SEED              [1]      determinism seed
#   SETTLE            [65]     seconds to wait after seeding so the 100/min
#                             admin-write window resets before the run (set 0
#                             to skip; risks 429s on the user_lookup journey)
#   EXTRA_RUN_ARGS    []       extra flags appended to the `run` subcommand
#
# Loopback / dev only — the server boots with `--dev` (bootstrap enabled,
# relaxed security) and an in-memory store. Never point this at shared infra.
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
PORT="${PORT:-8420}"
MODE="${MODE:-steady}"
USERS="${USERS:-20}"
RUN_TIME="${RUN_TIME:-90s}"
HATCH_RATE="${HATCH_RATE:-5}"
THROTTLE="${THROTTLE:-3}"
USERS_PER_REALM="${USERS_PER_REALM:-80}"
SESSIONS_FRAC="${SESSIONS_FRAC:-0.5}"
REVOKED_FRAC="${REVOKED_FRAC:-0.1}"
SEED="${SEED:-1}"
SETTLE="${SETTLE:-65}"
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

# ── 2. Loopback-only config with the request shaper raised ───────────────────
# The per-client token/admin caps are compile-time constants (we stay under
# them via THROTTLE); this only lifts the per-IP shaper so a loopback run is
# not dominated by 429s. See loadtest/README.md "Rate limits".
cat >"${CONFIG}" <<YAML
server:
  bind_address: "127.0.0.1"
  port: ${PORT}
security:
  request_shaper:
    ip_rps: 500000
    realm_rps: 5000000
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
echo "==> Running load (mode=${MODE}, users=${USERS}, run-time=${RUN_TIME}, throttle=${THROTTLE})"
# shellcheck disable=SC2086
"${LOADTEST_BIN}" run \
  --seed-handle "${SEED_HANDLE}" \
  --mode "${MODE}" \
  --users "${USERS}" \
  --run-time "${RUN_TIME}" \
  --hatch-rate "${HATCH_RATE}" \
  --throttle "${THROTTLE}" \
  ${EXTRA_RUN_ARGS}

echo "==> Done. Reports in ${LOADTEST_DIR}/reports/ (report.json + *.html)"
