#!/usr/bin/env bash
#
# One-shot load-test pipeline for Hearth (HEA-1787).
#
# Boots a dev-only Hearth on loopback that is pre-seeded with the LARGE demo
# corpus (multi-hundred-thousand users; see loadtest/loadtest-corpus.yaml),
# mints a live-token pool, runs the Goose journeys, and writes the JSON + HTML
# reports — then tears the server down. Running the journeys against a
# realistically-large storage engine (not an empty DB) is the entire point of
# the loadtest, so the large corpus is the DEFAULT for `make loadtest`
# specifically (HEA-1787). For advanced/attach usage, call the binary directly
# via `make loadtest ARGS="..."` (see loadtest/README.md).
#
# The corpus is seeded FRESH on every run into a throwaway on-disk data dir
# (LOADTEST_DATA_DIR, wiped before boot) so the dev-realm bootstrap the token
# pool needs always succeeds. Seeding the full ~1.2M-user corpus takes a couple
# of minutes on a release build; shrink it via the CORPUS_* knobs for a fast
# pipeline smoke. This is a nightly / pre-release tool, not a per-PR gate.
#
# Everything is overridable via environment variables (defaults in brackets):
#   PORT              [auto]   loopback port the server binds
#                             (default: a free ephemeral port; never collides)
#   MODE              [steady] steady | ramp | soak
#   USERS             [200]    concurrent Goose users
#   RUN_TIME          [90s]    per-run duration
#   HATCH_RATE        [50]     users spawned per second
#   THROTTLE          [0]      cap total req/s; 0 = unthrottled (the default —
#                             all server-side rate limits are disabled via
#                             security.load_test_unthrottled, so there is no
#                             limiter to stay under). Set >0 only to pin a
#                             specific offered load for a controlled ramp.
#   LOADTEST_DATA_DIR [./data/loadtest-corpus]  throwaway corpus data dir
#                             (wiped before each boot so bootstrap stays fresh)
#   CORPUS_ACME       [500000] users seeded into the acme realm (large default)
#   CORPUS_GLOBEX     [400000] users seeded into the globex realm
#   CORPUS_INITECH    [200000] users seeded into the initech realm
#   CORPUS_UMBRELLA   [100000] users seeded into the umbrella realm
#                             Lower these for a fast pipeline smoke, e.g.
#                             CORPUS_ACME=200 CORPUS_GLOBEX=0 ... make loadtest
#   HOT_TIER_CAPACITY [100000] hot-tier resident capacity (HEA-1800)
#   SEED_WAIT         [1800]   max seconds to wait for background seeding to
#                             finish before load starts
#   USERS_PER_REALM   [80]     token-pool user records (dev realm; token journeys)
#   SESSIONS_FRAC     [0.5]    fraction of pool users given a live token
#   REVOKED_FRAC      [0.1]    fraction of live tokens pre-revoked
#   SEED              [1]      determinism seed
#   SETTLE            [0]      seconds to wait after seeding before the run
#   EXTRA_RUN_ARGS    []       extra flags appended to the `run` subcommand
#
# Loopback / dev only — the server boots with `--dev` (bootstrap enabled,
# relaxed security) and `security.load_test_unthrottled` which disables ALL
# request-rate limiters so the run saturates the hot path instead of a limiter.
# That flag is refused on any non-loopback bind. Never point this at shared
# infra.
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

# ── Large-corpus parameters (the default dataset for `make loadtest`) ────────
# Seeded fresh each run into a throwaway data dir (wiped before boot) so the
# dev-realm bootstrap the token pool needs always succeeds on a clean instance.
LOADTEST_DATA_DIR="${LOADTEST_DATA_DIR:-${REPO_ROOT}/data/loadtest-corpus}"
CORPUS_ACME="${CORPUS_ACME:-500000}"
CORPUS_GLOBEX="${CORPUS_GLOBEX:-400000}"
CORPUS_INITECH="${CORPUS_INITECH:-200000}"
CORPUS_UMBRELLA="${CORPUS_UMBRELLA:-100000}"
HOT_TIER_CAPACITY="${HOT_TIER_CAPACITY:-100000}"
SEED_WAIT="${SEED_WAIT:-1800}"
CORPUS_TOTAL=$(( CORPUS_ACME + CORPUS_GLOBEX + CORPUS_INITECH + CORPUS_UMBRELLA ))

HOST="http://127.0.0.1:${PORT}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/hearth-loadtest.XXXXXX")"
CORPUS_CONFIG="${LOADTEST_DIR}/loadtest-corpus.yaml"
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

# ── 2. Large-corpus config (loopback-only, all rate limiters disabled) ───────
# loadtest/loadtest-corpus.yaml is the DEFAULT dataset for `make loadtest`: a
# demo-seeded, multi-hundred-thousand-user corpus. Its env placeholders let us
# pin the port, the throwaway data dir, the hot-tier capacity, and the
# per-realm user counts without editing the file. security.load_test_unthrottled
# (baked into that config) disables the token, admin, export, and per-IP/
# per-realm request-shaper limiters so the run measures the hot path, not a
# limiter — refused unless the bind is loopback (it is: 127.0.0.1).
export LOADTEST_PORT="${PORT}"
export LOADTEST_DATA_DIR
export LOADTEST_HOT_TIER_CAPACITY="${HOT_TIER_CAPACITY}"
export LOADTEST_ISSUER="${HOST}"
export LOADTEST_CORPUS_ACME="${CORPUS_ACME}"
export LOADTEST_CORPUS_GLOBEX="${CORPUS_GLOBEX}"
export LOADTEST_CORPUS_INITECH="${CORPUS_INITECH}"
export LOADTEST_CORPUS_UMBRELLA="${CORPUS_UMBRELLA}"
# Fresh data dir each run: the dev-realm bootstrap the token pool needs only
# succeeds anonymously on a clean instance (a persisted dev realm 401s).
rm -rf "${LOADTEST_DATA_DIR}"
mkdir -p "${LOADTEST_DATA_DIR}"

# ── 3. Boot the server, pre-seeded with the large corpus (dev mode, on disk) ──
echo "==> Booting hearth on ${HOST} (dev, large corpus target=${CORPUS_TOTAL} users)"
echo "    corpus data dir: ${LOADTEST_DATA_DIR} (fresh; re-seeded each run)"
"${HEARTH_BIN}" serve --dev --config "${CORPUS_CONFIG}" >"${SERVER_LOG}" 2>&1 &
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

# ── 3b. Wait for the background large-corpus seeding to finish ────────────────
# demo.enabled seeding runs in a BACKGROUND task (src/main.rs), so the server is
# healthy while it is still loading ~1.2M users. Running load now would measure a
# partially-resident, actively-writing store. Gate on the server's completion
# log line so the run starts against the full corpus. The line is emitted once
# per boot whether the corpus was freshly seeded or resumed from the sentinel.
echo "==> Waiting for large-corpus seeding to finish (target=${CORPUS_TOTAL} users, timeout=${SEED_WAIT}s)"
seed_deadline=$(( SECONDS + SEED_WAIT ))
until grep -q "demo seeding finished (all realms)" "${SERVER_LOG}" 2>/dev/null; do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "error: server exited during corpus seeding; log:" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
  fi
  if (( SECONDS >= seed_deadline )); then
    echo "error: corpus seeding did not finish within ${SEED_WAIT}s; raise SEED_WAIT or lower CORPUS_*; log tail:" >&2
    tail -n 20 "${SERVER_LOG}" >&2
    exit 1
  fi
  sleep 1
done
echo "==> Large corpus resident; proceeding to token-pool seed + run"

# ── 4. Seed the live-token pool (dev realm; drives the token journeys) ────────
# Distinct from the large corpus above: the validate/issuance/revoke journeys
# need live access tokens, minted here against the fresh dev realm that
# POST /admin/bootstrap creates. The large corpus provides the lookup/residency
# pressure; this pool provides the tokens.
echo "==> Seeding token pool (${USERS_PER_REALM} users, seed=${SEED})"
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
  --resident-corpus-size "${CORPUS_TOTAL}" \
  ${THROTTLE_ARG} \
  ${EXTRA_RUN_ARGS}

echo "==> Done. Reports in ${LOADTEST_DIR}/reports/ (report.json + *.html)"
