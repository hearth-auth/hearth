#!/usr/bin/env bash
# HEA-1871: Separate the load generator from the server under test.
#
# Pins the Hearth server to cores 0-7 and the generator to cores 8-15 via
# `taskset -c`, then re-runs the 500→cliff bisect to determine whether
# isolation moves the failure onset materially (proving the old cliff at
# 500→600 was generator CPU starvation, not a Hearth server limit).
#
# Hardware: 16 vCPU AMD Ryzen 7 7840HS (8 physical cores × 2 HT).
#   server_cores   = 0-7   (physical cores 0-3, both hyperthreads each)
#   generator_cores = 8-15 (physical cores 4-7, both hyperthreads each)
#
# ── Remote-generator path (documented) ──────────────────────────────────────
# The generator and server communicate over HTTP only. To run the generator on
# a separate machine (Tier 2 / cloud box):
#
#   Server machine A:
#     hearth serve --config hearth.yaml   # listens on 0.0.0.0:PORT
#     # (or: LOADTEST_PORT=8421 run-loadtest.sh seeds corpus but exits before
#     #  the generator step if you omit step 6 — wire that up manually)
#
#   Generator machine B:
#     # 1. Seed the token pool against machine A:
#     hearth-loadtest seed \
#       --target-host http://<machine-A-ip>:<port> \
#       --users-per-realm 80 --sessions-frac 0.5 \
#       --revoked-frac 0.1 --seed 1 \
#       --seed-out seed-handle.json
#
#     # 2. Run load against machine A:
#     hearth-loadtest run \
#       --seed-handle seed-handle.json \
#       --mode steady --users 2000 --run-time 60s \
#       --hatch-rate 500 \
#       --resident-corpus-size <total-users-on-A>
#
# With a remote generator there is no resource contention; the server can use
# all its cores and the generator is not on /proc of the server box. This is
# the definitive Tier 2 measurement described in the plan (§4).
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOADTEST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${LOADTEST_DIR}/.." && pwd)"
PROTOC="${PROTOC:-$(command -v protoc || true)}"
[[ -z "${PROTOC}" ]] && { echo "error: protoc not found; set PROTOC=/path/to/protoc" >&2; exit 1; }
export PROTOC

# ── Core-affinity knobs ───────────────────────────────────────────────────────
# Halve the 16 vCPUs: server gets physical cores 0-3 (LPs 0-7),
# generator gets physical cores 4-7 (LPs 8-15).
SERVER_CORES="${SERVER_CORES:-0-7}"
GENERATOR_CORES="${GENERATOR_CORES:-8-15}"
TASKSET="$(command -v taskset)"
if [[ -z "${TASKSET}" ]]; then
  echo "error: taskset not found; install util-linux" >&2
  exit 1
fi

# ── Corpus / run parameters ───────────────────────────────────────────────────
# Same corpus as HEA-1812 baseline (300 k users) for a direct apples-to-apples
# comparison. Lower SEED_WAIT if your machine seeds faster.
CORPUS_ACME="${CORPUS_ACME:-150000}"
CORPUS_GLOBEX="${CORPUS_GLOBEX:-90000}"
CORPUS_INITECH="${CORPUS_INITECH:-40000}"
CORPUS_UMBRELLA="${CORPUS_UMBRELLA:-20000}"
HOT_TIER_CAPACITY="${HOT_TIER_CAPACITY:-100000}"
SEED_WAIT="${SEED_WAIT:-1800}"
CORPUS_TOTAL=$(( CORPUS_ACME + CORPUS_GLOBEX + CORPUS_INITECH + CORPUS_UMBRELLA ))

USERS_PER_REALM="${USERS_PER_REALM:-80}"
SESSIONS_FRAC="${SESSIONS_FRAC:-0.5}"
REVOKED_FRAC="${REVOKED_FRAC:-0.1}"
SEED="${SEED:-1}"
RUN_TIME="${RUN_TIME:-45s}"
HATCH_RATE="${HATCH_RATE:-500}"
# User ladder for the bisect.
BISECT_USERS="${BISECT_USERS:-500 600 700 800 1000 1500 2000 3000 5000}"

# Output
OUT="${LOADTEST_DIR}/reports/hea1871"
mkdir -p "${OUT}"

pick_free_port() {
  python3 - <<'PY' 2>/dev/null || echo 0
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
PORT="$(pick_free_port)"
[[ "${PORT}" == "0" || -z "${PORT}" ]] && PORT="8422"
HOST="http://127.0.0.1:${PORT}"

LOADTEST_DATA_DIR="${LOADTEST_DATA_DIR:-${REPO_ROOT}/data/hea1871-corpus}"
CORPUS_CONFIG="${LOADTEST_DIR}/loadtest-corpus.yaml"
SEED_HANDLE="${OUT}/seed-handle.json"
LOG="${OUT}/server.log"

# ── Resolve binaries ─────────────────────────────────────────────────────────
HEARTH_BIN="${HEARTH_BIN:-}"
LOADTEST_BIN="${LOADTEST_BIN:-}"
if [[ -z "${HEARTH_BIN}" ]]; then
  HEARTH_BIN="$(cargo metadata --format-version 1 --no-deps \
    --manifest-path "${REPO_ROOT}/Cargo.toml" \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/release/hearth"
fi
if [[ -z "${LOADTEST_BIN}" ]]; then
  LOADTEST_BIN="$(cargo metadata --format-version 1 --no-deps \
    --manifest-path "${LOADTEST_DIR}/Cargo.toml" \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/release/hearth-loadtest"
fi
[[ -x "${HEARTH_BIN}" ]] || { echo "error: hearth binary not found at ${HEARTH_BIN}; run cargo build --release first" >&2; exit 1; }
[[ -x "${LOADTEST_BIN}" ]] || { echo "error: hearth-loadtest binary not found at ${LOADTEST_BIN}; run cargo build --release --manifest-path loadtest/Cargo.toml" >&2; exit 1; }

SERVER_PID=""
cleanup() {
  local code=$?
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  exit "${code}"
}
trap cleanup EXIT INT TERM

# ── Boot the server pinned to SERVER_CORES ────────────────────────────────────
echo "==> Booting hearth on ${HOST}"
echo "    server cores: ${SERVER_CORES}  generator cores: ${GENERATOR_CORES}"
echo "    corpus total: ${CORPUS_TOTAL} users  data: ${LOADTEST_DATA_DIR}"

rm -rf "${LOADTEST_DATA_DIR}"
mkdir -p "${LOADTEST_DATA_DIR}"

export LOADTEST_PORT="${PORT}"
export LOADTEST_DATA_DIR
export LOADTEST_HOT_TIER_CAPACITY="${HOT_TIER_CAPACITY}"
export LOADTEST_ISSUER="${HOST}"
export LOADTEST_CORPUS_ACME="${CORPUS_ACME}"
export LOADTEST_CORPUS_GLOBEX="${CORPUS_GLOBEX}"
export LOADTEST_CORPUS_INITECH="${CORPUS_INITECH}"
export LOADTEST_CORPUS_UMBRELLA="${CORPUS_UMBRELLA}"

"${TASKSET}" -c "${SERVER_CORES}" "${HEARTH_BIN}" serve --dev \
  --config "${CORPUS_CONFIG}" >"${LOG}" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 120); do
  curl -sf "${HOST}/health" >/dev/null 2>&1 && break
  kill -0 "${SERVER_PID}" 2>/dev/null || { echo "error: server exited; log:"; tail -20 "${LOG}"; exit 1; }
  sleep 0.5
done
curl -sf "${HOST}/health" >/dev/null 2>&1 || { echo "error: server unhealthy after 60s"; tail -20 "${LOG}"; exit 1; }
echo "==> Server healthy"

echo "==> Waiting for corpus seeding (target=${CORPUS_TOTAL}, timeout=${SEED_WAIT}s)"
seed_deadline=$(( SECONDS + SEED_WAIT ))
until grep -q "demo seeding finished (all realms)" "${LOG}" 2>/dev/null; do
  kill -0 "${SERVER_PID}" 2>/dev/null || { echo "error: server exited during seeding"; tail -20 "${LOG}"; exit 1; }
  (( SECONDS >= seed_deadline )) && { echo "error: seeding timeout"; tail -20 "${LOG}"; exit 1; }
  sleep 1
done
echo "==> Corpus resident"

echo "==> Seeding token pool (pinned to generator cores ${GENERATOR_CORES})"
"${TASKSET}" -c "${GENERATOR_CORES}" "${LOADTEST_BIN}" seed \
  --target-host "${HOST}" \
  --users-per-realm "${USERS_PER_REALM}" \
  --sessions-frac "${SESSIONS_FRAC}" \
  --revoked-frac "${REVOKED_FRAC}" \
  --seed "${SEED}" \
  --seed-out "${SEED_HANDLE}"

echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "  HEA-1871 isolated bisect: server=cores${SERVER_CORES}  gen=cores${GENERATOR_CORES}"
echo "  corpus=${CORPUS_TOTAL}  hardware=AMD Ryzen 7 7840HS 16vCPU/54GiB"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
printf "%-6s %8s %7s %18s %10s %10s %8s\n" \
  "USERS" "RPS" "FAIL%" "CEILING" "CPU_MEAN%" "CPU_PEAK%" "RSS_MiB"
echo "------------------------------------------------------------------------"

SUMMARY_FILE="${OUT}/summary.tsv"
echo -e "users\trps\tfail_pct\tceiling\tcpu_mean\tcpu_peak\trss_mib" > "${SUMMARY_FILE}"

for U in ${BISECT_USERS}; do
  echo "  --- running users=${U} ---"
  REPORT_JSON="${OUT}/steady-${U}u.json"

  set +e
  "${TASKSET}" -c "${GENERATOR_CORES}" "${LOADTEST_BIN}" run \
    --seed-handle "${SEED_HANDLE}" \
    --mode steady \
    --users "${U}" \
    --run-time "${RUN_TIME}" \
    --hatch-rate "${HATCH_RATE}" \
    --resident-corpus-size "${CORPUS_TOTAL}" \
    --server-pid "${SERVER_PID}" \
    2>&1 | tail -5
  set -e

  if [[ -f "${LOADTEST_DIR}/reports/report.json" ]]; then
    cp "${LOADTEST_DIR}/reports/report.json" "${REPORT_JSON}"
    python3 - <<PY
import json, sys
with open("${REPORT_JSON}") as fh:
    d = json.load(fh)
s = d.get("summary", {})
r = d.get("resources", {})
rps = s.get("achieved_rps", 0)
fail = s.get("failure_rate", 0) * 100
ceil = s.get("ceiling", "?")
cpu_m = r.get("cpu_mean_pct", 0)
cpu_p = r.get("cpu_peak_pct", 0)
rss = r.get("rss_peak_bytes", 0) / (1024*1024)
print(f"{${U}:>6} {rps:>8.0f} {fail:>7.1f}% {ceil:>18} {cpu_m:>10.1f} {cpu_p:>10.1f} {rss:>8.0f}")
with open("${SUMMARY_FILE}", "a") as f:
    f.write(f"${U}\t{rps:.0f}\t{fail:.1f}\t{ceil}\t{cpu_m:.1f}\t{cpu_p:.1f}\t{rss:.0f}\n")
PY
  else
    echo "  (no report.json produced for users=${U})"
  fi
done

echo ""
echo "==> Done. Per-point reports: ${OUT}/steady-*.json"
echo "==> Summary TSV: ${SUMMARY_FILE}"
