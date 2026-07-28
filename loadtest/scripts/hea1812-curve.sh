#!/usr/bin/env bash
# HEA-1812: boot the corpus ONCE, then sweep several unthrottled concurrency
# points to trace the RPS-vs-failure curve (max-comfortable band -> failure
# ceiling). Reuses the loadtest-corpus.yaml config (all rate limiters disabled
# via security.load_test_unthrottled; loopback only). Throwaway helper.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export PROTOC="${PROTOC:-$(command -v protoc)}"

REPO_ROOT="$(pwd)"
LOADTEST_DIR="$REPO_ROOT/loadtest"
OUT="$LOADTEST_DIR/reports/hea1812"
mkdir -p "$OUT"
HEARTH_BIN=/scratch/cache/target/release/hearth
LOADTEST_BIN=/scratch/cache/target/release/hearth-loadtest

PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
HOST="http://127.0.0.1:${PORT}"
DATA_DIR="$REPO_ROOT/data/loadtest-curve"
LOG="$(mktemp)"
SEED_HANDLE="$LOADTEST_DIR/reports/seed-handle-curve.json"

export LOADTEST_PORT="$PORT"
export LOADTEST_DATA_DIR="$DATA_DIR"
export LOADTEST_HOT_TIER_CAPACITY=100000
export LOADTEST_ISSUER="$HOST"
export LOADTEST_CORPUS_ACME=150000
export LOADTEST_CORPUS_GLOBEX=90000
export LOADTEST_CORPUS_INITECH=40000
export LOADTEST_CORPUS_UMBRELLA=20000
CORPUS_TOTAL=300000

SERVER_PID=""
cleanup(){ local c=$?; [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$DATA_DIR"; exit $c; }
trap cleanup EXIT INT TERM

rm -rf "$DATA_DIR"; mkdir -p "$DATA_DIR"
echo "==> boot $HOST (corpus target=$CORPUS_TOTAL)"
"$HEARTH_BIN" serve --dev --config "$LOADTEST_DIR/loadtest-corpus.yaml" >"$LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do curl -sf "$HOST/health" >/dev/null 2>&1 && break; sleep 0.5; done
echo "==> waiting for corpus seeding"
until grep -q "demo seeding finished (all realms)" "$LOG" 2>/dev/null; do
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "server died"; tail -20 "$LOG"; exit 1; }
  sleep 1
done
echo "==> seeding token pool"
"$LOADTEST_BIN" seed --target-host "$HOST" --users-per-realm 80 --sessions-frac 0.5 \
  --revoked-frac 0.1 --seed 1 --seed-out "$SEED_HANDLE"

# Fine bisect of 500 -> 1000u to locate the true failure onset (HEA-1813), plus
# a couple of anchors past the cliff to confirm the collapse is monotone. Each
# step passes --server-pid so the report's `resources` block attributes the step
# to server saturation vs. co-resident load-generator starvation (HEA-1811).
for U in 500 600 700 800 900 1000 1500 2000; do
  echo "############ steady users=$U ############"
  "$LOADTEST_BIN" run --seed-handle "$SEED_HANDLE" --mode steady --users "$U" \
    --run-time 45s --hatch-rate 500 --resident-corpus-size "$CORPUS_TOTAL" \
    --server-pid "$SERVER_PID" || true
  cp "$LOADTEST_DIR/reports/report.json" "$OUT/steady-${U}u.json"
  jq -r --arg u "$U" '"users=\($u) rps=\(.summary.achieved_rps|floor) fail=\(.summary.failure_rate) ceiling=\(.summary.ceiling) rss_peak=\(.resources.rss_peak_bytes // 0) cpu_peak=\(.resources.cpu_peak_pct // 0) cpu_mean=\(.resources.cpu_mean_pct // 0) samples=\(.resources.samples // 0)"' "$OUT/steady-${U}u.json"
done
echo "############ CURVE DONE ############"
