#!/usr/bin/env bash
# C10 (HEA-1878) — measure the two VISION §7.3 rows that need no load harness:
#   K8  binary size            (target < 50 MB)
#   K9  cold start to serving  (target < 2 s)
#
# Both are properties of the built artifact and of startup, so they are gradeable
# without C0-C9. Emits docs/perf/artifacts/c10-artifact-facts.json per the data
# contract in docs/perf/PERFORMANCE_REPORT_1_0.md §7.
#
# Usage: bash docs/perf/scripts/c10-artifact-facts.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN="${CARGO_TARGET_DIR:-$REPO/target}/release/hearth"
OUT="$REPO/docs/perf/artifacts/c10-artifact-facts.json"
PORT=8421

[[ -x "$BIN" ]] || { echo "no release binary at $BIN — run: cargo build --release --bin hearth" >&2; exit 1; }

GIT_SHA="$(git -C "$REPO" rev-parse --short HEAD)"
DIRTY="$(git -C "$REPO" status --porcelain -- src/ Cargo.toml Cargo.lock | head -1)"
[[ -z "$DIRTY" ]] || echo "WARNING: src/ or manifest is dirty; binary may not correspond to $GIT_SHA" >&2

# ---- K8: binary size -------------------------------------------------------
SIZE_BYTES="$(stat -c %s "$BIN")"
SIZE_MB="$(awk -v b="$SIZE_BYTES" 'BEGIN{printf "%.2f", b/1000000}')"   # MB, decimal (VISION says "MB")
SIZE_MIB="$(awk -v b="$SIZE_BYTES" 'BEGIN{printf "%.2f", b/1048576}')"
K8_VERDICT=$(awk -v m="$SIZE_MB" 'BEGIN{print (m<50)?"PASS":"MISS"}')

# ---- K9: cold start to serving requests ------------------------------------
# "Cold start to serving requests" = process exec -> first successful /health.
# Measured 5x on a COLD data dir each time; we report the max (worst case is the
# operator-visible figure) as well as the full sample.
COLD_SAMPLES=()
for i in 1 2 3 4 5; do
  DATA="$(mktemp -d)"
  # Distinct port per iteration: a just-killed listener can hold the port in
  # TIME_WAIT and the next run would fail with EADDRINUSE, silently dropping samples.
  RUN_PORT=$(( PORT + i ))
  START_NS=$(date +%s%N)
  HEARTH_STORAGE__DATA_DIR="$DATA" "$BIN" serve --dev --bind 127.0.0.1 --port "$RUN_PORT" >"$DATA/log" 2>&1 &
  PID=$!
  # Poll tightly; do not sleep in coarse increments or we quantise the measurement.
  READY_NS=""
  for _ in $(seq 1 20000); do
    if curl -sf -o /dev/null "http://127.0.0.1:$RUN_PORT/health" 2>/dev/null; then
      READY_NS=$(date +%s%N); break
    fi
    kill -0 "$PID" 2>/dev/null || break
  done
  kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true
  if [[ -n "$READY_NS" ]]; then
    COLD_SAMPLES+=( "$(( (READY_NS - START_NS) / 1000000 ))" )
  else
    echo "run $i: server never became ready; log tail:" >&2; tail -5 "$DATA/log" >&2
  fi
  rm -rf "$DATA"
done

[[ ${#COLD_SAMPLES[@]} -gt 0 ]] || { echo "K9: no successful cold starts — cannot grade" >&2; exit 1; }
COLD_LIST="$(IFS=,; echo "${COLD_SAMPLES[*]}")"
COLD_MAX="$(printf '%s\n' "${COLD_SAMPLES[@]}" | sort -n | tail -1)"
COLD_MIN="$(printf '%s\n' "${COLD_SAMPLES[@]}" | sort -n | head -1)"
K9_VERDICT=$(awk -v m="$COLD_MAX" 'BEGIN{print (m<2000)?"PASS":"MISS"}')

# ---- host + swap facts (required by the data contract) ---------------------
CPU_MODEL="$(lscpu | sed -n 's/^Model name: *//p' | head -1)"
CORES="$(lscpu | sed -n 's/^Core(s) per socket: *//p' | head -1)"
THREADS="$(nproc)"
GOV="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
RAM_TOTAL="$(free -g | awk '/^Mem:/{print $2}')"
RAM_AVAIL="$(free -g | awk '/^Mem:/{print $NF}')"
SWAP_IN="$(awk '/^pswpin/{print $2}' /proc/vmstat)"
SWAP_OUT="$(awk '/^pswpout/{print $2}' /proc/vmstat)"

mkdir -p "$(dirname "$OUT")"
cat > "$OUT" <<JSON
{
  "schema": 1,
  "child_issue": "HEA-1878",
  "axis": "K8,K9",
  "git_sha": "$GIT_SHA",
  "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": {
    "profile": "dev-ryzen-7840hs",
    "cpu_model": "$CPU_MODEL",
    "cores_physical": $CORES,
    "threads": $THREADS,
    "governor": "$GOV",
    "ram_total_gib": $RAM_TOTAL,
    "ram_available_gib": $RAM_AVAIL,
    "generator_placement": "n/a"
  },
  "swap": {
    "swap_in_pages": $SWAP_IN,
    "swap_out_pages": $SWAP_OUT,
    "void_due_to_swap": false,
    "note": "Cumulative host counters since boot, not deltas over the window. K8/K9 are not load-generated and are insensitive to swap pressure; recorded for schema conformance."
  },
  "ceiling": {
    "attribution": "n/a",
    "reason": "K8/K9 are artifact and startup properties, not load-generated figures. Rule 3 does not apply."
  },
  "measurements": [
    { "name": "binary_size_bytes", "value": $SIZE_BYTES, "unit": "bytes" },
    { "name": "binary_size_mb_decimal", "value": $SIZE_MB, "unit": "MB" },
    { "name": "binary_size_mib", "value": $SIZE_MIB, "unit": "MiB" },
    { "name": "cold_start_to_serving_max_ms", "value": $COLD_MAX, "unit": "ms" },
    { "name": "cold_start_to_serving_min_ms", "value": $COLD_MIN, "unit": "ms" }
  ],
  "cold_start_samples_ms": [$COLD_LIST],
  "verdicts": { "K8": "$K8_VERDICT", "K9": "$K9_VERDICT" },
  "verdict_reason": "K8: release binary $SIZE_MB MB vs < 50 MB target. K9: worst-of-5 cold start ${COLD_MAX} ms vs < 2000 ms target; measured as exec -> first successful GET /health on a fresh empty data dir, --dev (in-memory storage), no corpus. A cold start against a large on-disk corpus is a DIFFERENT measurement and is NOT graded here — it belongs to C8.",
  "reproduction": "bash docs/perf/scripts/c10-artifact-facts.sh"
}
JSON

echo "K8 binary size:  $SIZE_MB MB ($SIZE_MIB MiB) -> $K8_VERDICT"
echo "K9 cold start:   max ${COLD_MAX} ms, min ${COLD_MIN} ms, samples [$COLD_LIST] -> $K9_VERDICT"
echo "artifact: $OUT"
