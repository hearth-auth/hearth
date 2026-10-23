#!/usr/bin/env bash
# The steady-state memory test (#445) on one Linux host. It runs a production-mode
# Hearth server with small cache limits and short lifetimes, so every cache reaches
# its limit and the cleanup sweep deletes rows as fast as the load creates them. It
# drives the soak's k6 mix against the server, scrapes /metrics every 5 seconds, and
# ends with steady_heap.py's verdict.
#
# The weekly workflow (.github/workflows/steady-memory.yml) runs it on a GitHub-hosted
# runner. It needs passwordless sudo once: the generated config uses /opt/hearth and
# /var/lib/hearth, as on the AWS server, and both must not exist yet.
#
# Usage: steady-memory.sh <hearth binary> <out dir>
#
# Environment (default):
#   K6                        the k6 binary (k6)
#   RATE                      journeys per second (120)
#   VUS                       k6 VUs (500)
#   LOAD_MIN                  minutes of load (300): the latest steady start, 120,
#                             plus the 180-minute window
#   LOGIN_USERS               users with a password (1000)
#   HOT_TIER_CAPACITY         storage.hot_tier_capacity (20000)
#   BLOCK_CACHE_BYTES         storage.block_cache_bytes (33554432)
#   MEMTABLE_FLUSH_BYTES      storage.memtable_flush_bytes (8388608)
#   COMPACTION_INTERVAL_SECS  storage.compaction.interval_secs (600)
#   CLAIMS_CACHE_MAX          token.claims_cache_max (2048)
#   ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL, SESSION_TTL  (5m, 10m, 10m)
#   HEAP_PROFILE              1: a heap-profile run (0). The binary must be a
#                             --features heap-profile build. The server writes a
#                             jemalloc heap profile to <out dir>/jeprof at each
#                             HEAP_PROFILE_INTERVAL_SECS (300)
#
# The out dir receives server.log, metrics.txt, sampler.csv, k6-summary.json,
# k6.txt and verdict.txt. The exit status is steady_heap.py's (0 on PASS), or 2 when the
# test could not run. The profiler changes the heap, so the verdict of a
# heap-profile run does not count: its exit status is 0 when the server wrote
# profiles.
set -euo pipefail

usage="usage: steady-memory.sh <hearth binary> <out dir>"
hearth=$(realpath "${1:?$usage}")
mkdir -p "${2:?$usage}"
out=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")" && pwd)

K6=${K6:-k6}
RATE=${RATE:-120}
VUS=${VUS:-500}
LOAD_MIN=${LOAD_MIN:-300}
LOGIN_USERS=${LOGIN_USERS:-1000}
export HOT_TIER_CAPACITY=${HOT_TIER_CAPACITY:-20000}
export BLOCK_CACHE_BYTES=${BLOCK_CACHE_BYTES:-33554432}
export MEMTABLE_FLUSH_BYTES=${MEMTABLE_FLUSH_BYTES:-8388608}
export COMPACTION_INTERVAL_SECS=${COMPACTION_INTERVAL_SECS:-600}
export CLAIMS_CACHE_MAX=${CLAIMS_CACHE_MAX:-2048}
export ACCESS_TOKEN_TTL=${ACCESS_TOKEN_TTL:-5m}
export REFRESH_TOKEN_TTL=${REFRESH_TOKEN_TTL:-10m}
export SESSION_TTL=${SESSION_TTL:-10m}
HEAP_PROFILE=${HEAP_PROFILE:-0}
HEAP_PROFILE_INTERVAL_SECS=${HEAP_PROFILE_INTERVAL_SECS:-300}

log() { printf 'steady-memory: %s\n' "$*" >&2; }
die() {
  log "FAILED: $*"
  exit 2
}

for dir in /opt/hearth /var/lib/hearth; do
  [ ! -e "$dir" ] || die "$dir exists; the test needs a host without a Hearth install"
done

work=$(mktemp -d)
pids=()
cleanup() {
  local pid
  for pid in "${pids[@]}"; do
    kill "$pid" 2> /dev/null || true
  done
  wait 2> /dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

bash "$here/gen-config.sh" "$work/bundle" 127.0.0.1 "$LOGIN_USERS"
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 /opt/hearth /var/lib/hearth
cp -r "$work/bundle/server/." /opt/hearth/
cp "$work/bundle/ca.crt" /opt/hearth/ca.crt
cat "$work/bundle/ca.crt" /etc/ssl/certs/ca-certificates.crt > "$work/trust.pem"
cp "$work/bundle/generator.env" "$work/generator.env"

profile_conf=
if [ "$HEAP_PROFILE" = 1 ]; then
  mkdir -p "$out/jeprof"
  # README, "Heap accounting": one sampled call stack per 512 KiB allocated.
  profile_conf="prof:true,lg_prof_sample:19,prof_prefix:$out/jeprof/hearth"
fi

log "starting hearth ($hearth)"
(
  set -a
  # shellcheck disable=SC1091
  . /opt/hearth/hearth.env
  if [ -n "$profile_conf" ]; then
    _RJEM_MALLOC_CONF=$profile_conf
    HEARTH_HEAP_PROFILE_INTERVAL_SECS=$HEAP_PROFILE_INTERVAL_SECS
  fi
  set +a
  exec "$hearth" serve --config /opt/hearth/hearth.yaml
) > "$out/server.log" 2>&1 &
server=$!
pids+=("$server")
# Hearth's thread count, RSS and CPU, once a second.
bash "$here/sampler.sh" "$out/sampler.csv" "" "$(basename "$hearth")" &
pids+=("$!")

ready() {
  curl -fsS -o /dev/null --max-time 4 --cacert /opt/hearth/ca.crt \
    --resolve hearth.stress.test:8443:127.0.0.1 https://hearth.stress.test:8443/readyz 2> /dev/null
}
# Start-up hashes every seed user's password with Argon2id.
for _ in $(seq 1 600); do
  kill -0 "$server" 2> /dev/null || {
    tail -n 40 "$out/server.log" >&2
    die "hearth exited during start-up"
  }
  ! ready || break
  sleep 1
done
ready || die "hearth is not ready after 600 s"
if [ "$HEAP_PROFILE" = 1 ]; then
  # The start-up log of a heap-profile build with the profiler on (src/main.rs).
  grep -q 'writing a jemalloc heap profile at each interval' "$out/server.log" \
    || die "the server writes no heap profiles: is $hearth a --features heap-profile build?"
fi

k6_env() {
  cd "$here/k6"
  set -a
  # shellcheck disable=SC1091
  . "$work/generator.env"
  set +a
  export SSL_CERT_FILE=$work/trust.pem
  "$@"
}

log "regenerating the api client's secret (prepare.js)"
(k6_env env PREPARE_CLIENTS=1 PREPARE_OUT="$work/prepare.json" "$K6" run -q prepare.js) \
  > "$out/prepare.txt" 2>&1 || die "prepare.js failed (see prepare.txt)"
secret=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["api_secret"])' \
  "$work/prepare.json")
sed -i '/^STRESS_API_SECRET=/d' "$work/generator.env"
printf 'STRESS_API_SECRET=%s\n' "$secret" >> "$work/generator.env"

bash "$here/metrics-scrape.sh" "$out/metrics.txt" &
pids+=("$!")

log "k6 mix at $RATE journeys/s for $LOAD_MIN min ($VUS VUs)"
status=0
(k6_env env JOURNEY=mix START_RATE="$RATE" STEP_RATE=0 STEPS=1 HOLD_S=$((LOAD_MIN * 60)) \
  VUS="$VUS" RUN_ID=steady CHAIN_REFRESHES=20 PRESENT=chain \
  SUMMARY_OUT="$out/k6-summary.json" "$K6" run -q stress.js) > "$out/k6.txt" 2>&1 || status=$?
log "k6 ended with status $status"
[ -s "$out/k6-summary.json" ] || die "k6 wrote no summary (see k6.txt)"

cleanup
trap - EXIT

set +e
if [ "$HEAP_PROFILE" = 1 ]; then
  echo "heap-profile run: the profiler is on, so this verdict does not count" \
    | tee "$out/verdict.txt"
else
  : > "$out/verdict.txt"
fi
python3 "$here/steady_heap.py" --hot-tier-capacity "$HOT_TIER_CAPACITY" \
  --block-cache-bytes "$BLOCK_CACHE_BYTES" --duration-s $((LOAD_MIN * 60)) \
  --target-rate "$RATE" "$out" | tee -a "$out/verdict.txt"
status=${PIPESTATUS[0]}
if [ "$HEAP_PROFILE" = 1 ]; then
  profiles=$(find "$out/jeprof" -name '*.heap' | wc -l)
  log "$profiles heap profiles in $out/jeprof"
  [ "$profiles" -gt 0 ] || die "the server wrote no heap profiles"
  status=0
fi
exit "$status"
