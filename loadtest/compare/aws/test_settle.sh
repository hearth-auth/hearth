#!/usr/bin/env bash
# remote.sh settle (#913): a seed server's store has settled when the device
# that holds it (the data volume) has written less than SETTLE_IDLE_KBPS for
# SETTLE_QUIET_S in a row. Checks, with a made-up /proc/diskstats
# (SETTLE_DISKSTATS) and 1 s steps:
#   - a store that keeps changing at an idle trickle settles: Zitadel's
#     projections write their positions about once a second while idle, so
#     its files never stop changing (the first rule, no file changed for 60 s,
#     would have stopped the Zitadel seed after SETTLE_MAX_S)
#   - a store that writes hard, then stops, settles only after it stops
#   - a store that never stops writing hard fails after SETTLE_MAX_S
#
# Usage: bash loadtest/compare/aws/test_settle.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
writer=""
trap '[ -z "$writer" ] || kill "$writer" 2> /dev/null; rm -rf "$tmp"' EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

store=$tmp/store
mkdir -p "$store"
devno=$(findmnt -no MAJ:MIN --target "$store" | tr -d "[:space:]")
stats=$tmp/diskstats

# Writes the fake diskstats line of the store's device: <sectors> written.
put() {
  printf '%s %s fake 0 0 0 0 0 0 %s 0 0 0 0 0 0 0 0 0 0\n' "${devno%%:*}" "${devno##*:}" "$1" > "$stats.new"
  mv "$stats.new" "$stats"
}

# Runs in the background: every 0.25 s, <sectors> more written (and a file of
# the store changed) until <until> s from now, then <after> sectors.
write() {
  local per=$1 until=$2 after=$3 n=0 end
  end=$(($(date +%s) + until))
  while :; do
    if [ "$(date +%s)" -lt "$end" ]; then n=$((n + per)); else n=$((n + after)); fi
    put "$n"
    date +%s%N > "$store/position"
    sleep 0.25
  done
}

settle() {
  SETTLE_DISKSTATS=$stats SETTLE_STEP_S=1 SETTLE_QUIET_S=3 SETTLE_IDLE_KBPS=512 SETTLE_MAX_S=${1:-20} \
    bash "$here/remote.sh" settle "$store" > "$tmp/out" 2>&1
}
stop() {
  kill "$writer" 2> /dev/null
  wait "$writer" 2> /dev/null
  writer=""
}

# Zitadel at idle: about 80 KB/s (160 sectors/s), its files change all the time.
put 0
write 40 0 40 &
writer=$!
t0=$(date +%s)
if settle && grep -q '^settled after' "$tmp/out"; then
  pass "a store that changes at an idle trickle settles ($(($(date +%s) - t0)) s)"
else
  fail "a store that changes at an idle trickle does not settle: $(tail -n 1 "$tmp/out")"
fi
stop

# 4 MiB/s (8192 sectors/s) for 5 s, then nothing.
put 0
write 2048 5 0 &
writer=$!
t0=$(date +%s)
if settle; then
  took=$(($(date +%s) - t0))
  if [ "$took" -ge 7 ]; then
    pass "a store that writes hard settles after it stops ($took s)"
  else
    fail "a store that writes hard for 5 s settled after $took s, before 5 s + 3 s quiet"
  fi
else
  fail "a store that writes hard, then stops, does not settle: $(tail -n 1 "$tmp/out")"
fi
stop

# 4 MiB/s all the time.
put 0
write 2048 3600 2048 &
writer=$!
if settle 6; then
  fail "a store that never stops writing hard settled"
elif grep -q 'FAILED: .* still writes' "$tmp/out"; then
  pass "a store that never stops writing hard fails after SETTLE_MAX_S"
else
  fail "a store that never stops writing hard: not the still-writes failure: $(tail -n 1 "$tmp/out")"
fi
stop

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all settle checks passed"
