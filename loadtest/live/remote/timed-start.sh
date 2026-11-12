#!/usr/bin/env bash
# Starts Hearth and measures the time until /readyz first answers 200 (#647).
# It writes "<seconds> <outcome>" to /opt/hearth/out/<name>.start, where the
# outcome is "ready" or "timeout". kill.sh runs it after a kill -9 (crash
# steps); round.sh runs it after a clean stop (restart steps).
#
# Usage: timed-start.sh <name> [timeout_s, default 1800]
set -uo pipefail

name=${1:?usage: timed-start.sh <name> [timeout_s]}
limit=${2:-1800}
out=/opt/hearth/out/$name.start

ready() {
  [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 https://127.0.0.1:8443/readyz)" = 200 ]
}

systemctl reset-failed hearth 2> /dev/null || true
t0=$(date +%s.%N)
systemctl start hearth
outcome=timeout
while :; do
  if ready; then
    outcome=ready
    break
  fi
  elapsed=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { print int(b - a) }')
  [ "$elapsed" -lt "$limit" ] || break
  sleep 0.2
done
awk -v a="$t0" -v b="$(date +%s.%N)" -v o="$outcome" 'BEGIN { printf "%.1f %s\n", b - a, o }' > "$out"
[ "$outcome" = ready ]
