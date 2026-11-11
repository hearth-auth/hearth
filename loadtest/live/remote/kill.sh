#!/usr/bin/env bash
# Sends kill -9 to Hearth and records when. cloud.sh schedules it with
# systemd-run --on-active, so the kill happens on time without SSH.
#
# With "restart" (a crash step of round.sh, #647), it then waits for the
# process to go and starts Hearth again with timed-start.sh, which records the
# time to ready.
#
# Usage: kill.sh <name> [restart]
set -uo pipefail

name=${1:?usage: kill.sh <name> [restart]}
if pkill -9 -x hearth; then
  date +%s.%N > "/opt/hearth/out/$name.killed_at"
fi
if [ "${2:-}" = restart ]; then
  for _ in $(seq 1 100); do pgrep -x hearth > /dev/null || break; sleep 0.1; done
  exec /opt/hearth/timed-start.sh "$name"
fi
