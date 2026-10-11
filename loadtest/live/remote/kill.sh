#!/usr/bin/env bash
# Sends kill -9 to Hearth and records when. cloud.sh schedules it with
# systemd-run --on-active, so the kill happens on time without SSH.
#
# Usage: kill.sh <name>
set -uo pipefail

name=${1:?usage: kill.sh <name>}
if pkill -9 -x hearth; then
  date +%s.%N > "/opt/hearth/out/$name.killed_at"
fi
