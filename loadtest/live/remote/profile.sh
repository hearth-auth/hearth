#!/usr/bin/env bash
# Profiles Hearth for <seconds>: where it uses the CPU (perf, 99 Hz with call
# stacks) and where its threads wait off the CPU (offcputime, folded stacks).
# Use it on a ramp step whose ceiling the CPU does not explain.
#
# Usage: profile.sh <name> <seconds>
set -uo pipefail

name=${1:?usage: profile.sh <name> <seconds>}
secs=${2:?usage: profile.sh <name> <seconds>}
out=/opt/hearth/out
pid=$(pgrep -o -x hearth) || { echo "no hearth process" > "$out/$name.profile-error"; exit 1; }

perf record -q -F 99 -g -p "$pid" -o "$out/$name.perf.data" -- sleep "$secs" 2> "$out/$name.perf.err" &
offcputime-bpfcc -f -p "$pid" "$secs" > "$out/$name.offcpu.folded" 2> "$out/$name.offcpu.err" &
wait
perf report -q --stdio --no-children -i "$out/$name.perf.data" --percent-limit 0.5 \
  > "$out/$name.perf.txt" 2>> "$out/$name.perf.err" || true
