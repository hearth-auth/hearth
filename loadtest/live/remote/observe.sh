#!/usr/bin/env bash
# Observes the server for one ramp, for <seconds> or until its systemd unit is
# stopped: the Hearth process and the machine (sampler.sh), Hearth's /metrics
# (metrics-scrape.sh) and disk latency and use (iostat, every 5 s).
#
# Usage: observe.sh <name> <seconds>
set -uo pipefail

name=${1:?usage: observe.sh <name> <seconds>}
secs=${2:?usage: observe.sh <name> <seconds>}
out=/opt/hearth/out

timeout "$secs" /opt/hearth/sampler.sh "$out/$name.sampler.csv" &
timeout "$secs" /opt/hearth/metrics-scrape.sh "$out/$name.metrics.txt" &
timeout "$secs" iostat -dxty 5 > "$out/$name.iostat.txt" 2>&1 &
wait
