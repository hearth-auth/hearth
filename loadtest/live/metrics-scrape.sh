#!/usr/bin/env bash
# Scrapes Hearth's /metrics every 5 seconds until killed, keeping only the
# storage, WAL, KDF, connection and process series. Runs on the server.
# Each output line is "<epoch seconds> <metric line>".
#
# Usage: metrics-scrape.sh <out.txt>
# Reads STRESS_METRICS_TOKEN from /opt/hearth/hearth.env and trusts
# /opt/hearth/ca.crt.
set -euo pipefail

out=${1:?usage: metrics-scrape.sh <out.txt>}
token=$(sed -n 's/^STRESS_METRICS_TOKEN=//p' /opt/hearth/hearth.env | tr -d '"')
[ -n "$token" ] || { echo "no STRESS_METRICS_TOKEN in /opt/hearth/hearth.env" >&2; exit 1; }
keep='^(hearth_(storage|wal|kdf|connection|http_connections|active_connections|requests_in_flight)|process_)'

: > "$out"
while true; do
  ts=$(date +%s)
  curl -fsS --max-time 4 --cacert /opt/hearth/ca.crt \
    --resolve hearth.stress.test:8443:127.0.0.1 \
    -H "Authorization: Bearer $token" https://hearth.stress.test:8443/metrics 2> /dev/null \
    | grep -E "$keep" | grep -v '_bucket{' | sed "s/^/$ts /" >> "$out" || true
  sleep 5
done
