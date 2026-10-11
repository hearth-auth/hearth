#!/usr/bin/env bash
# Runs one k6 job on a generator, described by /opt/stress/out/<name>/params.env.
# cloud.sh starts it with systemd-run, so it outlives the SSH session that
# started it. Writes k6.exit when k6 ends.
#
# Usage: launch.sh <name>
set -uo pipefail

name=${1:?usage: launch.sh <name>}
dir=/opt/stress/out/$name
set -a
# shellcheck disable=SC1091
. /opt/stress/generator.env
# shellcheck disable=SC1091
. "$dir/params.env"
set +a
export SSL_CERT_FILE=/opt/stress/trust.pem
ulimit -n 1048576

bash /opt/stress/sampler.sh "$dir/gen-sampler.csv" '' k6 &
sampler=$!

# K6_NO_CSV=1 skips the per-request CSV (a long fill would write millions of rows).
out_args=(--out "csv=$dir/raw.csv.gz")
[ "${K6_NO_CSV:-}" != 1 ] || out_args=()
cd /opt/stress/k6 || exit 1
/usr/local/bin/k6 run -q "${out_args[@]}" --console-output="$dir/console.log" \
  "${K6_SCRIPT:-stress.js}" > "$dir/k6.txt" 2>&1
echo $? > "$dir/k6.exit"
kill "$sampler" 2> /dev/null || true
