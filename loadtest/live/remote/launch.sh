#!/usr/bin/env bash
# Runs one k6 job on a generator, described by /opt/stress/out/<name>/params.env.
# cloud.sh starts it with systemd-run, so it outlives the SSH session that
# started it. Writes k6.exit when k6 ends.
#
# Usage: launch.sh <name>
# STRESS_ROOT and STRESS_K6 stand in for /opt/stress and /usr/local/bin/k6
# (test_env.sh only; systemd-run passes no environment).
set -uo pipefail

name=${1:?usage: launch.sh <name>}
root=${STRESS_ROOT:-/opt/stress}
k6=${STRESS_K6:-/usr/local/bin/k6}
dir=$root/out/$name
# Both files are data, never shell code (a generator.env value may hold `$`,
# quotes or spaces: env.sh). A file that does not load ends the job here,
# without k6.exit: cloud.sh's wait_job then fails the job at once.
# shellcheck source=env.sh
. "$root/env.sh" || exit 1
load_env "$root/generator.env" || exit 1
load_env "$dir/params.env" || exit 1
export SSL_CERT_FILE=$root/trust.pem
ulimit -n 1048576

bash "$root/sampler.sh" "$dir/gen-sampler.csv" '' k6 &
sampler=$!

# K6_NO_CSV=1 skips the per-request CSV (a long fill would write millions of rows).
out_args=(--out "csv=$dir/raw.csv.gz")
[ "${K6_NO_CSV:-}" != 1 ] || out_args=()
cd "$root/k6" || exit 1
"$k6" run -q "${out_args[@]}" --console-output="$dir/console.log" \
  "${K6_SCRIPT:-stress.js}" > "$dir/k6.txt" 2>&1
echo $? > "$dir/k6.exit"
kill "$sampler" 2> /dev/null || true
