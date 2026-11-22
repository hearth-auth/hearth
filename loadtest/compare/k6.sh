#!/usr/bin/env bash
# Runs one of the live k6 scripts (loadtest/live/k6) against a product of the
# comparison (#913), from the official k6 image pinned in images.env. For a
# host without k6; the AWS generators run the k6 binary that cloud.sh installs.
#
# Usage: k6.sh <bundle> <script> [VAR=value ...]
#   <bundle>   the product's bundle (for example .build/keycloak): generator.env
#              (PRODUCT, STRESS_*) and ca.crt; k6 output goes to <bundle>/out,
#              which the script sees as /out
#   <script>   stress.js or prepare.js
#   VAR=value  more k6 environment, for example JOURNEY=login START_RATE=5
#
# OUT=<name> (environment of k6.sh) also writes k6's per-request CSV to
# <bundle>/out/<name>.csv.gz and the console (ACK lines) to <name>.console.log,
# as remote/launch.sh does on a generator.
#
# Example, a 30 s check of the login journey at 5/s:
#   k6.sh .build/keycloak stress.js JOURNEY=login START_RATE=5 STEP_RATE=0 \
#     STEPS=1 HOLD_S=30 VUS=50 SUMMARY_OUT=/out/login.json
set -euo pipefail

usage="usage: k6.sh <bundle> <script> [VAR=value ...]"
bundle=$(cd "${1:?$usage}" && pwd)
script=${2:?$usage}
shift 2
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$here/images.env"

[ -f "$bundle/generator.env" ] || {
  echo "k6: $bundle/generator.env is missing" >&2
  exit 2
}
mkdir -p "$bundle/out"
# Every product of the comparison runs with PRESENT=chain (#913): each VU
# presents its own newest access token, as a real client does. With the
# #647 default (pool), VUs present tokens of other VUs' refresh chains, which
# a product that revokes the access token at refresh (Zitadel) refuses. The
# same condition for all products, Hearth included; stress.js keeps its
# default for the #647 rounds. A VAR=value below comes later and wins.
args=(-e PRESENT=chain)
for kv in "$@"; do
  [[ $kv == *=* ]] || {
    echo "k6: $kv is not VAR=value" >&2
    exit 2
  }
  args+=(-e "$kv")
done
out=()
[ -z "${OUT:-}" ] || out=(--out "csv=/out/$OUT.csv.gz" --console-output="/out/$OUT.console.log")
# --network host: the server listens on this host; lib.js maps its name to
# STRESS_SERVER_IP. The passwords reach k6 through --env-file only.
exec docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v "$here/../live/k6:/k6:ro" -v "$bundle/ca.crt:/trust.pem:ro" -v "$bundle/out:/out" \
  -w /k6 --env-file "$bundle/generator.env" -e SSL_CERT_FILE=/trust.pem "${args[@]}" \
  "$K6_IMAGE" run -q "${out[@]}" "/k6/$script"
