#!/usr/bin/env bash
# HEA-1812: capture the ramp-to-knee (max comfortable RPS) and the unthrottled
# ceiling (hard failure ceiling) on a representative seeded corpus, then stash
# each report.json under loadtest/reports/hea1812/. Throwaway helper; deleted
# after the numbers land in the baseline + README.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export PROTOC="${PROTOC:-$(command -v protoc)}"
OUT=loadtest/reports/hea1812
mkdir -p "$OUT"

# Representative but tractable corpus (~300k users; labelled in the baseline).
CORPUS_ENV=(CORPUS_ACME=150000 CORPUS_GLOBEX=90000 CORPUS_INITECH=40000 \
  CORPUS_UMBRELLA=20000 HOT_TIER_CAPACITY=100000 SEED_WAIT=1800)

echo "############ RAMP-TO-KNEE ############"
env "${CORPUS_ENV[@]}" MODE=ramp RUN_TIME=30s HATCH_RATE=200 \
  EXTRA_RUN_ARGS="--ramp-start-users 250 --ramp-step-users 250 --ramp-steps 16" \
  loadtest/scripts/run-loadtest.sh
cp loadtest/reports/report.json "$OUT/ramp.json"
echo "RAMP report saved to $OUT/ramp.json"

echo "############ UNTHROTTLED CEILING ############"
env "${CORPUS_ENV[@]}" MODE=steady USERS=6000 RUN_TIME=60s HATCH_RATE=600 \
  loadtest/scripts/run-loadtest.sh
cp loadtest/reports/report.json "$OUT/ceiling.json"
echo "CEILING report saved to $OUT/ceiling.json"

echo "############ DONE ############"
