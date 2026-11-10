#!/usr/bin/env bash
# scripts/tests/check-monitoring.test.sh — tests for check-monitoring.sh (#648).
#
# The guard must be shown to FAIL on each shape it exists to catch, not only
# to pass on the shipped files.
#
#   case 1  the shipped files pass
#   case 2  an alert rule with a PromQL syntax error
#   case 3  a dashboard expression with a PromQL syntax error
#   case 4  an alert threshold that no longer matches its unit test
#   case 5  a missing dashboard file
#
# Usage: bash scripts/tests/check-monitoring.test.sh

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/scripts/check-monitoring.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

# new_case: a fresh copy of deploy/monitoring; prints its path.
new_case() {
    local dir
    dir="$(mktemp -d "$TMP/case-XXXX")"
    cp -R "${ROOT}/deploy/monitoring/." "$dir/"
    printf '%s' "$dir"
}

# expect <name> <expected-exit> <dir>
expect() {
    local name="$1" want="$2" dir="$3" got
    case_n=$((case_n + 1))
    bash "$CHECK" "$dir" >"$TMP/out" 2>&1
    got=$?
    if { [ "$want" -eq 0 ] && [ "$got" -eq 0 ]; } || { [ "$want" -ne 0 ] && [ "$got" -ne 0 ]; }; then
        echo "ok   ${name}"
    else
        echo "FAIL ${name}: exit ${got}, want ${want}"
        sed 's/^/     /' "$TMP/out"
        failures=$((failures + 1))
    fi
}

dir="$(new_case)"
expect "shipped files pass" 0 "$dir"

dir="$(new_case)"
sed -i 's/expr: up{job="hearth"} == 0/expr: up{job="hearth"} == = 0/' "$dir/prometheus/hearth-alerts.yml"
grep -q '== = 0' "$dir/prometheus/hearth-alerts.yml" || { echo "FAIL case 2 setup"; failures=$((failures + 1)); }
expect "alert rule with a PromQL syntax error fails" 1 "$dir"

dir="$(new_case)"
python3 -I - "$dir/grafana/hearth-dashboard.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
for panel in d["panels"]:
    if panel.get("targets"):
        panel["targets"][0]["expr"] = "sum(rate(hearth_storage_sst_files[5m]"
        break
json.dump(d, open(p, "w"))
PY
expect "dashboard expression with a PromQL syntax error fails" 1 "$dir"

dir="$(new_case)"
sed -i 's/total_bytes{job="hearth"} < 0.15/total_bytes{job="hearth"} < 0.01/' "$dir/prometheus/hearth-alerts.yml"
grep -q '< 0.01' "$dir/prometheus/hearth-alerts.yml" || { echo "FAIL case 4 setup"; failures=$((failures + 1)); }
expect "alert threshold that breaks its unit test fails" 1 "$dir"

dir="$(new_case)"
rm "$dir/grafana/hearth-dashboard.json"
expect "missing dashboard fails" 1 "$dir"

if [ "$failures" -ne 0 ]; then
    echo "check-monitoring.test.sh: ${failures} of ${case_n} cases failed"
    exit 1
fi
echo "check-monitoring.test.sh: all ${case_n} cases passed"
