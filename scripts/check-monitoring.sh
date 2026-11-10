#!/usr/bin/env bash
# Checks the shipped Prometheus alert rules and Grafana dashboard (#648).
#
#   1. `promtool check rules` on prometheus/hearth-alerts.yml.
#   2. `promtool test rules` on prometheus/hearth-alerts.test.yml.
#   3. Every PromQL expression in grafana/hearth-dashboard.json parses: each
#      one becomes a recording rule in a temporary file for `promtool check
#      rules`. The dashboard variable `$instance` is replaced by `.*`.
#
# tests/metric_names_in_docs.rs checks that the metric names exist.
#
# Usage: scripts/check-monitoring.sh [monitoring-dir]   (default deploy/monitoring)
#
# promtool comes from $PROMTOOL, else from PATH, else from the Prometheus
# image below, run with Docker without network access.
set -euo pipefail

# prom/prometheus 3.15.0, pinned by digest.
IMAGE="prom/prometheus@sha256:efd719c99d83b060d9daefdcf00360461adf279f45ef5391f8d111892118753e"

dir="${1:-deploy/monitoring}"
rules="$dir/prometheus/hearth-alerts.yml"
rule_tests="$dir/prometheus/hearth-alerts.test.yml"
dashboard="$dir/grafana/hearth-dashboard.json"
for f in "$rules" "$rule_tests" "$dashboard"; do
  [ -f "$f" ] || { echo "check-monitoring: missing $f" >&2; exit 1; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$rules" "$work/hearth-alerts.yml"
cp "$rule_tests" "$work/hearth-alerts.test.yml"

python3 -I - "$dashboard" "$work/dashboard-exprs.yml" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    dashboard = json.load(f)
exprs = []
def walk(panels):
    for panel in panels:
        for target in panel.get("targets", []):
            if target.get("expr"):
                exprs.append((panel.get("title", "?"), target["expr"]))
        walk(panel.get("panels", []))
walk(dashboard.get("panels", []))
if not exprs:
    sys.exit("check-monitoring: the dashboard has no PromQL expressions")
with open(sys.argv[2], "w") as out:
    out.write("groups:\n  - name: dashboard\n    rules:\n")
    for i, (title, expr) in enumerate(exprs):
        expr = expr.replace("$instance", ".*")
        out.write(f"      - record: dashboard:expr_{i}\n")
        out.write(f"        expr: {json.dumps(expr)}\n")
print(f"check-monitoring: {len(exprs)} dashboard expressions")
PY

run_promtool() {
  if [ -n "${PROMTOOL:-}" ]; then
    (cd "$work" && "$PROMTOOL" "$@")
  elif command -v promtool >/dev/null 2>&1; then
    (cd "$work" && command promtool "$@")
  else
    docker run --rm --network none -u "$(id -u):$(id -g)" \
      -v "$work:/w:ro" -w /w --entrypoint promtool "$IMAGE" "$@"
  fi
}

run_promtool check rules hearth-alerts.yml
run_promtool test rules hearth-alerts.test.yml
run_promtool check rules dashboard-exprs.yml
echo "check-monitoring: OK"
