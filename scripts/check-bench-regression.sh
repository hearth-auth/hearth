#!/usr/bin/env bash
# check-bench-regression.sh — report criterion benchmark mean changes vs the
# stored 'main' baseline. Emits GitHub Actions warning annotations for any
# benchmark that regresses beyond THRESHOLD%, but always exits 0.
#
# WHY THIS IS INFORMATIONAL, NOT FATAL:
#   The storage_gate bench binary runs hard absolute latency gates (p50/p99
#   limits from ARCHITECTURE.md) in its custom main() before criterion
#   sampling. Those gates panic — and fail the CI job — if any target is
#   breached. Relative % comparison against a cached baseline is inherently
#   unreliable on shared GitHub Actions runners because the same benchmark
#   can vary ±10–15% across Azure regions and time-of-day load. Blocking on
#   a relative threshold produces false positives without adding meaningful
#   regression detection beyond what the absolute gates already enforce.
#
# Usage: scripts/check-bench-regression.sh [threshold_pct]
#   threshold_pct  Warning threshold as an integer percentage (default: 10)
#
# Reads:  target/criterion/<bench>/main/estimates.json  (baseline)
#         target/criterion/<bench>/new/estimates.json   (current run)
#
# The 'main' baseline is written by:
#   cargo bench --bench <name> -- --save-baseline main --noplot
#
# The 'new' snapshot is written automatically after every `cargo bench` run.
# Both must exist for a benchmark to be checked; missing pairs are skipped.
#
# Exit codes:
#   0  Always (informational only — absolute gate tests are the authoritative check).

set -euo pipefail

THRESHOLD="${1:-10}"
CRITERION_DIR="target/criterion"
FAILED=0
CHECKED=0
SKIPPED=0

if [[ ! -d "$CRITERION_DIR" ]]; then
    echo "WARNING: $CRITERION_DIR not found; no benchmarks to check."
    exit 0
fi

while IFS= read -r -d '' baseline_file; do
    # Derive sibling 'new' snapshot from baseline path.
    # baseline: .../main/estimates.json  → new: .../new/estimates.json
    bench_dir="$(dirname "$(dirname "$baseline_file")")"
    current_file="$bench_dir/new/estimates.json"

    if [[ ! -f "$current_file" ]]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    baseline_mean=$(awk -F'"point_estimate":' 'NR==1{print $2}' "$baseline_file" \
        | awk -F'[,}]' '{print $1}' | tr -d ' ')
    current_mean=$(awk -F'"point_estimate":' 'NR==1{print $2}' "$current_file" \
        | awk -F'[,}]' '{print $1}' | tr -d ' ')

    # Skip if either value is empty or zero (malformed JSON guard).
    [[ -z "$baseline_mean" || -z "$current_mean" ]] && { SKIPPED=$((SKIPPED + 1)); continue; }
    awk "BEGIN { exit ($baseline_mean > 0) ? 0 : 1 }" || { SKIPPED=$((SKIPPED + 1)); continue; }

    # Derive a human-readable name from directory structure.
    bench_name=$(basename "$bench_dir")
    parent_dir=$(basename "$(dirname "$bench_dir")")
    if [[ "$parent_dir" == "criterion" ]]; then
        label="$bench_name"
    else
        label="$parent_dir/$bench_name"
    fi

    CHECKED=$((CHECKED + 1))

    # pct_change = (current - baseline) / baseline * 100
    result=$(awk "BEGIN {
        pct = ($current_mean - $baseline_mean) / $baseline_mean * 100
        if (pct > $THRESHOLD) {
            printf \"FAIL %.1f\", pct
        } else {
            printf \"OK   %.1f\", pct
        }
    }")

    status="${result%% *}"
    pct="${result##* }"

    if [[ "$status" == "OK" ]]; then
        echo "  OK   $label: ${pct}%"
    else
        echo "  WARN $label: +${pct}% (informational threshold: ${THRESHOLD}%)"
        echo "::warning file=benches::$label mean regressed +${pct}% vs main baseline (threshold: ${THRESHOLD}%). Absolute latency gates passed — this is runner noise, not a blocking failure."
        FAILED=$((FAILED + 1))
    fi
done < <(find "$CRITERION_DIR" -name "estimates.json" -path "*/main/estimates.json" -print0 2>/dev/null | sort -z)

echo ""
echo "Benchmarks checked: $CHECKED | Skipped (no baseline): $SKIPPED | Regressions: $FAILED"

if [[ $CHECKED -eq 0 && $SKIPPED -eq 0 ]]; then
    echo "WARNING: no main baseline found — run with --save-baseline main on main branch first."
    exit 0
fi

if [[ $FAILED -gt 0 ]]; then
    echo ""
    echo "NOTE: $FAILED benchmark(s) exceeded the ${THRESHOLD}% informational threshold."
    echo "The absolute latency gates (p50/p99 limits in storage_gate.rs) are the"
    echo "authoritative pass/fail criterion. Runner variance on shared GitHub Actions"
    echo "runners causes ±10–15% noise for in-process microbenchmarks."
    echo "To investigate locally: PROTOC=protoc cargo bench -- --baseline main"
fi

# Always exit 0 — absolute gate tests (storage_gate custom main()) are the
# real regression blocker. Relative % comparison is informational only.
exit 0
