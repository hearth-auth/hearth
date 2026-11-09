#!/usr/bin/env bash
# scripts/tests/check-mutants-budget.test.sh — tests for
# scripts/check-mutants-budget.py (#641, OpenSpec trusted-core-confidence 4.3).
#
# The budget check is the gate of the nightly mutation run. A check that only
# ever passes is a stub, so this test proves that it FAILS when a module has
# more survivors than its budget, and when a result cannot be trusted (a
# missing shard must not look like fewer survivors). It also proves that it
# passes when the count is equal or lower, and that a lower count tells the
# reader to lower the budget.
#
# No cargo build happens: the fixtures are outcomes.json files in the format
# that cargo-mutants writes.
#
# Usage: bash scripts/tests/check-mutants-budget.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-mutants-budget.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# budget <file> <alpha survivors or ""> <beta survivors or ""> — two modules.
# An empty value leaves `survivors` out.
budget() {
    local file="$1" a="$2" b="$3"
    {
        echo '[modules.alpha]'
        echo 'files = ["src/alpha/**"]'
        [[ -n "$a" ]] && echo "survivors = ${a}"
        echo
        echo '[modules.beta]'
        echo 'files = ["src/beta/**"]'
        [[ -n "$b" ]] && echo "survivors = ${b}"
    } > "$file"
}

# shard <results dir> <module> <k> <n> <outcome...> — one shard directory.
# An outcome is <summary>:<file>, for example MissedMutant:src/alpha/a.rs.
# The special outcome NOEND writes no end_time (a shard that did not finish);
# BASELINE-FAIL writes a failed baseline.
shard() {
    local results="$1" module="$2" k="$3" n="$4"
    shift 4
    local dir="${results}/mutants-${module}-${k}"
    mkdir -p "$dir"
    echo "${module} ${k} ${n}" > "${dir}/shard.txt"
    local end='"2026-11-09T05:00:00Z"' baseline='Success' items="" sep="" i=0
    for o in "$@"; do
        case "$o" in
            NOEND) end='null'; continue ;;
            BASELINE-FAIL) baseline='Failure'; continue ;;
        esac
        i=$((i + 1))
        items+="${sep}{\"scenario\":{\"Mutant\":{\"name\":\"${o#*:}:${i}:1: replace f\",\"file\":\"${o#*:}\"}},\"summary\":\"${o%%:*}\"}"
        sep=","
    done
    printf '{"outcomes":[{"scenario":"Baseline","summary":"%s"}%s%s],"end_time":%s}\n' \
        "$baseline" "${items:+,}" "$items" "$end" > "${dir}/outcomes.json"
}

# A complete result set: alpha in 2 shards has 2 survivors (one per shard)
# and a timeout, beta in 1 shard has 1 survivor.
full_results() {
    local results="$1"
    shard "$results" alpha 0 2 MissedMutant:src/alpha/a.rs CaughtMutant:src/alpha/a.rs Timeout:src/alpha/a.rs
    shard "$results" alpha 1 2 MissedMutant:src/alpha/b.rs Unviable:src/alpha/b.rs
    shard "$results" beta 0 1 MissedMutant:src/beta/c.rs CaughtMutant:src/beta/c.rs
}

# expect <passes|fails> <name> <budget file> <results dir> [text the output must contain]
expect() {
    local want="$1" name="$2" budget_file="$3" results="$4" needle="${5:-}" out rc
    out="$(python3 -I "$CHECK" --budget "$budget_file" "$results" 2>&1)"
    rc=$?
    if [[ "$want" == passes && $rc -ne 0 ]]; then
        fail "${name}: expected a pass, got exit ${rc}: ${out}"
        return
    fi
    if [[ "$want" == fails && $rc -eq 0 ]]; then
        fail "${name}: expected a failure, got a pass: ${out}"
        return
    fi
    if [[ -n "$needle" && "$out" != *"$needle"* ]]; then
        fail "${name}: the output does not contain '${needle}': ${out}"
        return
    fi
    pass "$name"
}

echo "check-mutants-budget.py"

# A new, empty directory for each case.
case_dir() { mktemp -d "${TMP}/case.XXXXXX"; }

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"
expect passes "the count equals the budget" "$d/b.toml" "$d/r" "alpha: tested 5, survivors 2, budget 2, timeouts 1: ok"

d="$(case_dir)"; budget "$d/b.toml" 1 1; full_results "$d/r"
expect fails "THE GATE: one more survivor than the budget" "$d/b.toml" "$d/r" \
    "alpha: 2 survivors, budget 1 (+1)"

d="$(case_dir)"; budget "$d/b.toml" 2 0; full_results "$d/r"
expect fails "a rise in one module fails although the other is equal" "$d/b.toml" "$d/r" \
    "beta: 1 survivors, budget 0 (+1)"

d="$(case_dir)"; budget "$d/b.toml" 5 1; full_results "$d/r"
expect passes "a lower count passes and says to lower the budget" "$d/b.toml" "$d/r" \
    "Lower the budget to 2 in ci/mutants-budget.toml"

d="$(case_dir)"; budget "$d/b.toml" "" 1; full_results "$d/r"
expect fails "a module with no recorded budget fails and gives the count" "$d/b.toml" "$d/r" \
    "Record \`survivors = 2\` under [modules.alpha]"

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"; rm -rf "$d/r/mutants-alpha-1"
expect fails "a missing shard fails (it must not look like fewer survivors)" "$d/b.toml" "$d/r" \
    "alpha: no result for shard(s) 1 of 2"

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"
shard "$d/r" alpha 1 2 NOEND MissedMutant:src/alpha/b.rs
expect fails "a shard that did not finish fails" "$d/b.toml" "$d/r" \
    "alpha: shard 1/2 did not finish"

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"
shard "$d/r" beta 0 1 BASELINE-FAIL MissedMutant:src/beta/c.rs
expect fails "a failed baseline fails" "$d/b.toml" "$d/r" \
    "beta: shard 0/1: the unmutated tree failed"

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"
mkdir -p "$d/r/copy" && cp "$d/r/mutants-beta-0/"* "$d/r/copy/"
expect fails "a shard reported twice fails" "$d/b.toml" "$d/r" "beta: shard 0/1 is reported twice"

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"
shard "$d/r" alpha 2 3 MissedMutant:src/alpha/b.rs
expect fails "shards that disagree on the shard count fail" "$d/b.toml" "$d/r" \
    "alpha: shards disagree on the shard count: [2, 3]"

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"; rm -rf "$d/r/mutants-beta-0"
expect fails "a module with no result at all fails" "$d/b.toml" "$d/r" \
    "beta: no shard reported a result"

d="$(case_dir)"; budget "$d/b.toml" 2 1; full_results "$d/r"
shard "$d/r" beta 0 1 MissedMutant:src/gamma/x.rs
expect fails "a mutant outside its module fails" "$d/b.toml" "$d/r" "not in this module"

d="$(case_dir)"; printf 'x = 1\n' > "$d/b.toml"; full_results "$d/r"
expect fails "a budget file with no modules fails" "$d/b.toml" "$d/r" "has no [modules.<name>] tables"

# --check-config: the cheap PR-time half. It reads the budget file only.
out="$(python3 -I "$CHECK" --check-config --budget "${SCRIPT_DIR}/../ci/mutants-budget.toml" 2>&1)" \
    && pass "--check-config accepts the real budget file" \
    || fail "--check-config refuses the real budget file: ${out}"

d="$(case_dir)"; printf '[modules.alpha]\nfiles = ["src/no-such-dir/**"]\n' > "$d/b.toml"
out="$(python3 -I "$CHECK" --check-config --budget "$d/b.toml" 2>&1)"
if [[ $? -ne 0 && "$out" == *"matches no file"* ]]; then
    pass "--check-config refuses a module whose files glob matches nothing"
else
    fail "--check-config accepted a glob that matches nothing: ${out}"
fi

echo
if [[ $failures -ne 0 ]]; then
    echo "${failures} case(s) failed"
    exit 1
fi
echo "all cases passed"
