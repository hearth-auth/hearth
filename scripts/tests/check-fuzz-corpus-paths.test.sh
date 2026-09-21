#!/usr/bin/env bash
# scripts/tests/check-fuzz-corpus-paths.test.sh — tests for
# scripts/check-fuzz-corpus-paths.sh (production-readiness task 26.30).
#
# A guard with no red case is not a guard. Every rule below is fed the shape it
# exists to refuse, including the exact shape that was at HEAD:
#
#   case 1  the remediated shape passes
#   case 2  R1 — THE DEFECT: "$SEEDS" as libFuzzer's first corpus argument
#   case 3  R1 — a literal fuzz/seeds/<target> path first
#   case 4  R1 — no corpus argument at all (libFuzzer writes into ./)
#   case 5  R1 — a fuzz workflow with no `cargo fuzz run` line (guard rot)
#   case 6  R2 — the writable corpus is not gitignored
#   case 7  R3 — "fixing" it by gitignoring the tracked seeds instead
#   case 8  prose quoting the audited invocation must NOT trip the rule
#   case 9  the checked-in repository passes
#
# Usage: bash scripts/tests/check-fuzz-corpus-paths.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-fuzz-corpus-paths.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

GOOD_GITIGNORE='/target/
fuzz/artifacts/
fuzz/corpus/
fuzz/target/
'

# The remediated fuzz.yml run step.
GOOD_RUN='          SEEDS="fuzz/seeds/${{ matrix.target }}"
          CORPUS="fuzz/corpus/${{ matrix.target }}"
          mkdir -p "$CORPUS"
          if [ -d "$SEEDS" ]; then
            cargo fuzz run ${{ matrix.target }} "$CORPUS" "$SEEDS" -- -runs=1000
          else
            cargo fuzz run ${{ matrix.target }} "$CORPUS" -- -runs=1000
          fi
'

# run_case <name> <expected-exit> <run-block> <gitignore> [expected-substring]
run_case() {
    local name="$1" want="$2" run_block="$3" gitignore="$4" expect="${5:-}"
    case_n=$((case_n + 1))
    local dir="${TMP}/case-${case_n}"
    mkdir -p "${dir}/.github/workflows"
    printf '%s' "$gitignore" > "${dir}/.gitignore"
    {
        echo 'name: Fuzz'
        echo 'jobs:'
        echo '  fuzz:'
        echo '    steps:'
        echo '      - name: Fuzz smoke'
        echo '        run: |'
        printf '%s' "$run_block"
    } > "${dir}/.github/workflows/fuzz.yml"

    local out got=0
    out="$(REPO_ROOT="$dir" bash "$CHECK" 2>&1)" || got=$?
    if [[ "$got" -ne "$want" ]]; then
        echo "FAIL: ${name} — expected exit ${want}, got ${got}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    if [[ -n "$expect" && "$out" != *"$expect"* ]]; then
        echo "FAIL: ${name} — output missing expected text: ${expect}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${name}"
}

# 1 — the remediated shape.
run_case "the remediated shape passes" 0 "$GOOD_RUN" "$GOOD_GITIGNORE" \
    "libFuzzer writes only into gitignored corpus directories"

# 2 — THE DEFECT AT HEAD (F-7). `cargo fuzz run <target> "$SEEDS"` makes the
#     tracked, reviewed seed corpus the fuzzer's output directory. Two 2 000-run
#     passes left between 14 and 364 generated files in each seed directory.
run_case "R1 rejects \$SEEDS as the first corpus argument" 1 \
'          SEEDS="fuzz/seeds/${{ matrix.target }}"
          if [ -d "$SEEDS" ]; then
            cargo fuzz run ${{ matrix.target }} "$SEEDS" -- -runs=1000
          else
            cargo fuzz run ${{ matrix.target }} -- -runs=1000
          fi
' "$GOOD_GITIGNORE" \
    "the TRACKED seed corpus is libFuzzer's FIRST"

# 3 — the same defect spelled out literally rather than through a variable.
run_case "R1 rejects a literal fuzz/seeds path first" 1 \
'          cargo fuzz run ${{ matrix.target }} fuzz/seeds/${{ matrix.target }} -- -runs=1000
' "$GOOD_GITIGNORE" \
    "the TRACKED seed corpus is libFuzzer's FIRST"

# 4 — no corpus at all: libFuzzer then writes discovered units into the
#     working directory, which is the repository root.
run_case "R1 rejects an invocation with no corpus directory" 1 \
'          cargo fuzz run ${{ matrix.target }} -- -runs=1000
' "$GOOD_GITIGNORE" \
    "names no corpus directory"

# 5 — guard rot: a fuzz workflow whose invocation has been renamed or moved
#     out of reach would otherwise make this script pass on zero findings.
run_case "a fuzz workflow with no invocation is rejected, not silently passed" 1 \
'          echo "fuzzing disabled for now"
' "$GOOD_GITIGNORE" \
    "no \`cargo fuzz run\` line was found"

# 6 — R2: writing into a directory that is not gitignored leaves the discovered
#     inputs untracked in `git status`.
run_case "R2 rejects a writable corpus that is not gitignored" 1 "$GOOD_RUN" \
'/target/
fuzz/artifacts/
fuzz/target/
' \
    "is NOT gitignored"

# 7 — R3: the wrong fix. Gitignoring fuzz/seeds/ makes `git status` clean and
#     destroys the reviewed seed corpus the split exists to protect.
run_case "R3 rejects gitignoring the tracked seed corpus" 1 "$GOOD_RUN" \
'/target/
fuzz/artifacts/
fuzz/corpus/
fuzz/seeds/
fuzz/target/
' \
    "must stay tracked"

# 8 — the guard must not cry wolf. ci.yml quotes the audited invocation
#     verbatim in the comment that explains why this guard exists. A gate that
#     fails on its own rationale gets switched off, which is the fail-open the
#     guard is here to prevent.
run_case "prose quoting the audited invocation does not trip the rule" 0 \
'          # The defect: cargo fuzz run ${{ matrix.target }} "$SEEDS" made the
          # TRACKED seed corpus libFuzzer'"'"'s write directory.
          SEEDS="fuzz/seeds/${{ matrix.target }}"
          CORPUS="fuzz/corpus/${{ matrix.target }}"
          mkdir -p "$CORPUS"
          cargo fuzz run ${{ matrix.target }} "$CORPUS" "$SEEDS" -- -runs=1000
' "$GOOD_GITIGNORE" \
    "libFuzzer writes only into gitignored corpus directories"

# 9 — the checked-in repository passes.
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    echo "ok: the repository's own .github/workflows and .gitignore pass"
else
    echo "FAIL: the checked-in tree does not pass"
    sed 's/^/    /' <<<"$out"
    failures=$((failures + 1))
fi

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} guard self-test failure(s)."
    exit 1
fi
echo "OK: guard self-tests passed."
exit 0
