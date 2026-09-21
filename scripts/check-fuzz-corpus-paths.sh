#!/usr/bin/env bash
# scripts/check-fuzz-corpus-paths.sh — libFuzzer must never be handed the
# TRACKED seed corpus as the directory it writes into.
#
# Production-readiness task 26.30 (audit
# reports/subsystem-audit-fuzz-loadtest-2026-09-21.md, finding F-7):
#
#   `.github/workflows/fuzz.yml` ran `cargo fuzz run <target> "$SEEDS"`.
#   libFuzzer treats its FIRST corpus argument as the directory it WRITES
#   newly-discovered units into; every later argument is a read-only input
#   directory. So `fuzz/seeds/<target>/` — hand-written, reviewed and
#   version-controlled — was also the fuzzer's output directory. Two 2 000-run
#   passes over the eleven targets left between 14 and 364 machine-generated
#   files in each seed directory. On a CI runner the checkout is discarded, so
#   the discovered inputs are thrown away rather than promoted; on a developer's
#   machine the documented command dirties the repository, in a tree where
#   `git add -A` is a documented hazard.
#
# The rule is a property of the argument ORDER, which is why it is checkable as
# text and needs no Rust build:
#
#   R1  Every `cargo fuzz run` in the workflow directory passes a writable
#       corpus directory as its FIRST positional argument, and that directory
#       must NOT be under `fuzz/seeds/`.
#   R2  The writable corpus directory each invocation names is gitignored, so a
#       local run cannot leave untracked files in `git status`. (Checked against
#       the repository's own .gitignore; skipped when it is absent.)
#   R3  `fuzz/seeds/` stays tracked — the split between reviewed seeds and
#       machine-accumulated corpus is the thing this guard protects, and a
#       "fix" that gitignores the seeds instead would destroy it.
#
# Usage:  bash scripts/check-fuzz-corpus-paths.sh
# Env:    REPO_ROOT     tree to inspect (default: this script's repository)
#         WORKFLOW_DIR  workflow directory (default: $REPO_ROOT/.github/workflows)

set -uo pipefail

DEFAULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${REPO_ROOT:-$DEFAULT_ROOT}"
WORKFLOW_DIR="${WORKFLOW_DIR:-${REPO_ROOT}/.github/workflows}"
GITIGNORE="${REPO_ROOT}/.gitignore"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}
pass() { echo "ok:   $*"; }

if [[ ! -d "$WORKFLOW_DIR" ]]; then
    fail "R1: ${WORKFLOW_DIR} not found; there is no fuzz invocation to inspect."
    echo ""
    echo "✗ fuzz corpus guard: ${failures} rule(s) failed."
    exit 1
fi

# Every `cargo fuzz run` line in any workflow, with its file and line number.
#
# YAML comment lines are excluded. ci.yml carries a comment quoting the audited
# `cargo fuzz run <target> "$SEEDS"` invocation to explain why this guard
# exists; a gate that fails on its own rationale gets switched off, which is
# the fail-open the guard is here to prevent (same lesson as R3 in
# scripts/check-red-test-gate.sh).
mapfile -t RUN_LINES < <(
    find "$WORKFLOW_DIR" -maxdepth 1 \( -name '*.yml' -o -name '*.yaml' \) \
        | sort \
        | xargs grep -Hn 'cargo fuzz run' 2>/dev/null \
        | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#'
)

if [[ "${#RUN_LINES[@]}" -eq 0 ]]; then
    # Nothing to guard is not a pass: fuzz.yml exists in this repository and a
    # silent "0 invocations found" is exactly how a text guard rots into a
    # no-op. Only accept it when there is genuinely no fuzz workflow.
    if find "$WORKFLOW_DIR" -maxdepth 1 -name 'fuzz*.y*ml' | grep -q .; then
        fail "R1: a fuzz workflow exists but no \`cargo fuzz run\` line was found." \
            $'\n      The guard would silently pass on every future change.'
    else
        pass "R1: no fuzz workflow in ${WORKFLOW_DIR}; nothing to guard."
    fi
else
    corpus_dirs=""
    for entry in "${RUN_LINES[@]}"; do
        file="${entry%%:*}"
        rest="${entry#*:}"
        lineno="${rest%%:*}"
        body="${rest#*:}"

        # Collapse `${{ matrix.target }}` to a single word FIRST: it contains
        # spaces, so naive word-splitting would make `matrix.target` look like
        # the corpus argument and the guard would report nonsense.
        body_norm="$(sed -E 's/\$\{\{[^}]*\}\}/TARGET/g' <<<"$body")"
        # Everything after `cargo fuzz run`, up to `--` (libFuzzer's own flags)
        # or end of line.
        args="${body_norm#*cargo fuzz run }"
        args="${args%%--*}"
        # shellcheck disable=SC2206  # deliberate word splitting on the arg list
        parts=($args)

        if [[ "${#parts[@]}" -lt 2 ]]; then
            fail "R1: ${file}:${lineno}: \`cargo fuzz run\` names no corpus directory." \
                $'\n      With no positional corpus, libFuzzer writes into ./ — pass an' \
                $'\n      explicit, gitignored corpus directory as the FIRST argument.' \
                $'\n      '"${body_norm# }"
            continue
        fi

        first="${parts[1]}"
        first="${first//\"/}"
        # Resolve the one shell variable fuzz.yml uses for a path.
        [[ "$first" == '$SEEDS' || "$first" == '${SEEDS}' ]] && first="fuzz/seeds/TARGET"
        [[ "$first" == '$CORPUS' || "$first" == '${CORPUS}' ]] && first="fuzz/corpus/TARGET"

        if [[ "$first" == *"fuzz/seeds"* ]]; then
            fail "R1: ${file}:${lineno}: the TRACKED seed corpus is libFuzzer's FIRST" \
                $'\n      argument, which is the directory it WRITES into (F-7). Pass the' \
                $'\n      gitignored corpus first and the seeds second:' \
                $'\n        cargo fuzz run <target> "$CORPUS" "$SEEDS" -- -runs=N' \
                $'\n      '"${body_norm# }"
            continue
        fi
        corpus_dirs="${corpus_dirs} ${first}"
    done

    if [[ $failures -eq 0 ]]; then
        pass "R1: every \`cargo fuzz run\` writes into a non-seed corpus directory."
    fi

    # ── R2 — that writable directory is gitignored ───────────────────────────
    if [[ ! -f "$GITIGNORE" ]]; then
        pass "R2: no ${GITIGNORE}; skipping the gitignore check."
    else
        unignored=""
        for dir in $corpus_dirs; do
            # Strip the trailing target segment so `fuzz/corpus/TARGET` is
            # matched by the `fuzz/corpus/` entry in .gitignore. Fixed-string
            # prefix match via awk: the paths contain `/`, which a hand-escaped
            # regex gets wrong.
            prefix="${dir%/*}/"
            awk -v p="$prefix" '
                { line = $0; sub(/^\//, "", line) }
                index(line, p) == 1 { found = 1 }
                END { exit(found ? 0 : 1) }
            ' "$GITIGNORE" || unignored="${unignored} ${dir}"
        done
        if [[ -n "${unignored// /}" ]]; then
            fail "R2: libFuzzer's writable corpus is NOT gitignored:${unignored}" \
                $'\n      A local fuzz run would leave its discovered inputs untracked in' \
                $'\n      `git status`, in a tree where `git add -A` is a documented hazard.'
        else
            pass "R2: every writable corpus directory is gitignored."
        fi
    fi
fi

# ── R3 — the seeds stay tracked ──────────────────────────────────────────────
if [[ ! -f "$GITIGNORE" ]]; then
    pass "R3: no ${GITIGNORE}; skipping the seed-tracking check."
elif grep -qE '^/?fuzz/seeds/?' "$GITIGNORE"; then
    fail "R3: .gitignore ignores fuzz/seeds/. The hand-written, reviewed seed" \
        $'\n      corpus must stay tracked — ignoring it "fixes" F-7 by throwing away' \
        $'\n      the thing F-7 exists to protect (fuzz.yml:117-119).'
else
    pass "R3: fuzz/seeds/ stays tracked."
fi

echo ""
if [[ $failures -gt 0 ]]; then
    echo "✗ fuzz corpus guard: ${failures} rule(s) failed — a fuzz run would dirty the repository."
    exit 1
fi
echo "✓ fuzz corpus guard: libFuzzer writes only into gitignored corpus directories."
exit 0
