#!/usr/bin/env bash
# scripts/summarize-nextest.sh — read a `cargo nextest run` log and report what
# the suite actually did.
#
# Audit 2026-08-28 findings §4.8#6 and §4.12#9 (MEDIUM):
#
#   `validation-summary.txt` reports a completed 4-failure suite as "suite did
#   not complete" because its parser cannot read the ANSI-coloured nextest
#   output a pinned third-party action causes.
#
# The old parser was a single inline `grep -oE '[0-9]+ tests run: .*'` in
# .github/workflows/release.yml. nextest's summary line is coloured per field:
#
#   ESC[31;1m     SummaryESC[0m [   6.0s] ESC[1m846ESC[0m tests run: ...
#
# The escape sequence sits between the digits and " tests run", so the regex
# never matched, the fallback fired, and a suite that ran to completion with
# four named failures was reported to the release engineer as one that never
# ran. That reads as infrastructure trouble, not as a red suite.
#
# This script removes the cause and the symptom. The workflow now runs nextest
# with `--color never`, and this parser strips ANSI anyway, so a future colour
# source cannot defeat it again.
#
# Usage:  bash scripts/summarize-nextest.sh <log> [--line|--failures]
#
#   --line      (default) print the summary text, e.g.
#               "846 tests run: 842 passed, 4 failed, 3 skipped".
#               Exit 0 when the suite completed, 1 when no summary line
#               exists — the ONLY condition under which a caller may say the
#               suite did not complete.
#   --failures  print one "<binary> <test>" line per failing test, in the
#               order nextest first reported them. Exit 0 always.

set -uo pipefail

LOG="${1:-nextest.log}"
MODE="${2:---line}"

# Cap on named failures printed, so a wholesale red suite cannot bury the rest
# of validation-summary.txt.
MAX_NAMED_FAILURES="${MAX_NAMED_FAILURES:-50}"

if [[ ! -f "$LOG" ]]; then
    case "$MODE" in
        --failures) exit 0 ;;
        *)
            echo "suite did not complete (no log at ${LOG})"
            exit 1
            ;;
    esac
fi

# ESC built with printf so the expression works under both GNU and BSD sed;
# neither `\x1B` nor `\e` is portable inside a sed script.
ESC="$(printf '\033')"

# Strips SGR/CSI escapes and CR, so every pattern below matches plain text.
strip_ansi() {
    sed -E -e "s/${ESC}\[[0-9;?]*[a-zA-Z]//g" -e 's/\r$//' "$LOG"
}

# nextest statuses that mean "this test did not pass". LEAK is a pass with a
# warning and is deliberately absent; LEAK-FAIL is not.
STATUS_RE='(TRY [0-9]+ )?(FAIL|ABORT|SIGSEGV|SIGABRT|SIGTERM|SIGILL|SIGBUS|TIMEOUT|LEAK-FAIL)'

case "$MODE" in
    --line)
        # Anchor on nextest's own summary line rather than searching the whole
        # log for "tests run:" — a test's captured stdout must not be able to
        # supply the release engineer's verdict.
        summary="$(strip_ansi | grep -E '^[[:space:]]*Summary[[:space:]]+\[' | tail -1)"
        if [[ -z "$summary" ]]; then
            echo "suite did not complete (no nextest summary line in ${LOG})"
            exit 1
        fi
        line="$(printf '%s\n' "$summary" | grep -oE '[0-9]+ tests run:.*')"
        if [[ -z "$line" ]]; then
            # A summary line in a shape this parser does not know. Report the
            # line verbatim; it is still evidence the suite completed.
            printf '%s\n' "$(printf '%s\n' "$summary" | sed -E 's/^[[:space:]]+//')"
            exit 0
        fi
        printf '%s\n' "$line"
        ;;
    --failures)
        # nextest names each failure twice — once as it happens, once in the
        # end-of-run recap — so dedupe while preserving first-seen order.
        strip_ansi \
            | grep -E "^[[:space:]]*${STATUS_RE}[[:space:]]+\[" \
            | sed -E "s/^[[:space:]]*${STATUS_RE}[[:space:]]+\[[^]]*\][[:space:]]*(\([0-9]+\/[0-9]+\)[[:space:]]*)?//" \
            | awk -v max="$MAX_NAMED_FAILURES" '
                !seen[$0]++ {
                    n++
                    if (n <= max) print
                }
                END { if (n > max) printf "... and %d more\n", n - max }
              '
        ;;
    *)
        echo "usage: $0 <log> [--line|--failures]" >&2
        exit 2
        ;;
esac
