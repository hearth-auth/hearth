#!/usr/bin/env bash
# scripts/check-systemd-units.sh — shipped systemd units must not carry
# directives in a section where systemd ignores them.
#
# Audit 2026-08-28 finding §4.8#14 (LOW):
#
#   The systemd crash-loop limiter is silently ignored.
#
# deploy/systemd/hearth.service set StartLimitBurst=3 and
# StartLimitIntervalSec=60 in [Service]. systemd parses both in [Unit] only
# (since v229) and reports "Unknown key 'StartLimitIntervalSec' in section
# [Service], ignoring." With the interval ignored the default 10 s window
# applied instead of the intended 60 s, so the documented "give up after 3
# rapid restarts" bound was never the one in force.
#
# The failure is silent at deploy time — the unit still starts, and the warning
# goes to the journal where nobody reads it. This guard is a plain parser, so it
# runs on every PR with no systemd required.
#
# Usage:  bash scripts/check-systemd-units.sh [unit-file ...]
#         Defaults to every *.service / *.timer under deploy/ and scripts/.

set -uo pipefail

if [[ $# -gt 0 ]]; then
    units=("$@")
else
    mapfile -t units < <(find deploy scripts -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | sort)
fi

if [[ "${#units[@]}" -eq 0 ]]; then
    echo "FAIL: no systemd unit files found."
    exit 1
fi

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# Directives systemd accepts only in [Unit]. Placing one in [Service] is not a
# validation error — it is ignored, which is why this needs a guard.
UNIT_ONLY='StartLimitBurst|StartLimitIntervalSec|StartLimitInterval|StartLimitAction|RebootArgument|OnFailure|OnSuccess|SuccessAction|FailureAction'

for unit in "${units[@]}"; do
    [[ -f "$unit" ]] || { fail "${unit} not found."; continue; }

    section=""
    lineno=0
    while IFS= read -r line; do
        lineno=$((lineno + 1))
        # Strip inline whitespace; skip comments and blanks.
        case "$line" in
            \#*|\;*|"") continue ;;
        esac
        if [[ "$line" =~ ^\[([A-Za-z]+)\]$ ]]; then
            section="${BASH_REMATCH[1]}"
            continue
        fi
        key="${line%%=*}"
        key="${key// /}"
        if [[ "$section" != "Unit" ]] && [[ "$key" =~ ^($UNIT_ONLY)$ ]]; then
            fail "${unit}:${lineno}: '${key}' is in [${section}]. systemd reads it in [Unit] only and ignores it here, so the setting has no effect."
        fi
    done < "$unit"

    # A restart policy without a limiter is a runaway crash loop.
    if grep -qE '^[[:space:]]*Restart=(always|on-failure|on-abnormal|on-abort)' "$unit"; then
        if ! grep -qE '^[[:space:]]*StartLimitBurst=' "$unit"; then
            fail "${unit} restarts on failure but sets no StartLimitBurst, so a crash loop is unbounded."
        fi
        if ! grep -qE '^[[:space:]]*StartLimitIntervalSec=' "$unit"; then
            fail "${unit} sets StartLimitBurst but no StartLimitIntervalSec, so systemd's default window applies, not the documented one."
        fi
    fi
done

if [[ "$failures" -gt 0 ]]; then
    echo
    echo "${failures} problem(s) in shipped systemd units (audit §4.8#14)."
    exit 1
fi

echo "OK: ${#units[@]} systemd unit(s) place every directive in a section systemd reads."
