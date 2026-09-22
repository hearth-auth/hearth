#!/usr/bin/env bash
# scripts/check-nextest-profile-live.sh — a nextest profile nothing selects is
# not configuration, it is a comment.
#
# Audit 2026-08-28 finding §4.12#18 (Informational):
#
#   .config/nextest.toml declared
#
#       [profile.ci]
#       retries = 2
#       fail-fast = false
#
#   and nothing anywhere passed `--profile ci` or set `NEXTEST_PROFILE`. Every
#   run therefore used [profile.default] — retries = 0, fail-fast = true. Two
#   consequences the profile existed to prevent:
#
#     * a red suite stops at the first failure, so the run reports a fraction of
#       what is actually broken and each fix needs another full CI round trip;
#     * a genuine flake fails the build outright, with no retry to distinguish
#       it from a real regression.
#
#   The profile was not wrong. It was simply never selected — the failure mode
#   of every piece of configuration that has no consumer.
#
# One rule:
#
#   R1  Every `[profile.<name>]` in the nextest config, other than `default` and
#       the tool-owned `default-*` profiles, is selected somewhere: a
#       `--profile <name>` argument, or a `NEXTEST_PROFILE` assignment naming
#       it, in a workflow, the Makefile, or a script.
#
# Deleting an unused profile satisfies this rule just as well as wiring it up.
# Both are honest; leaving it declared and unreachable is not.
#
# Usage:  bash scripts/check-nextest-profile-live.sh
# Env:    NEXTEST_CONFIG  path to the config  (default .config/nextest.toml)
#         SEARCH_ROOT     tree to search for selectors (default: repo root)

set -uo pipefail

NEXTEST_CONFIG="${NEXTEST_CONFIG:-.config/nextest.toml}"
SEARCH_ROOT="${SEARCH_ROOT:-.}"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

if [[ ! -f "$NEXTEST_CONFIG" ]]; then
    echo "FAIL: nextest config not found: ${NEXTEST_CONFIG}"
    exit 1
fi

mapfile -t PROFILES < <(
    grep -oE '^\[profile\.[A-Za-z0-9_-]+\]' "$NEXTEST_CONFIG" \
        | sed -E 's/^\[profile\.//; s/\]$//'
)

if [[ "${#PROFILES[@]}" -eq 0 ]]; then
    fail "${NEXTEST_CONFIG} declares no profiles; the rule has nothing to check."
fi

checked=0
for profile in "${PROFILES[@]}"; do
    # `default` is what nextest uses with no selector. `default-miri` and any
    # future `default-<tool>` are selected by the tool, not by this repo.
    [[ "$profile" == "default" || "$profile" == default-* ]] && continue
    checked=$((checked + 1))

    if grep -rqE -- "(--profile[= ]${profile}\b|NEXTEST_PROFILE[:=][[:space:]]*[\"']?${profile}\b)" \
        --exclude-dir=.git --exclude-dir=target --exclude-dir=node_modules \
        --exclude-dir=.claude --exclude="$(basename "$0")" \
        "$SEARCH_ROOT" 2>/dev/null; then
        continue
    fi
    fail "${NEXTEST_CONFIG}: profile '${profile}' is declared but never selected." \
        $'\n      No --profile '"${profile}"$' argument and no NEXTEST_PROFILE assignment' \
        $'\n      names it, so every run uses [profile.default] instead and this block' \
        $'\n      changes nothing (§4.12#18). Wire it up, or delete it.'
done

if [[ "$checked" -eq 0 && "$failures" -eq 0 ]]; then
    echo "OK: no selectable nextest profiles are declared."
    exit 0
fi

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} dead nextest profile(s)."
    echo "See scripts/check-nextest-profile-live.sh for the rule and the audit citation."
    exit 1
fi
echo "OK: every declared nextest profile is selected somewhere."
exit 0
