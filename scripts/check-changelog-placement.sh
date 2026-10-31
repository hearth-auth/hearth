#!/usr/bin/env bash
# scripts/check-changelog-placement.sh — every non-blank line that a change
# adds to CHANGELOG.md must sit in its [Unreleased] section.
#
# Why: a PR that merges after a release PR (`chore(release): vX.Y.Z`) merges
# with no conflict and no new CI run. Its entry, written at the end of
# [Unreleased], then lands in the section that the release PR just created.
# #709's Security entry landed in [4.7.0], which does not contain #709, and the
# v4.7.1 cut found [Unreleased] empty (#716 corrected it).
#
# The change is HEAD^1..HEAD. On a pull_request run HEAD is the merge commit,
# so the diff is the PR applied to the current main. On a push to main HEAD is
# the squash commit, so a merge that misplaces an entry turns main red at once.
#
# Skipped:
#   - a release cut: the diff adds a "## [X.Y.Z]" heading;
#   - a change titled "docs(changelog)..." or "chore(release)...", which edits
#     released sections on purpose. The title is $PR_TITLE when it is set (the
#     PR title on a pull_request run), else HEAD's subject.
#
# Usage: bash scripts/check-changelog-placement.sh [path, default CHANGELOG.md]

set -euo pipefail

file="${1:-CHANGELOG.md}"
title="${PR_TITLE:-$(git log -1 --format=%s HEAD)}"

if [[ "$title" == "docs(changelog)"* || "$title" == "chore(release)"* ]]; then
    echo "OK: \"${title}\" may edit released sections of ${file}."
    exit 0
fi
if ! git rev-parse -q --verify 'HEAD^1' >/dev/null; then
    echo "OK: HEAD has no parent, so there is no change to check."
    exit 0
fi

diff="$(git diff -U0 'HEAD^1' HEAD -- "$file")"
if [[ -z "$diff" ]]; then
    echo "OK: the change does not touch ${file}."
    exit 0
fi
if grep -qE '^\+## \[[0-9]+\.[0-9]+\.[0-9]+\]' <<<"$diff"; then
    echo "OK: the change is a release cut (it adds a version heading to ${file})."
    exit 0
fi

# The line numbers, in HEAD's file, of the non-blank lines the change adds.
added="$(awk '
    /^@@/ { split($3, a, ","); n = substr(a[1], 2) + 0; next }
    /^(\+\+\+|---)/ { next }
    /^\+/ { if ($0 !~ /^\+[[:space:]]*$/) print n; n++ }
' <<<"$diff")"

content="$(git show "HEAD:${file}")"
read -r start end < <(awk '
    /^## \[Unreleased\]/ { s = NR; next }
    s && !e && /^## \[/ { e = NR }
    END { print s + 0, (e ? e : NR + 1) }
' <<<"$content")
if [[ "$start" == 0 ]]; then
    echo "ERROR: ${file} has no '## [Unreleased]' heading." >&2
    exit 1
fi

outside=()
for n in $added; do
    if ((n <= start || n >= end)); then
        outside+=("  line ${n}: $(sed -n "${n}p" <<<"$content")")
    fi
done
if ((${#outside[@]} == 0)); then
    echo "OK: every line the change adds to ${file} is in [Unreleased] (lines ${start}-$((end - 1)))."
    exit 0
fi

{
    echo "ERROR: the change adds lines to ${file} outside [Unreleased] (lines ${start}-$((end - 1))):"
    printf '%s\n' "${outside[@]}"
    echo
    echo "  Move them into [Unreleased]. A PR that merged after a release PR keeps its"
    echo "  place in the text, so its entry can land in the section the release cut."
    echo "  A change that corrects a released section on purpose is titled"
    echo "  'docs(changelog): ...'."
} >&2
exit 1
