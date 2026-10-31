#!/usr/bin/env bash
# scripts/tests/check-changelog-placement.test.sh — tests for
# scripts/check-changelog-placement.sh.
#
# The guard exists for one shape: a PR that merges after a release PR, with no
# conflict, whose entry then lands in the section the release PR cut (#709's
# Security entry landed in [4.7.0], fixed by #716). So it must be shown to FAIL
# on that merge, and on an entry added straight into a released section, not
# merely pass on a normal entry.
#
# Usage: bash scripts/tests/check-changelog-placement.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-changelog-placement.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# run_case <name> <expected-exit> <repo> <pr-title or ""> [expected-substring]
run_case() {
    local name="$1" want="$2" repo="$3" title="$4" expect="${5:-}" out rc
    out="$(cd "$repo" && PR_TITLE="$title" bash "$CHECK" 2>&1)"
    rc=$?
    if [[ "$rc" != "$want" ]]; then
        fail "${name}: exit ${rc}, want ${want}"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    if [[ -n "$expect" ]] && ! printf '%s\n' "$out" | grep -qF -- "$expect"; then
        fail "${name}: output does not mention '${expect}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    pass "$name"
}

# new_repo <dir>: a repo whose CHANGELOG.md has an [Unreleased] entry above a
# released [1.0.0].
new_repo() {
    local dir="$1"
    git init -q -b main "$dir"
    git -C "$dir" config user.email test@example.com
    git -C "$dir" config user.name test
    cat >"$dir/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

### Added
- **Feature A** (#1).

## [1.0.0] — 2026-01-01

### Fixed
- **Old fix** (#0).
EOF
    git -C "$dir" add CHANGELOG.md
    git -C "$dir" commit -q -m "docs: start"
}

# commit_file <dir> <subject>: commits CHANGELOG.md as it is in <dir>.
commit_file() {
    git -C "$1" commit -q -am "$2"
}

# ── an entry in [Unreleased] passes ───────────────────────────────────────────
r="$TMP/unreleased"
new_repo "$r"
sed -i 's/^- \*\*Feature A\*\* (#1)\.$/&\n\n### Security\n- **Hardening** (#2)./' "$r/CHANGELOG.md"
commit_file "$r" "fix: hardening (#2)"
run_case "entry added in [Unreleased]" 0 "$r" ""

# ── an entry added straight into a released section fails ────────────────────
r="$TMP/released"
new_repo "$r"
sed -i 's/^- \*\*Old fix\*\* (#0)\.$/&\n- **Late fix** (#3)./' "$r/CHANGELOG.md"
commit_file "$r" "fix: late fix (#3)"
run_case "entry added into [1.0.0]" 1 "$r" "" "Late fix"

# ── the #709 shape: a branch merges after a release cut, with no conflict ────
r="$TMP/after-release"
new_repo "$r"
git -C "$r" checkout -q -b feature
sed -i 's/^- \*\*Feature A\*\* (#1)\.$/&\n\n### Security\n- **Hardening** (#2)./' "$r/CHANGELOG.md"
commit_file "$r" "fix: hardening (#2)"
git -C "$r" checkout -q main
# The release PR: [Unreleased]'s entries move under a new [1.1.0] heading.
sed -i 's/^## \[Unreleased\]$/&\n\n## [1.1.0] — 2026-02-01/' "$r/CHANGELOG.md"
commit_file "$r" "chore(release): v1.1.0"
git -C "$r" merge -q --no-edit feature >/dev/null
if git -C "$r" show HEAD:CHANGELOG.md | awk '/^## \[1\.1\.0\]/{s=1} /^## \[1\.0\.0\]/{s=0} s && /Hardening/{f=1} END{exit !f}'; then
    run_case "entry merged after a release cut lands in [1.1.0]" 1 "$r" "" "Hardening"
else
    fail "setup: the merge did not reproduce the #709 shape"
    git -C "$r" show HEAD:CHANGELOG.md | sed 's/^/         /'
fi

# ── a release cut passes (it adds a version heading) ─────────────────────────
r="$TMP/release-cut"
new_repo "$r"
sed -i 's/^## \[Unreleased\]$/&\n\n## [1.1.0] — 2026-02-01/' "$r/CHANGELOG.md"
commit_file "$r" "chore(release): v1.1.0"
run_case "release cut" 0 "$r" ""

# ── a docs(changelog) correction of a released section passes ────────────────
r="$TMP/correction"
new_repo "$r"
sed -i 's/^- \*\*Old fix\*\* (#0)\.$/&\n- **Corrected entry** (#4)./' "$r/CHANGELOG.md"
commit_file "$r" "docs(changelog): the fix shipped in 1.0.0"
run_case "docs(changelog) commit subject" 0 "$r" ""
run_case "docs(changelog) PR title on a merge commit" 0 "$r" \
    "docs(changelog): the fix shipped in 1.0.0"
run_case "another PR title does not excuse the commit" 1 "$r" "fix: something else" \
    "Corrected entry"

# ── a change that does not touch CHANGELOG.md passes ─────────────────────────
r="$TMP/untouched"
new_repo "$r"
echo "x" >"$r/other.txt"
git -C "$r" add other.txt
git -C "$r" commit -q -m "chore: other file"
run_case "CHANGELOG.md unchanged" 0 "$r" ""

echo
if ((failures > 0)); then
    echo "check-changelog-placement.test.sh: ${failures} failure(s)"
    exit 1
fi
echo "check-changelog-placement.test.sh: all cases pass"
