#!/usr/bin/env bash
# scripts/tests/release-pr.test.sh — tests for scripts/release-bump.sh and
# scripts/release-pr.sh.
#
# Each binary release left four things stale on main: the README install pins
# (which then failed check-readme-version.sh on every PR), the CHANGELOG
# [Unreleased] section, and the Cargo.toml / Chart.yaml versions. The release PR
# fixes all of them in one commit. Part A runs the file edits on fixture files.
# Part B runs the git/gh part against a local bare remote and a fake `gh`.
#
# Usage: bash scripts/tests/release-pr.test.sh

# check() evals its condition string, so shellcheck cannot see the variables
# those strings read.
# shellcheck disable=SC2034

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUMP="${SCRIPT_DIR}/release-bump.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "ok: $1"; }
fail() {
    echo "FAIL: $1"
    failures=$((failures + 1))
    return 1
}
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

# ── Fixtures ────────────────────────────────────────────────────────────────

CHANGELOG_BODY='# Changelog

Intro text.

## [Unreleased]

<!-- branch note -->

### Added

- **New thing** — it does a thing.
  Second line of the entry.

### Fixed

- **Bug** — fixed.

## [1.0.0] — 2026-06-21

### Added

- First release.'

README_BODY='![v1.0.0](https://img.shields.io/badge/status-v1.0.0-brightgreen)
> **Stable 1.0.0:** APIs and on-disk formats are stable.
Download pre-built v1.0.0 artifacts from the [Releases page](https://github.com/hearth-auth/hearth/releases/tag/v1.0.0).
curl -LO https://github.com/hearth-auth/hearth/releases/download/v1.0.0/SHA256SUMS
docker pull ghcr.io/hearth-auth/hearth:v1.0.0
  --version 1.0.0 \
  ghcr.io/hearth-auth/charts/hearth:1.0.0
- **Rust 1.88.0+** is required.'

CARGO_TOML='[workspace]
members = [".", "simulation"]

[package]
name = "hearth"
version = "1.6.11"
edition = "2021"

[dependencies]
axum = { version = "0.8", features = ["multipart"] }'

CARGO_LOCK='version = 4

[[package]]
name = "axum"
version = "0.8.4"

[[package]]
name = "hearth"
version = "1.6.11"
dependencies = [
 "axum",
]

[[package]]
name = "hearth-simulation"
version = "0.1.0"
dependencies = [
 "hearth",
]'

FUZZ_LOCK='version = 4

[[package]]
name = "hearth"
version = "1.6.11"

[[package]]
name = "hearth-fuzz"
version = "0.0.0"'

CHART_YAML='apiVersion: v2
name: hearth
type: application
version: 1.6.11
appVersion: "1.6.11"
keywords:
  - identity'

SNAPSHOT='metadata:
  labels:
    helm.sh/chart: hearth-1.6.11
    app.kubernetes.io/version: "1.6.11"
spec:
  containers:
    - name: hearth
      image: "ghcr.io/hearth-auth/hearth:v1.6.11"
      args: ["--version", "1.6.11"]'

# make_tree <dir> — write every fixture file under <dir>.
make_tree() {
    local d="$1"
    mkdir -p "$d/fuzz" "$d/deploy/helm/hearth/tests"
    printf '%s\n' "$CHANGELOG_BODY" > "$d/CHANGELOG.md"
    printf '%s\n' "$README_BODY" > "$d/README.md"
    printf '%s\n' "$CARGO_TOML" > "$d/Cargo.toml"
    printf '%s\n' "$CARGO_LOCK" > "$d/Cargo.lock"
    printf '%s\n' "$FUZZ_LOCK" > "$d/fuzz/Cargo.lock"
    printf '%s\n' "$CHART_YAML" > "$d/deploy/helm/hearth/Chart.yaml"
    printf '%s\n' "$SNAPSHOT" > "$d/deploy/helm/hearth/tests/default.yaml"
    printf '%s\n' "$SNAPSHOT" > "$d/deploy/helm/hearth/tests/prod.yaml"
}

# tree_sum <dir> — one checksum over every fixture file, for idempotency checks.
tree_sum() {
    (cd "$1" && find . -type f -not -path './.git/*' -not -path './scripts/*' -print0 \
        | sort -z | xargs -0 cat | cksum)
}

# bump <dir> <version> — run the file-editing part on <dir>.
bump() {
    RELEASE_ROOT="$1" RELEASE_DATE=2026-10-14 bash "$BUMP" "$2"
}

# ── Part A: file edits (scripts/release-bump.sh) ────────────────────────────

A="$TMP/a"
make_tree "$A"
out="$(bump "$A" v9.9.9 2>&1)"
rc=$?
check "bump exits 0" '[[ "$rc" -eq 0 ]]' || echo "$out" | sed 's/^/    /'

EXPECTED_CHANGELOG='# Changelog

Intro text.

## [Unreleased]

## [9.9.9] — 2026-10-14

<!-- branch note -->

### Added

- **New thing** — it does a thing.
  Second line of the entry.

### Fixed

- **Bug** — fixed.

## [1.0.0] — 2026-06-21

### Added

- First release.'
got="$(cat "$A/CHANGELOG.md")"
check "CHANGELOG [Unreleased] body moves under the new version heading" \
    '[[ "$got" == "$EXPECTED_CHANGELOG" ]]' \
    || diff <(printf '%s\n' "$EXPECTED_CHANGELOG") <(printf '%s\n' "$got") | sed 's/^/    /'

check "README pins name the new version" \
    '[[ "$(cat "$A/README.md")" == "${README_BODY//1.0.0/9.9.9}" ]]'
check "README passes check-readme-version.sh for the new version" \
    'README_PATH="$A/README.md" README_LATEST_TAG=v9.9.9 bash "$SCRIPT_DIR/check-readme-version.sh" >/dev/null 2>&1'

check "Cargo.toml [package] version is set" \
    'grep -qx "version = \"9.9.9\"" "$A/Cargo.toml"'
check "Cargo.toml dependency pins are untouched" \
    'grep -qF "axum = { version = \"0.8\"" "$A/Cargo.toml"'

check "Cargo.lock hearth entry is set" \
    'grep -A1 -x "name = \"hearth\"" "$A/Cargo.lock" | grep -qx "version = \"9.9.9\""'
check "Cargo.lock other packages are untouched" \
    'grep -A1 -x "name = \"hearth-simulation\"" "$A/Cargo.lock" | grep -qx "version = \"0.1.0\"" \
     && grep -A1 -x "name = \"axum\"" "$A/Cargo.lock" | grep -qx "version = \"0.8.4\"" \
     && grep -qx "version = 4" "$A/Cargo.lock"'
check "fuzz/Cargo.lock hearth entry is set" \
    'grep -A1 -x "name = \"hearth\"" "$A/fuzz/Cargo.lock" | grep -qx "version = \"9.9.9\"" \
     && grep -A1 -x "name = \"hearth-fuzz\"" "$A/fuzz/Cargo.lock" | grep -qx "version = \"0.0.0\""'

check "Chart.yaml version and appVersion are set" \
    'grep -qx "version: 9.9.9" "$A/deploy/helm/hearth/Chart.yaml" \
     && grep -qx "appVersion: \"9.9.9\"" "$A/deploy/helm/hearth/Chart.yaml" \
     && grep -qx "apiVersion: v2" "$A/deploy/helm/hearth/Chart.yaml"'

EXPECTED_SNAPSHOT='metadata:
  labels:
    helm.sh/chart: hearth-9.9.9
    app.kubernetes.io/version: "9.9.9"
spec:
  containers:
    - name: hearth
      image: "ghcr.io/hearth-auth/hearth:v9.9.9"
      args: ["--version", "1.6.11"]'
check "Helm snapshots name the new chart version (and nothing else changes)" \
    '[[ "$(cat "$A/deploy/helm/hearth/tests/default.yaml")" == "$EXPECTED_SNAPSHOT" \
        && "$(cat "$A/deploy/helm/hearth/tests/prod.yaml")" == "$EXPECTED_SNAPSHOT" ]]'

# A second run with the same version changes nothing.
before="$(tree_sum "$A")"
bump "$A" 9.9.9 >/dev/null 2>&1
rc=$?
check "second run exits 0 and changes nothing" \
    '[[ "$rc" -eq 0 && "$(tree_sum "$A")" == "$before" ]]'

# An empty [Unreleased] still gets a version heading, with a note.
make_tree "$TMP/b"
bump "$TMP/b" 9.9.9 >/dev/null 2>&1
bump "$TMP/b" 9.9.10 >/dev/null 2>&1
rc=$?
EXPECTED_HEAD='## [Unreleased]

## [9.9.10] — 2026-10-14

No changelog entries for this release. The [GitHub release](https://github.com/hearth-auth/hearth/releases/tag/v9.9.10) lists its commits.

## [9.9.9] — 2026-10-14'
got="$(sed -n '/^## \[Unreleased\]/,/^## \[9\.9\.9\]/p' "$TMP/b/CHANGELOG.md")"
check "empty [Unreleased] gets the version heading and a one-line note" \
    '[[ "$rc" -eq 0 && "$got" == "$EXPECTED_HEAD" ]]' \
    || diff <(printf '%s\n' "$EXPECTED_HEAD") <(printf '%s\n' "$got") | sed 's/^/    /'

# Bad input fails and leaves the tree untouched.
make_tree "$TMP/c"
before="$(tree_sum "$TMP/c")"
for bad in "" main 1.6 v1.6.6-rc.1; do
    if bump "$TMP/c" "$bad" >/dev/null 2>&1; then
        fail "bump '${bad}' must fail"
    elif [[ "$(tree_sum "$TMP/c")" != "$before" ]]; then
        fail "bump '${bad}' must leave the tree untouched"
    else
        pass "bump '${bad}' is rejected"
    fi
done

make_tree "$TMP/d"
sed -i 's/^## \[Unreleased\]$/## Unreleased/' "$TMP/d/CHANGELOG.md"
before="$(tree_sum "$TMP/d")"
if bump "$TMP/d" 9.9.9 >/dev/null 2>&1; then
    fail "a CHANGELOG without '## [Unreleased]' must fail"
elif [[ "$(tree_sum "$TMP/d")" != "$before" ]]; then
    fail "a CHANGELOG without '## [Unreleased]' must leave the tree untouched"
else
    pass "a CHANGELOG without '## [Unreleased]' is rejected before any edit"
fi

# ── Part B: git + gh (scripts/release-pr.sh) ────────────────────────────────

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

REMOTE="$TMP/remote.git"
WORK="$TMP/work"
FAKEBIN="$TMP/bin"
GH_LOG="$TMP/gh.log"
GH_STATE="$TMP/gh.state"

git init --quiet --bare --initial-branch=main "$REMOTE"
git init --quiet --initial-branch=main "$WORK"
make_tree "$WORK"
mkdir -p "$WORK/scripts"
cp "$SCRIPT_DIR/release-pr.sh" "$SCRIPT_DIR/release-bump.sh" \
    "$SCRIPT_DIR/check-readme-version.sh" "$SCRIPT_DIR/stamp-version.sh" "$WORK/scripts/" \
    2>/dev/null
git -C "$WORK" add -A
git -C "$WORK" commit --quiet -m "feat: a release"
git -C "$WORK" tag v9.9.9
git -C "$WORK" remote add origin "$REMOTE"
git -C "$WORK" push --quiet origin main v9.9.9

# Fake gh: logs every call. `release list` names the published release in
# $GH_RELEASE; `pr list` prints the open PR number kept in $GH_STATE.
mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/gh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1 $2" in
    "release list") printf '%s\tLatest\t%s\t2026-10-14T00:00:00Z\n' "$GH_RELEASE" "$GH_RELEASE" ;;
    "pr list")      cat "$GH_STATE" 2>/dev/null || true ;;
    "pr create")    echo 7 > "$GH_STATE"; echo "https://github.com/hearth-auth/hearth/pull/7" ;;
    "pr edit")      ;;
    "pr merge")     [[ -n "${GH_MERGE_FAILS:-}" ]] && { echo "auto-merge is not allowed" >&2; exit 1; } ;;
    *)              echo "fake gh: unexpected call: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$FAKEBIN/gh"
export GH_LOG GH_STATE

# run_pr <tag> — run release-pr.sh in the work tree with the fake gh.
run_pr() {
    (cd "$WORK" && PATH="$FAKEBIN:$PATH" GH_RELEASE="${GH_RELEASE:-v9.9.9}" \
        RELEASE_DATE=2026-10-14 bash scripts/release-pr.sh "$1")
}

out="$(run_pr v9.9.9 2>&1)"
rc=$?
check "release-pr exits 0" '[[ "$rc" -eq 0 ]]' || echo "$out" | sed 's/^/    /'

branch_sha="$(git -C "$REMOTE" rev-parse -q --verify refs/heads/release/next 2>/dev/null)"
check "release/next is pushed" '[[ -n "$branch_sha" ]]'
check "release/next sits on the release tag" \
    '[[ "$(git -C "$REMOTE" rev-parse "${branch_sha}^")" == "$(git -C "$REMOTE" rev-parse "v9.9.9^{commit}")" ]]'
check "the commit title is chore(release): v9.9.9" \
    '[[ "$(git -C "$REMOTE" log -1 --format=%s "$branch_sha")" == "chore(release): v9.9.9" ]]'
EXPECTED_FILES='CHANGELOG.md
Cargo.lock
Cargo.toml
README.md
deploy/helm/hearth/Chart.yaml
deploy/helm/hearth/tests/default.yaml
deploy/helm/hearth/tests/prod.yaml
fuzz/Cargo.lock'
check "the commit changes exactly the release files" \
    '[[ "$(git -C "$REMOTE" diff --name-only "${branch_sha}^" "$branch_sha")" == "$EXPECTED_FILES" ]]'
check "a PR is created with the release title" \
    'grep -q "^pr create .*--head release/next.*--title chore(release): v9.9.9" "$GH_LOG"'
check "auto-merge (squash) is requested" \
    'grep -q "^pr merge 7 --auto --squash" "$GH_LOG"'

# Second run: same change, PR already open → no new PR, no new push.
: > "$GH_LOG"
out="$(run_pr v9.9.9 2>&1)"
rc=$?
check "second release-pr run exits 0" '[[ "$rc" -eq 0 ]]' || echo "$out" | sed 's/^/    /'
check "second run does not create another PR" '! grep -q "^pr create" "$GH_LOG"'
check "second run updates the open PR" 'grep -q "^pr edit 7 " "$GH_LOG"'
check "second run does not move release/next" \
    '[[ "$(git -C "$REMOTE" rev-parse refs/heads/release/next)" == "$branch_sha" ]]'

# Auto-merge unavailable: warn, do not fail the job.
: > "$GH_LOG"
out="$(GH_MERGE_FAILS=1 run_pr v9.9.9 2>&1)"
rc=$?
check "an auto-merge failure is a warning, not a failure" \
    '[[ "$rc" -eq 0 && "$out" == *"auto-merge"* ]]' || echo "$out" | sed 's/^/    /'

# A tag that is not the latest published release opens no PR.
git -C "$WORK" checkout --quiet main
git -C "$WORK" commit --quiet --allow-empty -m "fix: another"
git -C "$WORK" tag v9.9.10
git -C "$WORK" push --quiet origin main v9.9.10
: > "$GH_LOG"
out="$(GH_RELEASE=v9.9.9 run_pr v9.9.10 2>&1)"
rc=$?
check "an unpublished tag fails before any push or PR" \
    '[[ "$rc" -ne 0 && "$(git -C "$REMOTE" rev-parse refs/heads/release/next)" == "$branch_sha" ]] \
     && ! grep -q "^pr " "$GH_LOG"' || echo "$out" | sed 's/^/    /'

# A tag that is not on main (a maintenance-branch release) is a no-op.
git -C "$WORK" checkout --quiet -b 1.x v9.9.9
git -C "$WORK" commit --quiet --allow-empty -m "fix: backport"
git -C "$WORK" tag v1.9.9
git -C "$WORK" push --quiet origin 1.x v1.9.9
: > "$GH_LOG"
out="$(GH_RELEASE=v1.9.9 run_pr v1.9.9 2>&1)"
rc=$?
check "a tag not on main exits 0 and opens no PR" \
    '[[ "$rc" -eq 0 && "$(git -C "$REMOTE" rev-parse refs/heads/release/next)" == "$branch_sha" ]] \
     && ! grep -q "^pr " "$GH_LOG"' || echo "$out" | sed 's/^/    /'

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "OK: all release-bump.sh / release-pr.sh cases passed."
exit 0
