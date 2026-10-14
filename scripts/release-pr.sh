#!/usr/bin/env bash
# scripts/release-pr.sh — open (or update) the release PR for a published binary release.
#
# Runs in .github/workflows/release.yml after the GitHub Release is published.
# It commits the edits of scripts/release-bump.sh (CHANGELOG cut, README pins,
# Cargo.toml / Cargo.lock / Chart.yaml versions) on the fixed branch
# `release/next`, force-pushes that branch, opens or updates the PR
# `chore(release): vX.Y.Z` and turns on auto-merge (squash).
#
# It waits for the published release on purpose: check-readme-version.sh keys
# off published binary releases (HEA-2199), so a README pin to a tag without a
# published release would fail the PR's own CI and point readers at a 404.
#
# release/next starts from the current main, not from the tag. A branch built on
# the tag conflicted in CHANGELOG.md with every entry merged after the tag, so
# it could not auto-merge. The CHANGELOG cut moves only the entries that were in
# [Unreleased] at the tag (scripts/changelog_cut.py); later entries stay there.
#
# --refresh (.github/workflows/release-pr-refresh.yml, on each CHANGELOG.md
# push to main): when the open release PR conflicts with main, rebuild it on the
# new main for its version. A PR that merges cleanly is left alone.
#
# Idempotent. A re-run on the same main finds the same tree on release/next,
# does not push, and updates the open PR in place. A later release rebuilds
# release/next for its own version, so an unmerged release PR is replaced.
#
# `chore(release):` cuts no release (commit-analyzer default rules), so merging
# the PR does not start another release.
#
# Usage:  bash scripts/release-pr.sh <vX.Y.Z | X.Y.Z>
#         bash scripts/release-pr.sh --refresh
# Env:    GH_TOKEN, GH_REPO        used by gh (CI: SEMANTIC_RELEASE_PAT, so the PR triggers CI)
#         RELEASE_REMOTE           git remote (default: origin)
#         RELEASE_MAIN_BRANCH      base branch of the PR (default: main)
#         RELEASE_BRANCH           PR head branch (default: release/next)
#         RELEASE_DATE             CHANGELOG heading date (default: the tag commit's date, UTC)
#         RELEASE_POLL_SECONDS     --refresh: wait between mergeability reads (default: 10)
# Exit:   0 when the PR is open and current, when the tag is not on the main
#         branch (a maintenance release), or when --refresh has nothing to do;
#         1 on any failure; 2 on a usage error.

set -euo pipefail

# Everything runs inside main(): bash reads a script as it runs, and the
# checkout below can replace this file with main's copy.
main() {
    local SCRIPT_DIR ROOT REMOTE MAIN BRANCH
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    REMOTE="${RELEASE_REMOTE:-origin}"
    MAIN="${RELEASE_MAIN_BRANCH:-main}"
    BRANCH="${RELEASE_BRANCH:-release/next}"

    local ref="${1:-}"
    if [[ "$ref" == "--refresh" ]]; then
        ref="$(conflicting_release_pr_version)"
        [[ -n "$ref" ]] || return 0
    fi
    if [[ ! "$ref" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "usage: release-pr.sh <vX.Y.Z | X.Y.Z> | --refresh" >&2
        exit 2
    fi
    local VER="${ref#v}"
    local TAG="v${VER}"
    local TITLE="chore(release): ${TAG}"

    cd "$ROOT"

    if ! git diff --quiet HEAD --; then
        echo "release-pr: the work tree has uncommitted changes; refusing to commit them." >&2
        exit 1
    fi

    git fetch --quiet "$REMOTE" \
        "+refs/heads/${MAIN}:refs/remotes/${REMOTE}/${MAIN}" \
        "+refs/tags/${TAG}:refs/tags/${TAG}"
    local tag_commit main_head
    tag_commit="$(git rev-parse --verify "refs/tags/${TAG}^{commit}")"
    main_head="$(git rev-parse --verify "refs/remotes/${REMOTE}/${MAIN}")"

    # A maintenance branch (1.x, 2.x) release does not describe main.
    if ! git merge-base --is-ancestor "$tag_commit" "$main_head"; then
        echo "release-pr: ${TAG} is not on ${MAIN}; no release PR."
        exit 0
    fi

    export RELEASE_DATE="${RELEASE_DATE:-$(TZ=UTC git log -1 --date=format-local:%Y-%m-%d --format=%cd "$tag_commit")}"
    local at_tag
    at_tag="$(mktemp)"
    # shellcheck disable=SC2064  # expand now: at_tag is local
    trap "rm -f '${at_tag}'" EXIT
    git show "${tag_commit}:CHANGELOG.md" > "$at_tag"

    git checkout --quiet -B "$BRANCH" "$main_head"
    RELEASE_CHANGELOG_AT_TAG="$at_tag" bash "${SCRIPT_DIR}/release-bump.sh" "$VER"

    # The pins must name the latest published binary release, the same rule the
    # PR's CI applies. This fails when the release is not published yet or a
    # newer one is.
    if ! env -u README_LATEST_TAG bash "${SCRIPT_DIR}/check-readme-version.sh"; then
        git checkout --quiet -- .
        echo "release-pr: ${TAG} is not the latest published binary release; no release PR." >&2
        exit 1
    fi

    if git diff --quiet; then
        echo "release-pr: ${MAIN} already records ${TAG}; nothing to do."
        exit 0
    fi

    git add -u
    git commit --quiet -F - <<EOF
${TITLE}

Record release ${TAG} on ${MAIN}: move the CHANGELOG [Unreleased] entries
of ${TAG} under [${VER}], pin the README install docs to ${TAG}, and set
the Cargo.toml, Cargo.lock and Chart.yaml versions to ${VER}.

Written by scripts/release-pr.sh.
EOF

    # Push only when release/next does not hold this change on this main already.
    local same=0 remote_ref
    if git ls-remote --exit-code --heads "$REMOTE" "$BRANCH" >/dev/null 2>&1; then
        git fetch --quiet "$REMOTE" "+refs/heads/${BRANCH}:refs/remotes/${REMOTE}/${BRANCH}"
        remote_ref="refs/remotes/${REMOTE}/${BRANCH}"
        if [[ "$(git rev-parse "${remote_ref}^{tree}")" == "$(git rev-parse "HEAD^{tree}")" \
            && "$(git rev-parse -q --verify "${remote_ref}^" || true)" == "$main_head" ]]; then
            same=1
        fi
    fi
    if [[ "$same" -eq 1 ]]; then
        echo "release-pr: ${REMOTE}/${BRANCH} already holds this change; not pushing."
    else
        git push --quiet --force "$REMOTE" "HEAD:refs/heads/${BRANCH}"
        echo "release-pr: pushed ${BRANCH} ($(git rev-parse --short HEAD))."
    fi

    local BODY
    BODY="Automated release PR for [${TAG}](https://github.com/hearth-auth/hearth/releases/tag/${TAG}).

- Moves the \`CHANGELOG.md\` \`[Unreleased]\` entries of ${TAG} under \`[${VER}]\`. Entries merged after the tag stay under \`[Unreleased]\`.
- Pins the README install docs to ${TAG}, so \`check-readme-version.sh\` passes again.
- Sets the \`Cargo.toml\`, \`Cargo.lock\` and \`Chart.yaml\` versions to ${VER}.

\`scripts/release-pr.sh\` wrote this PR after the GitHub Release was published. It rebuilds the PR on the new main when a later CHANGELOG change conflicts with it.
Auto-merge (squash) is on: the PR merges when CI is green.
A later release replaces this PR. The title cuts no release."

    local pr url
    pr="$(gh pr list --head "$BRANCH" --base "$MAIN" --state open --json number --jq '.[0].number // empty')"
    if [[ -z "$pr" ]]; then
        url="$(gh pr create --base "$MAIN" --head "$BRANCH" --title "$TITLE" --body "$BODY")"
        pr="${url##*/}"
        echo "release-pr: opened ${url}"
    else
        gh pr edit "$pr" --title "$TITLE" --body "$BODY" >/dev/null
        echo "release-pr: updated PR #${pr}"
    fi
    if [[ ! "$pr" =~ ^[0-9]+$ ]]; then
        echo "release-pr: could not read the PR number (got '${pr}')." >&2
        exit 1
    fi

    # Auto-merge needs "Allow auto-merge" in the repository settings. Without it
    # the PR stays open for a human to merge; that is not a reason to fail.
    if ! gh pr merge "$pr" --auto --squash --subject "$TITLE"; then
        echo "::warning::release-pr: could not turn on auto-merge for PR #${pr}. Merge it by hand when CI is green."
    fi
}

# conflicting_release_pr_version — print the version of the open release PR when
# it conflicts with main; print nothing when there is no open release PR or it
# merges cleanly. GitHub computes mergeability after a push, so an UNKNOWN
# answer is read again a few times.
conflicting_release_pr_version() {
    local branch="${RELEASE_BRANCH:-release/next}" main="${RELEASE_MAIN_BRANCH:-main}"
    local line pr title state tries
    line="$(gh pr list --head "$branch" --base "$main" --state open \
        --json number,title --jq '.[0] | select(.) | "\(.number) \(.title)"')"
    if [[ -z "$line" ]]; then
        echo "release-pr: no open release PR; nothing to refresh." >&2
        return 0
    fi
    pr="${line%% *}"
    title="${line#* }"
    state=UNKNOWN
    for tries in 1 2 3 4 5 6; do
        state="$(gh pr view "$pr" --json mergeable --jq .mergeable)"
        [[ "$state" != UNKNOWN ]] && break
        sleep "${RELEASE_POLL_SECONDS:-10}"
    done
    if [[ "$state" != CONFLICTING ]]; then
        echo "release-pr: release PR #${pr} is ${state} (after ${tries} reads); nothing to refresh." >&2
        return 0
    fi
    echo "release-pr: release PR #${pr} conflicts with ${main}; rebuilding it." >&2
    echo "${title#chore(release): }"
}

main "$@"
