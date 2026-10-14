#!/usr/bin/env bash
# scripts/release-bump.sh — the file edits of the release PR.
#
# Each binary release left main naming the previous version in four places:
#
#   • README.md install pins. scripts/check-readme-version.sh then failed every
#     PR until someone opened a `docs(readme): pin vX.Y.Z` PR.
#   • CHANGELOG.md. Entries stayed under `## [Unreleased]` for good.
#   • Cargo.toml / Cargo.lock and deploy/helm/hearth/Chart.yaml. semantic-release
#     set them in its runner, and nothing committed them.
#
# This script writes all of them for one version. scripts/release-pr.sh commits
# the result and opens the PR. This script touches no git state and needs no
# network, so scripts/tests/release-pr.test.sh runs it on fixture files.
#
# Edits (each is a no-op when the file already names VERSION):
#
#   CHANGELOG.md                      The `## [Unreleased]` body moves under a new
#                                     `## [X.Y.Z] — YYYY-MM-DD` heading. The
#                                     `## [Unreleased]` heading stays. With
#                                     RELEASE_CHANGELOG_AT_TAG, only the entries that were
#                                     in [Unreleased] at the tag move (changelog_cut.py).
#                                     A version with no entry gets a one-line note that
#                                     links the GitHub release, so every version has a section.
#   README.md                         check-readme-version.sh --fix X.Y.Z
#   Cargo.toml                        the [package] version (stamp-version.sh)
#   Cargo.lock, fuzz/Cargo.lock       the `hearth` package entry
#   deploy/helm/hearth/Chart.yaml     version and appVersion
#   deploy/helm/hearth/tests/*.yaml   the chart label, the app version label and the
#                                     image tag in the `make helm-template` snapshots
#
# Usage:  bash scripts/release-bump.sh <vX.Y.Z | X.Y.Z>
# Env:    RELEASE_ROOT      tree to edit (default: the repository that holds this script)
#         RELEASE_DATE      date of the CHANGELOG heading (default: today, UTC)
#         RELEASE_REPO_URL  repository URL for the note (default: https://github.com/hearth-auth/hearth)
#         RELEASE_CHANGELOG_AT_TAG  CHANGELOG.md as it was at the release tag (optional)
# Exit:   0 on success, 1 when a file is missing or malformed, 2 on a usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${RELEASE_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
DATE="${RELEASE_DATE:-$(date -u +%Y-%m-%d)}"
REPO_URL="${RELEASE_REPO_URL:-https://github.com/hearth-auth/hearth}"

ref="${1:-}"
if [[ ! "$ref" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: release-bump.sh <vX.Y.Z | X.Y.Z>" >&2
    exit 2
fi
VER="${ref#v}"
VERSION_RE='[0-9]+\.[0-9]+\.[0-9]+'

CHANGELOG="${ROOT}/CHANGELOG.md"
README="${ROOT}/README.md"
CARGO_TOML="${ROOT}/Cargo.toml"
CARGO_LOCK="${ROOT}/Cargo.lock"
FUZZ_LOCK="${ROOT}/fuzz/Cargo.lock"
CHART="${ROOT}/deploy/helm/hearth/Chart.yaml"
SNAPSHOT_DIR="${ROOT}/deploy/helm/hearth/tests"

# Check every input before the first edit, so a bad tree is left as it was.
for f in "$CHANGELOG" "$README" "$CARGO_TOML" "$CARGO_LOCK" "$CHART"; do
    [[ -f "$f" ]] || { echo "release-bump: ${f} not found." >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "release-bump: python3 is required." >&2; exit 1; }
if [[ -n "${RELEASE_CHANGELOG_AT_TAG:-}" && ! -f "$RELEASE_CHANGELOG_AT_TAG" ]]; then
    echo "release-bump: ${RELEASE_CHANGELOG_AT_TAG} not found." >&2
    exit 1
fi
if ! grep -qx '## \[Unreleased\]' "$CHANGELOG"; then
    echo "release-bump: ${CHANGELOG} has no '## [Unreleased]' heading." >&2
    exit 1
fi
if ! grep -qx 'name = "hearth"' "$CARGO_LOCK"; then
    echo "release-bump: ${CARGO_LOCK} has no 'hearth' package entry." >&2
    exit 1
fi

# rewrite <file> <command...> — run the command with <file> on stdin and keep
# the output only when it differs. A temp file and mv, not `sed -i`, which
# differs between GNU and BSD sed.
rewrite() {
    local file="$1"
    shift
    "$@" < "$file" > "${file}.release-bump"
    if cmp -s "$file" "${file}.release-bump"; then
        rm -f "${file}.release-bump"
    else
        mv "${file}.release-bump" "$file"
    fi
}

# ── CHANGELOG.md ─────────────────────────────────────────────────────────────
# Skip when a section for this version exists already (a re-run).
if grep -qE "^## \[${VER//./\\.}\]( |$)" "$CHANGELOG"; then
    echo "release-bump: CHANGELOG.md already has a [${VER}] section."
else
    note="No changelog entries for this release. The [GitHub release](${REPO_URL}/releases/tag/v${VER}) lists its commits."
    # RELEASE_CHANGELOG_AT_TAG (release-pr.sh sets it): move only the entries
    # that were in [Unreleased] at the tag; later entries stay unreleased.
    cut_changelog() {
        python3 "${SCRIPT_DIR}/changelog_cut.py" "$VER" "$DATE" "$note" \
            ${RELEASE_CHANGELOG_AT_TAG:+"$RELEASE_CHANGELOG_AT_TAG"}
    }
    rewrite "$CHANGELOG" cut_changelog
    echo "release-bump: CHANGELOG.md [Unreleased] → [${VER}] — ${DATE}"
fi

# ── README.md ────────────────────────────────────────────────────────────────
# The guard's own pattern list does the rewrite, then checks the result.
README_PATH="$README" bash "${SCRIPT_DIR}/check-readme-version.sh" --fix "$VER" >/dev/null \
    || { echo "release-bump: check-readme-version.sh --fix ${VER} failed." >&2; exit 1; }
echo "release-bump: README.md install pins → ${VER}"

# ── Cargo.toml / Cargo.lock ──────────────────────────────────────────────────
CARGO_TOML="$CARGO_TOML" bash "${SCRIPT_DIR}/stamp-version.sh" "$VER" >/dev/null
echo "release-bump: Cargo.toml [package] version → ${VER}"

# The `hearth` entry is `name = "hearth"` followed by its `version = "…"` line.
# A targeted edit, not `cargo update`, so no dependency moves with the release.
set_lock_version() {
    awk -v ver="$VER" '
        hit && /^version = "/ { $0 = "version = \"" ver "\"" }
        { hit = ($0 == "name = \"hearth\""); print }
    '
}
rewrite "$CARGO_LOCK" set_lock_version
echo "release-bump: Cargo.lock hearth → ${VER}"
if [[ -f "$FUZZ_LOCK" ]]; then
    rewrite "$FUZZ_LOCK" set_lock_version
    echo "release-bump: fuzz/Cargo.lock hearth → ${VER}"
fi

# ── Helm chart ───────────────────────────────────────────────────────────────
# The same edit the root .releaserc.json prepareCmd made in the release runner.
rewrite "$CHART" sed -E \
    -e "s/^version: .*/version: ${VER}/" \
    -e "s/^appVersion: .*/appVersion: \"${VER}\"/"
echo "release-bump: Chart.yaml version and appVersion → ${VER}"

# `make helm-template` (helm.yml) diffs a render against these snapshots. A
# render names the chart version in three places only.
if [[ -d "$SNAPSHOT_DIR" ]]; then
    for snap in "$SNAPSHOT_DIR"/*.yaml; do
        [[ -f "$snap" ]] || continue
        rewrite "$snap" sed -E \
            -e "s#(helm\.sh/chart: hearth-)${VERSION_RE}\$#\\1${VER}#" \
            -e "s#(app\.kubernetes\.io/version: \")${VERSION_RE}(\")#\\1${VER}\\2#" \
            -e "s#(ghcr\.io/hearth-auth/hearth:v)${VERSION_RE}(\")#\\1${VER}\\2#"
    done
    echo "release-bump: Helm snapshots → ${VER}"
fi

echo "release-bump: done (${VER})."
