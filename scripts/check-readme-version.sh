#!/usr/bin/env bash
# scripts/check-readme-version.sh — CI guard: README install references must match the latest
# PUBLISHED binary release (HEA-2116, HEA-2199).
#
# Tracks: HEA-2116 (original guard), HEA-2199 (fix: compare against the latest published
# GitHub Release, not the latest git tag — a tag whose release run failed has no artifacts,
# so the README must not be forced to reference it and it must not block merges).
#
# The patterns checked are:
#
#   • GitHub Releases URLs:  /releases/tag/vX.Y.Z  and  /releases/download/vX.Y.Z/
#   • Docker image tags:     ghcr.io/hearth-auth/hearth:vX.Y.Z
#   • Helm chart version:    --version X.Y.Z  and  charts/hearth:X.Y.Z
#   • Status badge:          badge/status-vX.Y.Z-brightgreen  and its ![vX.Y.Z] alt text
#   • Stable-release prose:  **Stable X.Y.Z:**  and  "pre-built vX.Y.Z artifacts"
#
# Comparison is per-MATCH, not per-line. A line may legitimately carry more than
# one version pin (line 1 has both the badge alt-text and the badge URL; the
# Install line has both prose and a Releases URL). Filtering whole lines would
# let a half-updated line pass, so each matched pin is checked on its own.
#
# Reference version resolution order:
#   1. README_LATEST_TAG env var  — test override only; never set in CI.
#   2. gh release list            — latest non-draft, non-prerelease GitHub Release whose
#                                   tag matches ^v[0-9]+\.[0-9]+\.[0-9]+$ exactly. SDK
#                                   releases (sdk-ts-v1.6.10, …) are excluded by the regex.
#                                   A git tag whose release workflow failed (so no GitHub
#                                   Release object was published) is correctly invisible here.
#   3. gh unavailable / no match  — guard is SKIPPED (exit 0 with a notice). A broken release
#                                   pipeline must never block merges; local dev without GitHub
#                                   auth is also non-blocking.
#
# Usage: scripts/check-readme-version.sh
# Env (test hooks only — unset in CI):
#   README_PATH        path to the file to check                    (default: README.md)
#   README_LATEST_TAG  override the resolved reference version      (default: auto-resolved)
# Exit:  0 if all references match the latest published release (or if the check is skipped),
#        1 if any pin does not match.

set -euo pipefail

README="${README_PATH:-README.md}"

if [[ ! -f "$README" ]]; then
    echo "ERROR: ${README} not found (run from the repository root)."
    exit 1
fi

# ── Resolve the reference version ─────────────────────────────────────────────
#
# We compare README install pins against the latest PUBLISHED GitHub Release, not
# the latest git tag. The README documents artifact download URLs — those only
# exist once a release is published. A git tag with no corresponding GitHub Release
# (e.g. the release workflow failed mid-run) must not block merges (HEA-2199).

LATEST_TAG="${README_LATEST_TAG:-}"

if [[ -z "$LATEST_TAG" ]]; then
    if command -v gh &>/dev/null; then
        REPO="${GITHUB_REPOSITORY:-hearth-auth/hearth}"
        # Select non-draft, non-prerelease releases with a plain semver tag
        # (^v[0-9]+\.[0-9]+\.[0-9]+$). SDK release tags (sdk-ts-v1.6.10, …)
        # are excluded by the strict regex. max_by converts each tag to a
        # numeric [major, minor, patch] array for correct semver ordering.
        LATEST_TAG=$(gh release list \
            --repo "$REPO" \
            --limit 50 \
            --json tagName,isDraft,isPrerelease \
            --jq '[.[] | select(.isDraft == false and .isPrerelease == false
                               and (.tagName | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")))
                       | .tagName]
                  | max_by(ltrimstr("v") | split(".") | map(tonumber))
                  // empty' 2>/dev/null || true)
    fi
fi

if [[ -z "$LATEST_TAG" ]]; then
    echo "INFO: No published binary release found (gh unavailable, unauthenticated,"
    echo "      or repo has no releases matching ^v[0-9]+.[0-9]+.[0-9]+$)."
    echo "      Skipping README version-drift check (non-blocking)."
    exit 0
fi

# Bare version string without the leading 'v' (e.g. 1.6.9).
LATEST_BARE="${LATEST_TAG#v}"

echo "Latest published release: ${LATEST_TAG}  (bare: ${LATEST_BARE})"

# ── Patterns to check ────────────────────────────────────────────────────────
#
# Each pattern must match ONLY install-instruction version pins, not code lines
# or the CHANGELOG (which legitimately contains old versions). We grep specific
# enough patterns so false positives stay silent.
#
# Each entry is: <description> <ERE>
# grep -onE yields "<lineno>:<matched text>" per match; a matched pin that does
# not contain LATEST_BARE is flagged as stale.

declare -a PATTERNS=(
    "GitHub Releases tag URL"        "releases/tag/v[0-9]+\.[0-9]+\.[0-9]+"
    "GitHub Releases download URL"   "releases/download/v[0-9]+\.[0-9]+\.[0-9]+/"
    "Docker image tag"               "hearth-auth/hearth:v[0-9]+\.[0-9]+\.[0-9]+"
    "Helm chart OCI tag"             "charts/hearth:[0-9]+\.[0-9]+\.[0-9]+"
    "Helm --version flag"            "\-\-version [0-9]+\.[0-9]+\.[0-9]+"
    "Status badge URL"               "badge/status-v[0-9]+\.[0-9]+\.[0-9]+-brightgreen"
    "Status badge alt text"          "!\[v[0-9]+\.[0-9]+\.[0-9]+\]"
    "Stable-release prose"           "Stable [0-9]+\.[0-9]+\.[0-9]+:"
    "Install prose"                  "pre-built v?[0-9]+\.[0-9]+\.[0-9]+ artifacts"
)

stale=0

for (( i=0; i<${#PATTERNS[@]}; i+=2 )); do
    desc="${PATTERNS[$i]}"
    pat="${PATTERNS[$i+1]}"

    # grep -onE output is "N:matched-text" — one line per match, so a line that
    # carries two pins is evaluated as two independent pins.
    while IFS= read -r hit; do
        lineno="${hit%%:*}"
        matched="${hit#*:}"
        # A pin already referencing the latest version is fine.
        [[ "$matched" == *"$LATEST_BARE"* ]] && continue
        echo "STALE ($desc) line ${lineno}: ${matched}"
        stale=1
    done < <(grep -onE "$pat" "$README" 2>/dev/null || true)
done

echo ""
if [[ "$stale" -eq 1 ]]; then
    echo "ERROR: ${README} contains install-instruction version references that do not match the"
    echo "       latest published release (${LATEST_TAG})."
    echo ""
    echo "  Update each STALE pin listed above so it references ${LATEST_TAG} / ${LATEST_BARE}."
    echo "  Do NOT edit Cargo.toml version — semantic-release owns that field."
    exit 1
fi

echo "OK: all ${README} install-instruction version references match ${LATEST_TAG}."
exit 0
