#!/usr/bin/env bash
# scripts/check-readme-version.sh — CI guard: README install references must match the latest git tag.
#
# Tracks: HEA-2116. Ensures a release cannot ship with stale version pins in the
# install section of README.md. The patterns checked are:
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
# The latest tag is the highest semver tag in the local repo (vX.Y.Z). The check
# requires `git tag` history to be present — CI checkouts must use `fetch-depth: 0`.
#
# Usage: scripts/check-readme-version.sh
# Env (test hooks only — unset in CI):
#   README_PATH        path to the file to check          (default: README.md)
#   README_LATEST_TAG  override the resolved release tag  (default: highest local semver tag)
# Exit:  0 if all references match the latest tag, 1 otherwise.

set -euo pipefail

README="${README_PATH:-README.md}"

if [[ ! -f "$README" ]]; then
    echo "ERROR: ${README} not found (run from the repository root)."
    exit 1
fi

# Resolve the latest semver tag (e.g. v1.6.6).
LATEST_TAG="${README_LATEST_TAG:-$(git tag --sort=-version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)}"
if [[ -z "$LATEST_TAG" ]]; then
    echo "ERROR: no semver tags found in this repo (git tag returned nothing matching v[0-9]+.[0-9]+.[0-9]+)."
    echo "       CI must use fetch-depth: 0 so tags are available."
    exit 1
fi

# Bare version string without the leading 'v' (e.g. 1.6.6).
LATEST_BARE="${LATEST_TAG#v}"

echo "Latest release tag: ${LATEST_TAG}  (bare: ${LATEST_BARE})"

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
    echo "       latest release tag (${LATEST_TAG})."
    echo ""
    echo "  Update each STALE pin listed above so it references ${LATEST_TAG} / ${LATEST_BARE}."
    echo "  Do NOT edit Cargo.toml version — semantic-release owns that field."
    exit 1
fi

echo "OK: all ${README} install-instruction version references match ${LATEST_TAG}."
exit 0
