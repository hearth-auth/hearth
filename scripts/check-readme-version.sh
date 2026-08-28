#!/usr/bin/env bash
# scripts/check-readme-version.sh — CI guard: README install references must match the latest published binary release.
#
# Tracks: HEA-2116 / HEA-2199. Ensures a release cannot ship with stale version pins in the
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
# The reference version is the highest semver GitHub Release whose tag does NOT carry
# an SDK prefix (e.g. sdk-ts-v1.6.10 is excluded; v1.6.9 is included). This means
# a git tag pushed without a corresponding binary release does NOT advance the guard —
# preventing the trap where obeying the guard would publish 404 install docs (HEA-2199).
#
# Usage: scripts/check-readme-version.sh
# Env (test hooks only — unset in CI):
#   README_PATH        path to the file to check               (default: README.md)
#   README_LATEST_TAG  override the resolved release tag  (default: latest published binary release)
# Exit:  0 if all references match the latest published release, 1 otherwise.

set -euo pipefail

README="${README_PATH:-README.md}"

if [[ ! -f "$README" ]]; then
    echo "ERROR: ${README} not found (run from the repository root)."
    exit 1
fi

# Resolve the latest published binary release (e.g. v1.6.9).
# Uses `gh release list` and excludes SDK-prefixed releases (sdk-ts-*, sdk-rust-*, etc.)
# so a git tag pushed without binary artifacts does not advance the guard (HEA-2199).
#
# GH_TOKEN must be set in CI so `gh` can authenticate. An unauthenticated call fails
# loudly here — no exit-0 skip branch; an unresolvable release is always a hard error
# (HEA-2203).
if [[ -n "${README_LATEST_TAG:-}" ]]; then
    LATEST_TAG="$README_LATEST_TAG"
else
    _gh_err="$(mktemp)"
    trap 'rm -f "$_gh_err"' EXIT
    if ! _gh_list="$(gh release list --limit 100 2>"$_gh_err")"; then
        echo "ERROR: gh release list failed — ensure GH_TOKEN is set in CI (HEA-2203)."
        [[ -s "$_gh_err" ]] && sed 's/^/  /' "$_gh_err"
        exit 1
    fi
    LATEST_TAG="$(printf '%s\n' "$_gh_list" \
        | awk -F'\t' '{print $1}' \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -V | tail -1 || true)"
fi
if [[ -z "$LATEST_TAG" ]]; then
    echo "ERROR: no published binary release found (gh release list returned nothing matching v[0-9]+.[0-9]+.[0-9]+)."
    echo "       SDK-prefixed releases (sdk-ts-*, etc.) are excluded by design."
    exit 1
fi

# Bare version string without the leading 'v' (e.g. 1.6.6).
LATEST_BARE="${LATEST_TAG#v}"

echo "Latest published binary release: ${LATEST_TAG}  (bare: ${LATEST_BARE})"

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
    echo "       latest published binary release (${LATEST_TAG})."
    echo ""
    echo "  Update each STALE pin listed above so it references ${LATEST_TAG} / ${LATEST_BARE}."
    echo "  Do NOT edit Cargo.toml version — semantic-release owns that field."
    echo "  Note: the guard keys off published binary releases, not git tags."
    exit 1
fi

echo "OK: all ${README} install-instruction version references match the latest published binary release (${LATEST_TAG})."
exit 0
