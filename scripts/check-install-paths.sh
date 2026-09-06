#!/usr/bin/env bash
# scripts/check-install-paths.sh — the README's install paths must work for
# a stranger.
#
# Audit 2026-08-28 findings §4.8#5 and §4.12#4 (HIGH):
#
#   The container image and Helm chart the README tells operators to install
#   are not anonymously readable; two of the three documented install paths
#   fail at the first command.
#
# `docker pull` and `helm install` both start by fetching a manifest from
# ghcr.io with an anonymous bearer token. This script performs exactly that
# fetch — no credentials, ever — for the image tag and chart version the
# README pins. A 403 here is byte-for-byte the failure a new operator sees.
#
# The fix for a 403 is not in this repository: an org admin must set both
# GHCR packages to Public (github.com → hearth-auth org → Packages →
# <package> → Package settings → Danger Zone → Change visibility). There is
# no REST API for that toggle. This gate exists so a release cannot claim
# its install docs work while they do not, and so a later flip back to
# Private turns the next release red instead of stranding operators.
#
# Usage:  bash scripts/check-install-paths.sh
# Env:    README_PATH  (default README.md)

set -uo pipefail

README_PATH="${README_PATH:-README.md}"
REGISTRY="ghcr.io"
IMAGE_REPO="hearth-auth/hearth"
CHART_REPO="hearth-auth/charts/hearth"

[[ -f "$README_PATH" ]] || { echo "FAIL: ${README_PATH} not found."; exit 1; }

# The versions under test are the ones the README documents — the same pins
# scripts/check-readme-version.sh keeps current against the latest release.
IMAGE_TAG="$(grep -oE "ghcr\.io/${IMAGE_REPO}:v[0-9]+\.[0-9]+\.[0-9]+" "$README_PATH" \
    | head -1 | sed 's/.*://')"
CHART_VERSION="$(grep -A3 "oci://ghcr\.io/${CHART_REPO}" "$README_PATH" \
    | grep -oE -- '--version [0-9]+\.[0-9]+\.[0-9]+' | head -1 | awk '{print $2}')"

[[ -n "$IMAGE_TAG" ]] || { echo "FAIL: no pinned image tag found in ${README_PATH}."; exit 1; }
[[ -n "$CHART_VERSION" ]] || { echo "FAIL: no pinned chart version found in ${README_PATH}."; exit 1; }

failures=0

# anon_manifest <repo> <reference> <label> — the first request of a pull.
anon_manifest() {
    local repo="$1" ref="$2" label="$3"
    local token code
    # Anonymous token: no Authorization header on the token request. ghcr.io
    # answers 200 with a token for a public package and 401 for a private or
    # nonexistent one, so the token request alone decides reachability.
    token="$(curl -sf "https://${REGISTRY}/token?scope=repository:${repo}:pull" \
        | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
    if [[ -z "$token" ]]; then
        echo "FAIL: ${label}: ghcr.io refused an anonymous pull token for ${repo}."
        echo "      The package is private or absent, so the documented install"
        echo "      command fails at its first request. An org admin must set the"
        echo "      GHCR package to Public (Package settings → Danger Zone →"
        echo "      Change visibility) — audit 2026-08-28 §4.8#5, §4.12#4."
        failures=$((failures + 1))
        return
    fi
    code="$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.cncf.helm.config.v1+json" \
        "https://${REGISTRY}/v2/${repo}/manifests/${ref}")"
    if [[ "$code" != "200" ]]; then
        echo "FAIL: ${label}: anonymous manifest fetch for ${repo}:${ref} returned HTTP ${code}."
        echo "      This is the first request of the documented install command, run"
        echo "      without credentials. An org admin must set the GHCR package to"
        echo "      Public (Package settings → Danger Zone → Change visibility) —"
        echo "      audit 2026-08-28 §4.8#5, §4.12#4."
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${label}: ${repo}:${ref} is anonymously pullable."
}

anon_manifest "$IMAGE_REPO" "$IMAGE_TAG" "docker install path"
anon_manifest "$CHART_REPO" "$CHART_VERSION" "helm install path"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} documented install path(s) fail at the first command."
    echo "See scripts/check-install-paths.sh for the fix and the audit citation."
    exit 1
fi
echo "OK: the README's Docker and Helm install paths are anonymously reachable."
exit 0
