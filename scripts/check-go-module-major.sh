#!/usr/bin/env bash
# scripts/check-go-module-major.sh — the Go SDK's module path must carry the
# major version of the release (OpenSpec change `sdk-go-module-major`).
#
# Go resolves a tag `vN.x.y` with N >= 2 only for a module whose path ends in
# `/vN`; for N of 0 or 1 the path has no suffix. The Go SDK's go.mod declared
# `github.com/hearth-auth/hearth/sdks/go` while semantic-release tagged
# `sdks/go/v3.x.y`, so Go ignored every v2 and v3 tag and `go get` stopped at
# v1.6.11.
#
# semantic-release runs this as the Go SDK's `verifyReleaseCmd` with the next
# version, so a release that would tag an uninstallable version fails before it
# creates the tag. CI runs scripts/tests/check-go-module-major.test.sh.
#
# Usage:  bash scripts/check-go-module-major.sh <version>     (e.g. 3.5.9)
# Env:    GO_MOD   (default: sdks/go/go.mod next to this script's repo root)
# Exit:   0 match, 1 mismatch or unreadable go.mod, 2 usage

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_MOD="${GO_MOD:-${REPO_ROOT}/sdks/go/go.mod}"
VERSION="${1:-}"

if [[ ! "$VERSION" =~ ^([0-9]+)\.[0-9]+\.[0-9]+([-+].*)?$ ]]; then
    echo "usage: $0 <version>   (a semver version such as 3.5.9; got '${VERSION}')"
    exit 2
fi
MAJOR="${BASH_REMATCH[1]}"

if [[ ! -f "$GO_MOD" ]]; then
    echo "FAIL: ${GO_MOD} not found."
    exit 1
fi
MODULE="$(awk '$1 == "module" { print $2; exit }' "$GO_MOD")"
if [[ -z "$MODULE" ]]; then
    echo "FAIL: ${GO_MOD} declares no module path."
    exit 1
fi

if [[ "$MODULE" =~ /v([0-9]+)$ ]]; then
    SUFFIX="${BASH_REMATCH[1]}"
    BASE="${MODULE%/v*}"
else
    SUFFIX=""
    BASE="$MODULE"
fi

if (( MAJOR >= 2 )); then
    if [[ "$SUFFIX" != "$MAJOR" ]]; then
        echo "FAIL: release ${VERSION} has major version ${MAJOR}, so the Go module path must end in /v${MAJOR}."
        echo "      ${GO_MOD} declares '${MODULE}'. Go ignores the tag otherwise, and 'go get' cannot install it."
        echo "      Change the module path and every import of it to '${BASE}/v${MAJOR}'."
        exit 1
    fi
elif [[ -n "$SUFFIX" ]]; then
    echo "FAIL: release ${VERSION} has major version ${MAJOR}, so the Go module path must not end in a /vN suffix."
    echo "      ${GO_MOD} declares '${MODULE}'. Change it and every import of it to '${BASE}'."
    exit 1
fi

echo "OK: Go module '${MODULE}' can release ${VERSION}."
exit 0
