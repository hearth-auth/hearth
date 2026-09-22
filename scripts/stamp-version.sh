#!/usr/bin/env bash
# scripts/stamp-version.sh — stamp the workspace [package] version from the
# server release tag.
#
# Audit 2026-08-28 §2.4, §4.8#11, §4.12#5: the version an operator sees was
# wrong in five of seven surfaces. Both published SBOMs were two of them:
# `cargo cyclonedx` reads Cargo.toml, and Cargo.toml carries the last manually
# bumped value, not the version being released. release.yml and docker.yml run
# this script before generating an SBOM so the SBOM describes the release it
# ships with.
#
# A ref that is not a release version (a branch name, `workflow_dispatch` on
# main) is a deliberate no-op with exit 0: those runs are not releases and
# must not invent one.
#
# Usage:  bash scripts/stamp-version.sh <vX.Y.Z | X.Y.Z>

set -euo pipefail

CARGO_TOML="${CARGO_TOML:-Cargo.toml}"

ref="${1:?usage: stamp-version.sh <vX.Y.Z | X.Y.Z>}"
case "$ref" in
    v[0-9]*) ver="${ref#v}" ;;
    [0-9]*)  ver="$ref" ;;
    *)
        echo "stamp-version: '${ref}' is not a release version ref; leaving ${CARGO_TOML} untouched."
        exit 0
        ;;
esac

[[ -f "$CARGO_TOML" ]] || { echo "stamp-version: ${CARGO_TOML} not found."; exit 1; }

# Replace only the FIRST `version = "…"` line — the [package] version.
# Dependency pins like `axum = { version = "0.8", … }` must not be touched.
awk -v ver="$ver" '
    !done && /^version = "/ { sub(/"[^"]*"/, "\"" ver "\""); done = 1 }
    { print }
' "$CARGO_TOML" > "${CARGO_TOML}.stamped" && mv "${CARGO_TOML}.stamped" "$CARGO_TOML"

grep -q "^version = \"${ver}\"" "$CARGO_TOML" \
    || { echo "stamp-version: failed to stamp ${ver} into ${CARGO_TOML}."; exit 1; }

echo "stamp-version: ${CARGO_TOML} [package] version = ${ver}"
