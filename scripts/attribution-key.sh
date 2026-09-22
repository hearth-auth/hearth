#!/usr/bin/env bash
# scripts/attribution-key.sh — print the freshness key for THIRD_PARTY_LICENSES.
#
# Audit 2026-08-28 finding §4.8#10 (LOW):
#
#   The attribution freshness key is a whole-file hash of `Cargo.lock` that
#   includes the workspace's own version, so the release procedure trips a
#   legal-attribution gate with nothing to attribute.
#
# `make notice` used to store `sha256sum Cargo.lock`, and `make notice-check`
# compared against it. The workspace's own packages are entries in that file, so
# a version bump — every release does one — changed the hash and failed the
# gate. The operator is then told to regenerate THIRD_PARTY_LICENSES and commit
# it, for a change that adds, removes and alters nothing attributable.
#
# The key is now a hash of what attribution actually depends on: for every
# third-party package in Cargo.lock, its `name`, `version`, `source` and
# `checksum`. Two kinds of line are dropped.
#
#   * Workspace members. A `[[package]]` block with no `source =` line is a path
#     package, and cargo-about has nothing to attribute for it.
#   * `dependencies = [...]` edges. Re-pointing an edge between packages that
#     are all still in the lockfile changes no crate's licence. Verified on this
#     branch: the edge churn from removing reqwest and aws-lc-rs from the build
#     left `cargo about generate` byte-identical, while the whole-file hash had
#     already gone red.
#
# Everything that CAN change attribution still changes the key: a package added
# or removed, a version bump, a different registry, a different checksum.
#
# Usage:  bash scripts/attribution-key.sh [lockfile]
#         bash scripts/attribution-key.sh --packages [lockfile]   # what is hashed
#
# Prints the 64-character hex digest on stdout and nothing else.

set -uo pipefail

MODE="--digest"
if [[ "${1:-}" == "--packages" ]]; then
    MODE="--packages"
    shift
fi

LOCKFILE="${1:-Cargo.lock}"

if [[ ! -f "$LOCKFILE" ]]; then
    echo "ERROR: ${LOCKFILE} not found." >&2
    exit 1
fi

# Emits the attribution-relevant fields of every [[package]] block that has a
# `source =` line, in lockfile order. Blocks are separated by a blank line; a
# top-level section header other than [[package]] (e.g. [[patch.unused]]) ends
# the current block and is skipped.
third_party_packages() {
    awk '
        function flush() {
            if (n > 0 && has_source) {
                for (i = 1; i <= n; i++) print buf[i]
                print ""
            }
            n = 0
            has_source = 0
        }
        /^\[/ {
            flush()
            in_pkg = ($0 == "[[package]]")
            next
        }
        !in_pkg { next }
        # Blank line ends the block.
        /^[[:space:]]*$/ { flush(); next }
        /^source = / { has_source = 1 }
        # Keep only the fields cargo-about attributes on. Everything else in a
        # block is `dependencies = [...]` edges, which cannot change a licence.
        /^(name|version|source|checksum) = / { buf[++n] = $0 }
        END { flush() }
    ' "$LOCKFILE"
}

if [[ "$MODE" == "--packages" ]]; then
    third_party_packages
    exit 0
fi

# sha256sum is GNU; shasum ships on macOS. Either is fine — the value is only
# ever compared against one produced by this same script.
if command -v sha256sum >/dev/null 2>&1; then
    third_party_packages | sha256sum | awk '{print $1}'
elif command -v shasum >/dev/null 2>&1; then
    third_party_packages | shasum -a 256 | awk '{print $1}'
else
    echo "ERROR: neither sha256sum nor shasum is available." >&2
    exit 1
fi
