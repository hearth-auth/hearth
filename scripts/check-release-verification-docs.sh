#!/usr/bin/env bash
# scripts/check-release-verification-docs.sh — the documented verification path
# must be executable, and must verify something an attacker cannot forge.
#
# Audit 2026-08-28 finding §4.8#12 (MEDIUM):
#
#   The release-verification guide contains two commands that fail, and the
#   README's headline install step verifies nothing an attacker could not forge.
#
# The two failing commands:
#
#   * `cosign triangulate --type=blob <artifact>` — triangulate derives the
#     signature tag of a container image. Hearth's release artefacts carry
#     detached blob signatures, and `blob` is not one of triangulate's types.
#   * `brew install slsa-verifier` — slsa-verifier has no Homebrew formula.
#
# The forgeable step: the README told operators to download the binary and
# SHA256SUMS from the same release page and run `sha256sum -c`. Anyone who can
# substitute the binary can substitute the manifest beside it. The unforgeable
# check is `cosign verify-blob` over SHA256SUMS against the pinned workflow
# identity — a signature Sigstore logs publicly — and the release already ships
# SHA256SUMS.sig and SHA256SUMS.pem for exactly that.
#
# This guard is offline. It reads the docs and the release workflow, and refuses
# a combination that cannot execute or that verifies nothing.
#
# Usage:  bash scripts/check-release-verification-docs.sh
# Env:    README        (default README.md)
#         GUIDE         (default docs/guides/verify-release.md)
#         RELEASE_WORKFLOW (default .github/workflows/release.yml)

set -uo pipefail

README="${README:-README.md}"
GUIDE="${GUIDE:-docs/guides/verify-release.md}"
RELEASE_WORKFLOW="${RELEASE_WORKFLOW:-.github/workflows/release.yml}"

for f in "$README" "$GUIDE" "$RELEASE_WORKFLOW"; do
    [[ -f "$f" ]] || { echo "FAIL: ${f} not found."; exit 1; }
done

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# ── 1. No command that cannot execute ────────────────────────────────────────
for f in "$README" "$GUIDE"; do
    if grep -q 'cosign triangulate' "$f"; then
        # A line that documents the command as NOT working is fine; a line that
        # tells the reader to run it is not.
        if grep -E '^\s*cosign triangulate' "$f" | grep -q .; then
            fail "${f} tells the reader to run 'cosign triangulate' on a detached blob signature. triangulate takes an image reference; there is no blob type."
        fi
    fi
    if grep -qE '^\s*brew install slsa-verifier' "$f"; then
        fail "${f} tells the reader to run 'brew install slsa-verifier'. There is no Homebrew formula for slsa-verifier."
    fi
done

# ── 2. Every documented asset must actually be published ─────────────────────
#
# The `gh release create` argument list in release.yml is the authority. A doc
# that names an asset the release does not upload sends the operator to a 404.
release_assets="$(awk '
    /gh release create/ { inlist = 1 }
    inlist {
        if ($0 ~ /dist\//) print
        # The argument list ends at the first line without a line continuation.
        if ($0 !~ /\\[[:space:]]*$/) inlist = 0
    }
' "$RELEASE_WORKFLOW" | sed -E "s@^[[:space:]]*'?dist/@@; s@'?[[:space:]]*\\\\?[[:space:]]*\$@@")"

if [[ -z "$release_assets" ]]; then
    fail "could not read the release asset list from ${RELEASE_WORKFLOW}."
fi

# asset_is_published <name> — true if the name is uploaded literally or by glob.
asset_is_published() {
    local want="$1" have
    while IFS= read -r have; do
        [[ -z "$have" ]] && continue
        [[ "$want" == "$have" ]] && return 0
        # shellcheck disable=SC2053 — glob match is the point (dist/*.sig).
        [[ "$want" == $have ]] && return 0
    done <<< "$release_assets"
    return 1
}

# Assets the guide's table names, with <os>-<arch> resolved to one real target.
for asset in \
    hearth-linux-amd64 \
    hearth-linux-amd64.sig \
    hearth-linux-amd64.pem \
    hearth-sbom.cdx.json \
    hearth-sbom.cdx.json.sig \
    hearth-sbom.cdx.json.pem \
    SHA256SUMS \
    SHA256SUMS.sig \
    SHA256SUMS.pem \
    multiple.intoto.jsonl
do
    if ! asset_is_published "$asset"; then
        fail "${GUIDE} documents '${asset}', which ${RELEASE_WORKFLOW} never uploads."
    fi
done

# ── 3. The README must verify the manifest before trusting it ────────────────
#
# Each fenced block that checks a downloaded binary against SHA256SUMS must
# first verify SHA256SUMS itself with cosign.
check_block_verifies_manifest() {
    local file="$1" label="$2" block="$3"
    # Does this block check something against the manifest at all?
    if ! printf '%s\n' "$block" | grep -qE 'sha256sum -c|shasum -a 256 -c|Get-FileHash'; then
        return 0
    fi
    if ! printf '%s\n' "$block" | grep -q 'cosign verify-blob'; then
        fail "${file}: the ${label} install block checks a binary against SHA256SUMS without verifying SHA256SUMS. An attacker who replaces the binary replaces the manifest beside it."
        return 0
    fi
    if ! printf '%s\n' "$block" | grep -q 'certificate-oidc-issuer'; then
        fail "${file}: the ${label} install block runs 'cosign verify-blob' without pinning --certificate-oidc-issuer, so any Sigstore identity satisfies it."
    fi
    if ! printf '%s\n' "$block" | grep -q 'certificate-identity-regexp'; then
        fail "${file}: the ${label} install block runs 'cosign verify-blob' without pinning --certificate-identity-regexp, so any workflow's signature satisfies it."
    fi
    # Ordering: the verification must precede the comparison.
    local verify_at compare_at
    verify_at="$(printf '%s\n' "$block" | grep -n 'cosign verify-blob' | head -1 | cut -d: -f1)"
    compare_at="$(printf '%s\n' "$block" | grep -nE 'sha256sum -c|shasum -a 256 -c|Get-FileHash' | head -1 | cut -d: -f1)"
    if [[ -n "$verify_at" && -n "$compare_at" && "$verify_at" -gt "$compare_at" ]]; then
        fail "${file}: the ${label} install block compares against SHA256SUMS before verifying it."
    fi
}

# Extract each fenced code block that downloads a release binary.
readme_blocks="$(awk '
    /^```/ { infence = !infence; if (!infence) { print "\036" } next }
    infence { print }
' "$README")"

block=""
label=""
while IFS= read -r line; do
    if [[ "$line" == $'\036' ]]; then
        if [[ -n "$label" ]]; then
            check_block_verifies_manifest "$README" "$label" "$block"
        fi
        block=""
        label=""
        continue
    fi
    block+="${line}"$'\n'
    if [[ "$line" == *"releases/download/"* ]]; then
        if [[ "$line" == *"Invoke-WebRequest"* || "$line" == *'-Uri'* ]]; then
            label="Windows"
        else
            label="Linux/macOS"
        fi
    fi
done <<< "$readme_blocks"
[[ -n "$label" ]] && check_block_verifies_manifest "$README" "$label" "$block"

if [[ "$failures" -gt 0 ]]; then
    echo
    echo "${failures} problem(s) with the documented release-verification path (audit §4.8#12)."
    exit 1
fi

echo "OK: every documented verification command is executable, and the README verifies the manifest before trusting it."
