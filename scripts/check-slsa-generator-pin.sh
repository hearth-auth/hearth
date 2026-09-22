#!/usr/bin/env bash
# scripts/check-slsa-generator-pin.sh — the third-party SLSA provenance
# generator must still be the commit we reviewed.
#
# Audit 2026-08-28 finding §4.8#13 (MEDIUM):
#
#   A third-party reusable workflow holding `contents: write` + `id-token: write`
#   is referenced by mutable tag, with an incorrect justification.
#
# The workflow is slsa-framework/slsa-github-generator's
# generator_generic_slsa3.yml, referenced from .github/workflows/release.yml.
# Every other third-party action in this repository is pinned to a commit SHA.
# This one cannot be: its `generator` job downloads the builder binary from the
# release at the ref `detect-env` resolves, and upstream states that ref "must
# be a tag reference". A `@<sha>` reference fails there.
#
# The comment that used to sit beside it claimed GitHub resolves the tag to a
# commit at checkout time, "providing equivalent security". That is false. A tag
# is mutable: whoever controls the upstream repository can re-point v2.1.0 at
# any commit, and the next release would run it with `contents: write` and
# `id-token: write` — enough to write release assets and to mint Sigstore
# certificates under Hearth's identity.
#
# This guard restores the missing property. .github/slsa-generator.pin records
# the tag and the commit it must resolve to; the guard resolves the tag and
# refuses a mismatch. It runs on every PR and as a hard gate in the release
# `validation` job, which `provenance` needs — so a moved tag stops a release.
#
# Usage:  bash scripts/check-slsa-generator-pin.sh
# Env:    PIN_FILE         (default .github/slsa-generator.pin)
#         RELEASE_WORKFLOW (default .github/workflows/release.yml)
#         RESOLVED_SHA     (skip the network lookup; used by the self-test)

set -uo pipefail

PIN_FILE="${PIN_FILE:-.github/slsa-generator.pin}"
RELEASE_WORKFLOW="${RELEASE_WORKFLOW:-.github/workflows/release.yml}"
UPSTREAM="${UPSTREAM:-https://github.com/slsa-framework/slsa-github-generator}"

for f in "$PIN_FILE" "$RELEASE_WORKFLOW"; do
    [[ -f "$f" ]] || { echo "FAIL: ${f} not found."; exit 1; }
done

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# ── The recorded pin ─────────────────────────────────────────────────────────
pin_line="$(grep -vE '^[[:space:]]*(#|$)' "$PIN_FILE" | head -1)"
pinned_tag="$(printf '%s\n' "$pin_line" | awk '{print $1}')"
pinned_sha="$(printf '%s\n' "$pin_line" | awk '{print $2}')"

if [[ -z "$pinned_tag" || -z "$pinned_sha" ]]; then
    echo "FAIL: ${PIN_FILE} has no '<tag> <commit-sha>' line."
    exit 1
fi
if ! [[ "$pinned_sha" =~ ^[0-9a-f]{40}$ ]]; then
    fail "${PIN_FILE} records '${pinned_sha}', which is not a 40-character commit SHA."
fi

# ── The reference in the workflow ────────────────────────────────────────────
used_ref="$(grep -oE 'slsa-framework/slsa-github-generator/[^@[:space:]]+@[^[:space:]]+' \
    "$RELEASE_WORKFLOW" | head -1)"

if [[ -z "$used_ref" ]]; then
    fail "${RELEASE_WORKFLOW} no longer references slsa-github-generator; remove ${PIN_FILE} or restore the reference."
else
    used_tag="${used_ref##*@}"
    if [[ "$used_tag" != "$pinned_tag" ]]; then
        fail "${RELEASE_WORKFLOW} uses '@${used_tag}' but ${PIN_FILE} pins '${pinned_tag}'. Update both in the same commit, after reviewing the upstream diff."
    fi
fi

# ── The tag must still resolve to the reviewed commit ────────────────────────
if [[ -n "${RESOLVED_SHA:-}" ]]; then
    resolved="$RESOLVED_SHA"
else
    # `refs/tags/<t>^{}` is the commit an annotated tag points at; a lightweight
    # tag has only `refs/tags/<t>`. Prefer the dereferenced form when present.
    ls_remote="$(git ls-remote "$UPSTREAM" "refs/tags/${pinned_tag}" "refs/tags/${pinned_tag}^{}" 2>&1)"
    ls_rc=$?
    if [[ "$ls_rc" -ne 0 || -z "$ls_remote" ]]; then
        echo "FAIL: could not resolve ${pinned_tag} at ${UPSTREAM}."
        printf '%s\n' "$ls_remote" | sed 's/^/       /'
        echo "       This guard must not pass on a failed lookup — a moved tag would go unnoticed."
        exit 1
    fi
    deref="$(printf '%s\n' "$ls_remote" | awk '/\^\{\}$/ {print $1}' | head -1)"
    plain="$(printf '%s\n' "$ls_remote" | awk '!/\^\{\}$/ {print $1}' | head -1)"
    resolved="${deref:-$plain}"
fi

if [[ "$resolved" != "$pinned_sha" ]]; then
    fail "${pinned_tag} now resolves to ${resolved}, not the reviewed ${pinned_sha}. The upstream tag moved. Do NOT update the pin without reviewing what changed — this workflow runs with contents: write and id-token: write."
fi

if [[ "$failures" -gt 0 ]]; then
    echo
    echo "${failures} problem(s) with the SLSA generator pin (audit §4.8#13)."
    exit 1
fi

echo "OK: slsa-github-generator ${pinned_tag} still resolves to ${pinned_sha}."
