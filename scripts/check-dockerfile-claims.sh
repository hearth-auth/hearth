#!/usr/bin/env bash
# scripts/check-dockerfile-claims.sh — the Dockerfile must not describe a build
# other than the one it defines.
#
# Audit 2026-08-28 finding §4.8#15 (Informational):
#
#   The Dockerfile carries three false statements about the build it defines.
#
# Four were found in the end:
#
#   1. "the repo's declared `rust-version = "1.75"` is aspirational" — Cargo.toml
#      declares 1.88.0, and ci.yml's `msrv` job builds at exactly that toolchain.
#   2. "copy the static-ish binary" — it is dynamically linked against glibc,
#      which is why the runtime base is Debian and not `scratch`. Stage 1's own
#      comment said so two lines earlier.
#   3. "pure-Rust TLS" — `ring` bundles C and assembly, and `aws-lc-rs` compiles
#      AWS-LC (C) for rcgen's RSA key generation.
#   4. "keep the streaming phase under a couple of megabytes" — a clean checkout
#      streams roughly 22 MB.
#
# Three of the four are prose that only a reader can re-check. The two that rot
# silently are mechanical, and this guard holds them: a version claim that
# drifts from Cargo.toml, and a "static" claim about a dynamically linked build.
# It also checks the documented run command against the real CMD/ENTRYPOINT.
#
# Usage:  bash scripts/check-dockerfile-claims.sh
# Env:    DOCKERFILE  (default Dockerfile)
#         CARGO_TOML  (default Cargo.toml)

set -uo pipefail

DOCKERFILE="${DOCKERFILE:-Dockerfile}"
CARGO_TOML="${CARGO_TOML:-Cargo.toml}"

for f in "$DOCKERFILE" "$CARGO_TOML"; do
    [[ -f "$f" ]] || { echo "FAIL: ${f} not found."; exit 1; }
done

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# ── 1. Any rust-version the Dockerfile quotes must be the declared one ───────
declared="$(grep -m1 '^rust-version' "$CARGO_TOML" | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -z "$declared" ]]; then
    fail "${CARGO_TOML} declares no rust-version."
else
    while IFS= read -r quoted; do
        [[ "$quoted" == "$declared" ]] && continue
        fail "${DOCKERFILE} says rust-version = \"${quoted}\"; ${CARGO_TOML} declares \"${declared}\"."
    done < <(grep -oE 'rust-version[^"]*"[0-9]+\.[0-9]+(\.[0-9]+)?"' "$DOCKERFILE" \
             | sed -E 's/.*"([^"]+)"/\1/')
fi

# The builder image must be at least the declared MSRV, or the image cannot
# build what CI says is supported.
builder="$(grep -m1 -oE '^FROM rust:[0-9]+\.[0-9]+' "$DOCKERFILE" | sed 's/^FROM rust://')"
if [[ -z "$builder" ]]; then
    fail "${DOCKERFILE} has no 'FROM rust:<version>' builder stage."
else
    if [[ "$(printf '%s\n%s\n' "$declared" "$builder" | sort -V | head -1)" != "$declared" ]]; then
        fail "${DOCKERFILE} builds on rust:${builder}, older than the declared MSRV ${declared}."
    fi
fi

# ── 2. No "static" claim about a dynamically linked build ────────────────────
# The runtime base is a full libc image precisely because the binary needs one.
runtime_base="$(grep -oE '^FROM [^ ]+ AS runtime' "$DOCKERFILE" | awk '{print $2}')"
if [[ -n "$runtime_base" && "$runtime_base" != scratch* ]]; then
    while IFS= read -r line; do
        fail "${DOCKERFILE} describes the binary as static (\"$(printf '%s' "$line" | sed -E 's/^#[[:space:]]*//' | cut -c1-70)\"), but the runtime base is ${runtime_base}, not scratch — the binary is dynamically linked."
    done < <(grep -nE '^#.*(static-ish|statically linked|static binary)' "$DOCKERFILE" | cut -d: -f2-)
fi

# ── 3. The documented run command must be the real one ───────────────────────
cmd="$(grep -m1 -oE '^CMD \[.*\]' "$DOCKERFILE" \
    | sed -E 's/^CMD \[//; s/\]$//; s/"//g; s/,[[:space:]]*/ /g')"
if [[ -z "$cmd" ]]; then
    fail "${DOCKERFILE} has no CMD."
else
    documented="$(grep -oE '`hearth [^`]+`' "$DOCKERFILE" | head -1 | tr -d '`')"
    if [[ -n "$documented" && "$documented" != "hearth ${cmd}" ]]; then
        fail "${DOCKERFILE} says it runs '${documented}' but CMD is 'hearth ${cmd}'."
    fi
fi

if [[ "$failures" -gt 0 ]]; then
    echo
    echo "${failures} false statement(s) in ${DOCKERFILE} (audit §4.8#15)."
    exit 1
fi

echo "OK: ${DOCKERFILE}'s checkable claims match the build it defines."
