#!/usr/bin/env bash
# scripts/tests/check-readme-version.test.sh — tests for scripts/check-readme-version.sh (HEA-2116).
#
# The guard itself is the deliverable, so the guard needs a test that proves it
# FAILS on a deliberately stale reference — not just that it passes on a good
# README (which a `exit 0` stub would also satisfy).
#
# Case 3 is the regression that motivated this file: the first implementation
# filtered whole LINES containing the latest version, so a line carrying both a
# fresh pin and a stale pin (README line 1: badge alt-text + badge URL; README
# line 21: prose + Releases URL) passed the guard while half-updated.
#
# Resolution path (HEA-2199): the script resolves the reference version from
# `gh release list`, not `git tag`, so a tag without published binary artifacts
# does not advance the guard. The tests use README_LATEST_TAG to bypass
# resolution entirely — they validate pattern-matching logic, not resolution.
#
# Usage: bash scripts/tests/check-readme-version.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-readme-version.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export README_LATEST_TAG="v1.6.6"

failures=0

# run_case <name> <expected-exit> <readme-body> [expected-substring-in-output]
run_case() {
    local name="$1" want="$2" body="$3" expect="${4:-}"
    printf '%s\n' "$body" > "$TMP/README.md"
    local out got
    out="$(README_PATH="$TMP/README.md" bash "$CHECK" 2>&1)"
    got=$?
    if [[ "$got" -ne "$want" ]]; then
        echo "FAIL: ${name} — expected exit ${want}, got ${got}"
        echo "$out" | sed 's/^/    /'
        failures=$((failures + 1))
        return
    fi
    if [[ -n "$expect" && "$out" != *"$expect"* ]]; then
        echo "FAIL: ${name} — output missing expected text: ${expect}"
        echo "$out" | sed 's/^/    /'
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${name}"
}

CURRENT='![v1.6.6](https://img.shields.io/badge/status-v1.6.6-brightgreen)
> **Stable 1.6.6:** APIs and on-disk formats are stable.
Download pre-built v1.6.6 artifacts from the [Releases page](https://github.com/hearth-auth/hearth/releases/tag/v1.6.6).
curl -LO https://github.com/hearth-auth/hearth/releases/download/v1.6.6/SHA256SUMS
docker pull ghcr.io/hearth-auth/hearth:v1.6.6
  --version 1.6.6 \
  ghcr.io/hearth-auth/charts/hearth:1.6.6'

# 1 — a fully current README passes.
run_case "current README passes" 0 "$CURRENT" \
    "OK: all"

# 2 — the pre-fix README (every pin at v1.0.0) is rejected.
run_case "wholly stale README is rejected" 1 "${CURRENT//1.6.6/1.0.0}" \
    "STALE (GitHub Releases tag URL)"

# 3 — REGRESSION: a line carrying one fresh pin and one stale pin is rejected.
#     Prose says v1.6.6, the URL on the SAME LINE still says v1.0.0.
run_case "half-updated line is rejected (prose fresh, URL stale)" 1 \
    'Download pre-built v1.6.6 artifacts from the [Releases page](https://github.com/hearth-auth/hearth/releases/tag/v1.0.0).' \
    "STALE (GitHub Releases tag URL) line 1: releases/tag/v1.0.0"

# 4 — REGRESSION: badge alt-text fresh, badge URL stale, same line.
run_case "half-updated badge line is rejected" 1 \
    '![v1.6.6](https://img.shields.io/badge/status-v1.0.0-brightgreen)' \
    "STALE (Status badge URL)"

# 5 — a stale Helm --version pin is rejected (docker/helm block coverage).
run_case "stale helm --version is rejected" 1 \
    '  --version 1.5.0 \' \
    "STALE (Helm --version flag) line 1: --version 1.5.0"

# 6 — the CHANGELOG-style prose elsewhere in the file must NOT trip the guard.
run_case "unrelated version mentions do not trip the guard" 0 \
    '- **Rust 1.88.0+** (see Cargo.toml rust-version)
Released 1.4.2 on 2026-01-01; see CHANGELOG for 1.0.0 history.' \
    "OK: all"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "all check-readme-version.sh test cases passed."
exit 0
