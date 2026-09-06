#!/usr/bin/env bash
# scripts/tests/stamp-version.test.sh — tests for scripts/stamp-version.sh.
#
# The stamp exists so a released SBOM cannot describe a stale version (audit
# §4.8#11, §4.12#5). Case 1 is the release shape; case 4 pins the failure
# mode that would silently corrupt a dependency pin instead of the package
# version.
#
# Usage: bash scripts/tests/stamp-version.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${SCRIPT_DIR}/stamp-version.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
check() {
    local name="$1" cond="$2"
    if eval "$cond"; then
        echo "ok: ${name}"
    else
        echo "FAIL: ${name}"
        failures=$((failures + 1))
    fi
}

FIXTURE='[package]
name = "hearth"
version = "1.6.9"
edition = "2021"

[dependencies]
axum = { version = "0.8", features = ["multipart"] }
serde = { version = "1" }
'

# 1 — a v-prefixed tag stamps the package version, stripped of the v.
printf '%s' "$FIXTURE" > "$TMP/a.toml"
CARGO_TOML="$TMP/a.toml" bash "$STAMP" v9.9.9 >/dev/null
check "v-tag stamps package version" 'grep -q "^version = \"9.9.9\"" "$TMP/a.toml"'

# 2 — a bare version stamps unchanged.
printf '%s' "$FIXTURE" > "$TMP/b.toml"
CARGO_TOML="$TMP/b.toml" bash "$STAMP" 2.0.0 >/dev/null
check "bare version stamps" 'grep -q "^version = \"2.0.0\"" "$TMP/b.toml"'

# 3 — a non-release ref is a no-op that exits 0.
printf '%s' "$FIXTURE" > "$TMP/c.toml"
CARGO_TOML="$TMP/c.toml" bash "$STAMP" main >/dev/null
check "non-release ref exits 0 and leaves the file alone" \
    'grep -q "^version = \"1.6.9\"" "$TMP/c.toml"'

# 4 — dependency version pins are never touched.
check "dependency pins untouched" \
    'grep -q "axum = { version = \"0.8\"" "$TMP/a.toml" && grep -q "serde = { version = \"1\"" "$TMP/a.toml"'

# 5 — a missing Cargo.toml is a hard failure, not a silent pass.
if CARGO_TOML="$TMP/missing.toml" bash "$STAMP" v1.0.0 >/dev/null 2>&1; then
    echo "FAIL: missing Cargo.toml should exit non-zero"
    failures=$((failures + 1))
else
    echo "ok: missing Cargo.toml exits non-zero"
fi

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "OK: all stamp-version.sh cases passed."
exit 0
