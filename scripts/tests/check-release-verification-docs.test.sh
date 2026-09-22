#!/usr/bin/env bash
# scripts/tests/check-release-verification-docs.test.sh — tests for
# scripts/check-release-verification-docs.sh (audit 2026-08-28 §4.8#12).
#
# The guard is the deliverable, so it needs a test that proves it FAILS on the
# pre-fix docs — not just that it passes on the fixed ones, which an `exit 0`
# stub would also satisfy.
#
# The defects: the verification guide told the reader to run two commands that
# cannot execute (`cosign triangulate` on a detached blob signature, and
# `brew install slsa-verifier`, which has no formula), and the README's headline
# install step downloaded the binary and SHA256SUMS from the same release page
# and ran `sha256sum -c` — a check anyone who can replace the binary can pass.
#
# Usage: bash scripts/tests/check-release-verification-docs.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-release-verification-docs.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# A release.yml fixture with the same asset list the real workflow uploads.
cat > "${TMP}/release.yml" <<'EOF'
          gh release create "$TAG" \
            --draft \
            --generate-notes \
            --repo "$REPO" \
            dist/hearth-linux-amd64 \
            dist/hearth-linux-arm64 \
            dist/hearth-darwin-amd64 \
            dist/hearth-darwin-arm64 \
            'dist/hearth-windows-amd64.exe' \
            dist/hearth-sbom.cdx.json \
            dist/SHA256SUMS \
            dist/*.sig \
            dist/*.pem \
            dist/multiple.intoto.jsonl \
            dist/validation-summary.txt

          echo done
EOF

# The fixed guide: no unexecutable command.
cat > "${TMP}/guide-good.md" <<'EOF'
# Verifying a Hearth Release

Install slsa-verifier with Go; there is no Homebrew formula:

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1
```

`cosign triangulate` does not work here — these are detached blob signatures.

```bash
rekor-cli search --artifact "${ARTIFACT}"
```
EOF

# The fixed README: verify the manifest, then check against it.
cat > "${TMP}/readme-good.md" <<'EOF'
# Hearth

```bash
curl -LO "https://github.com/hearth-auth/hearth/releases/download/v1.6.10/hearth-linux-amd64"

cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/hearth-auth/hearth/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
```
EOF

# run_case <name> <expected-exit> <readme> <guide> [expected-substring]
run_case() {
    local name="$1" want="$2" readme="$3" guide="$4" expect="${5:-}" out rc
    out="$(README="$readme" GUIDE="$guide" RELEASE_WORKFLOW="${TMP}/release.yml" \
        bash "$CHECK" 2>&1)"
    rc=$?
    if [[ "$rc" != "$want" ]]; then
        fail "${name}: exit ${rc}, want ${want}"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    if [[ -n "$expect" ]] && ! printf '%s\n' "$out" | grep -qF "$expect"; then
        fail "${name}: output does not mention '${expect}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    pass "$name"
}

echo "== the fixed docs pass =="
run_case "manifest verified before use, no unexecutable command" \
    0 "${TMP}/readme-good.md" "${TMP}/guide-good.md" "OK:"

echo "== the pre-fix docs fail (the defects) =="

cat > "${TMP}/guide-triangulate.md" <<'EOF'
## Inspect the transparency log entry

```bash
cosign triangulate --type=blob "${ARTIFACT}"
```
EOF
run_case "the guide tells the reader to run cosign triangulate on a blob" \
    1 "${TMP}/readme-good.md" "${TMP}/guide-triangulate.md" "cosign triangulate"

cat > "${TMP}/guide-brew.md" <<'EOF'
## Prerequisites

```bash
brew install slsa-verifier
```
EOF
run_case "the guide tells the reader to brew install slsa-verifier" \
    1 "${TMP}/readme-good.md" "${TMP}/guide-brew.md" "no Homebrew formula"

cat > "${TMP}/readme-forgeable.md" <<'EOF'
# Hearth

```bash
curl -LO "https://github.com/hearth-auth/hearth/releases/download/v1.6.10/hearth-linux-amd64"
curl -LO https://github.com/hearth-auth/hearth/releases/download/v1.6.10/SHA256SUMS

# Verify the checksum
sha256sum -c SHA256SUMS --ignore-missing
```
EOF
run_case "the README checks a binary against an unverified manifest" \
    1 "${TMP}/readme-forgeable.md" "${TMP}/guide-good.md" "without verifying SHA256SUMS"

cat > "${TMP}/readme-windows-forgeable.md" <<'EOF'
# Hearth

```powershell
Invoke-WebRequest `
  -Uri "https://github.com/hearth-auth/hearth/releases/download/v1.6.10/hearth-windows-amd64.exe" `
  -OutFile hearth-windows-amd64.exe

$actual = (Get-FileHash hearth-windows-amd64.exe -Algorithm SHA256).Hash.ToLower()
```
EOF
run_case "the Windows block checks against an unverified manifest too" \
    1 "${TMP}/readme-windows-forgeable.md" "${TMP}/guide-good.md" "Windows install block"

echo "== a verification that pins nothing is not a verification =="

sed 's/--certificate-oidc-issuer https:\/\/token.actions.githubusercontent.com \\//' \
    "${TMP}/readme-good.md" > "${TMP}/readme-no-issuer.md"
run_case "cosign verify-blob without a pinned OIDC issuer" \
    1 "${TMP}/readme-no-issuer.md" "${TMP}/guide-good.md" "certificate-oidc-issuer"

sed "s|--certificate-identity-regexp '^https://github\\\\.com/hearth-auth/hearth/.\\*\$' \\\\||" \
    "${TMP}/readme-good.md" > "${TMP}/readme-no-identity.md"
run_case "cosign verify-blob without a pinned workflow identity" \
    1 "${TMP}/readme-no-identity.md" "${TMP}/guide-good.md" "certificate-identity-regexp"

cat > "${TMP}/readme-wrong-order.md" <<'EOF'
# Hearth

```bash
curl -LO "https://github.com/hearth-auth/hearth/releases/download/v1.6.10/hearth-linux-amd64"

sha256sum -c SHA256SUMS --ignore-missing

cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/hearth-auth/hearth/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```
EOF
run_case "the README compares before it verifies" \
    1 "${TMP}/readme-wrong-order.md" "${TMP}/guide-good.md" "before verifying it"

echo "== a documented asset the release never uploads is refused =="
cat > "${TMP}/release-missing.yml" <<'EOF'
          gh release create "$TAG" \
            --draft \
            dist/hearth-linux-amd64 \
            dist/SHA256SUMS

          echo done
EOF
out="$(README="${TMP}/readme-good.md" GUIDE="${TMP}/guide-good.md" \
    RELEASE_WORKFLOW="${TMP}/release-missing.yml" bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "1" ]] && printf '%s\n' "$out" | grep -q "never uploads"; then
    pass "a missing SHA256SUMS.sig is caught"
else
    fail "a missing release asset was not caught: exit ${rc}"
    printf '%s\n' "$out" | sed 's/^/         /'
fi

echo "== the real repository passes =="
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    pass "the checked-in README, guide and release workflow"
else
    fail "the checked-in docs do not pass"
    printf '%s\n' "$out" | sed 's/^/         /'
fi

echo
if [[ "$failures" -eq 0 ]]; then
    echo "check-release-verification-docs: all checks passed"
    exit 0
fi
echo "check-release-verification-docs: ${failures} check(s) failed"
exit 1
