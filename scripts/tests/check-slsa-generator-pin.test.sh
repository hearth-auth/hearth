#!/usr/bin/env bash
# scripts/tests/check-slsa-generator-pin.test.sh — tests for
# scripts/check-slsa-generator-pin.sh (audit 2026-08-28 §4.8#13).
#
# The guard is the deliverable, so it needs a test that proves it FAILS when the
# upstream tag moves — not just that it passes today, which an `exit 0` stub
# would also satisfy.
#
# The defect: slsa-framework/slsa-github-generator is referenced by the mutable
# tag `@v2.1.0` while holding `contents: write` + `id-token: write`. It cannot be
# referenced by SHA — upstream requires a tag — so the pin lives out of band in
# .github/slsa-generator.pin and this guard enforces it.
#
# Every case here uses RESOLVED_SHA, so the suite needs no network.
#
# Usage: bash scripts/tests/check-slsa-generator-pin.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-slsa-generator-pin.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

GOOD_SHA="f7dd8c54c2067bafc12ca7a55595d5ee9b75204a"
MOVED_SHA="0123456789abcdef0123456789abcdef01234567"

cat > "${TMP}/pin.good" <<EOF
# format: <tag> <commit-sha>
v2.1.0 ${GOOD_SHA}
EOF

cat > "${TMP}/release.good.yml" <<'EOF'
  provenance:
    permissions:
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
EOF

# run_case <name> <expected-exit> <pin> <workflow> <resolved> [expected-substring]
run_case() {
    local name="$1" want="$2" pin="$3" wf="$4" resolved="$5" expect="${6:-}" out rc
    out="$(PIN_FILE="$pin" RELEASE_WORKFLOW="$wf" RESOLVED_SHA="$resolved" \
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

echo "== the reviewed commit passes =="
run_case "tag resolves to the pinned commit" \
    0 "${TMP}/pin.good" "${TMP}/release.good.yml" "$GOOD_SHA" "OK:"

echo "== a moved upstream tag fails (the defect this guard exists for) =="
run_case "tag re-pointed at another commit" \
    1 "${TMP}/pin.good" "${TMP}/release.good.yml" "$MOVED_SHA" "The upstream tag moved"

echo "== the workflow and the pin must agree =="
cat > "${TMP}/release.other-tag.yml" <<'EOF'
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.2.0
EOF
run_case "workflow bumped to a tag the pin does not cover" \
    1 "${TMP}/pin.good" "${TMP}/release.other-tag.yml" "$GOOD_SHA" "Update both in the same commit"

cat > "${TMP}/release.none.yml" <<'EOF'
  provenance:
    uses: ./.github/workflows/local.yml
EOF
run_case "the reference disappeared while the pin remains" \
    1 "${TMP}/pin.good" "${TMP}/release.none.yml" "$GOOD_SHA" "no longer references"

echo "== a malformed pin is refused =="
printf '# only comments\n' > "${TMP}/pin.empty"
run_case "a pin file with no tag/sha line" \
    1 "${TMP}/pin.empty" "${TMP}/release.good.yml" "$GOOD_SHA" "no '<tag> <commit-sha>' line"

printf 'v2.1.0 not-a-sha\n' > "${TMP}/pin.badsha"
run_case "a pin recording something that is not a commit SHA" \
    1 "${TMP}/pin.badsha" "${TMP}/release.good.yml" "not-a-sha" "not a 40-character commit SHA"

echo "== a failed lookup must not pass =="
out="$(PIN_FILE="${TMP}/pin.good" RELEASE_WORKFLOW="${TMP}/release.good.yml" \
    UPSTREAM="file://${TMP}/definitely-not-a-repo" bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "1" ]] && printf '%s\n' "$out" | grep -q 'must not pass on a failed lookup'; then
    pass "an unresolvable upstream fails closed"
else
    fail "an unresolvable upstream: exit ${rc}"
    printf '%s\n' "$out" | sed 's/^/         /'
fi

echo "== the checked-in pin matches the checked-in workflow =="
out="$(cd "$REPO_ROOT" && RESOLVED_SHA="$(awk '!/^#/ && NF {print $2; exit}' .github/slsa-generator.pin)" \
    bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    pass "release.yml's tag and .github/slsa-generator.pin agree"
else
    fail "the checked-in pin does not match release.yml"
    printf '%s\n' "$out" | sed 's/^/         /'
fi

echo
if [[ "$failures" -eq 0 ]]; then
    echo "check-slsa-generator-pin: all checks passed"
    exit 0
fi
echo "check-slsa-generator-pin: ${failures} check(s) failed"
exit 1
