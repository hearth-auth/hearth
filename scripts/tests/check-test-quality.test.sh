#!/usr/bin/env bash
# scripts/tests/check-test-quality.test.sh — tests for check I of
# scripts/check-test-quality.sh (#[ignore] must name its tracking work).
#
# Added under production-readiness task 24.4. `make test-quality` is a merge
# gate: Makefile's `check` target runs it, and ci.yml's `quality` job — which
# is in `required-summary`'s `needs:` — runs it as its own step. It was RED at
# HEAD on two findings, one of them a false positive: the rule grepped for the
# literal text `#[ignore` anywhere on a line, so a prose comment in
# src/rbac/resolution_cache.rs saying a test must NOT be `#[ignore]`-d reported
# itself as an untracked ignore. A gate that cries wolf gets switched off, and a
# gate switched off is a fail-open merge gate.
#
#   case 1  an untracked #[ignore] is still rejected (the rule's whole point)
#   case 2  an HEA-#### reference is accepted
#   case 3  an openspec:<change>#<task> reference is accepted
#   case 4  prose that merely mentions #[ignore] is NOT a violation
#   case 5  a continuation line carrying the reference is accepted
#
# Usage: bash scripts/tests/check-test-quality.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-test-quality.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

# run_case <name> <expected-exit> <tests/fixture.rs contents> [expected-substring]
run_case() {
    local name="$1" want="$2" body="$3" expect="${4:-}"
    case_n=$((case_n + 1))
    local dir="${TMP}/case-${case_n}"
    mkdir -p "${dir}/tests"
    printf '%s' "$body" > "${dir}/tests/fixture.rs"

    local out got=0
    out="$(REPO_ROOT="$dir" bash "$CHECK" 2>&1)" || got=$?
    if [[ "$got" -ne "$want" ]]; then
        echo "FAIL: ${name} — expected exit ${want}, got ${got}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    if [[ -n "$expect" && "$out" != *"$expect"* ]]; then
        echo "FAIL: ${name} — output missing expected text: ${expect}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${name}"
}

# 1 — the rule's whole point: an ignore that names no tracking work.
run_case "an untracked #[ignore] is rejected" 1 \
'#[ignore = "flaky on CI"]
#[test]
fn parked() {
    assert_eq!(1, 1);
}
' \
    "without a tracking reference"

# 2 — an HEA-#### reference is the long-standing convention.
run_case "an HEA-#### reference is accepted" 0 \
'#[ignore = "HEA-1114: blocked on the unified AbuseGuard facade"]
#[test]
fn parked() {
    assert_eq!(1, 1);
}
' ""

# 3 — the remediation programme tracks its backlog in OpenSpec, not in issues.
run_case "an openspec task reference is accepted" 0 \
'#[ignore = "openspec:production-readiness-remediation#21.11: acceptance criterion"]
#[test]
fn parked() {
    assert_eq!(1, 1);
}
' ""

# 4 — THE FALSE POSITIVE (src/rbac/resolution_cache.rs:427). Prose about the
#     attribute is not the attribute.
run_case "prose mentioning #[ignore] is not a violation" 0 \
'#[test]
fn loaded() {
    // This must NOT be "fixed" by lowering the iteration count again or by
    // #[ignore]-ing this test: the same pattern is used on hot paths.
    assert_eq!(1, 1);
}
' ""

# 5 — a long reason wraps with a trailing backslash; the reference may sit on
#     any continuation line.
run_case "a reference on a continuation line is accepted" 0 \
'#[ignore = "byte-identity across pre-auth realm shapes is not implemented; \
            openspec:production-readiness-remediation#21.11 tracks it"]
#[test]
fn parked() {
    assert_eq!(1, 1);
}
' ""

echo ""
if [[ $failures -gt 0 ]]; then
    echo "✗ check-test-quality self-test: ${failures} case(s) failed"
    exit 1
fi
echo "✓ check-test-quality self-test: ${case_n} cases passed"
exit 0
