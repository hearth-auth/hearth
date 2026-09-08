#!/usr/bin/env bash
# scripts/tests/summarize-nextest.test.sh — tests for
# scripts/summarize-nextest.sh (audit 2026-08-28 §4.8#6, §4.12#9).
#
# The parser is the deliverable, so the suite must prove the OLD parser is red
# on the ANSI fixture — not just that the new one is green, which any `echo`
# stub would also satisfy.
#
# The defect: `grep -oE '[0-9]+ tests run: .*'` run over nextest's coloured
# output never matches, because an escape sequence sits between the digits and
# " tests run". The fallback then told the release engineer the suite did not
# complete, when it had completed with four named failures.
#
# Every fixture below is a byte-for-byte reproduction of real `cargo nextest
# run` output, coloured and plain.
#
# Usage: bash scripts/tests/summarize-nextest.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUMMARIZE="${SCRIPT_DIR}/summarize-nextest.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
E="$(printf '\033')"

pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# ── Fixtures ──────────────────────────────────────────────────────────────

# A completed suite: 6 tests, 2 passed, 4 failed, 1 skipped — coloured exactly
# as nextest emits it when CARGO_TERM_COLOR is inherited from a prior step.
cat > "${TMP}/coloured.log" <<EOF
    Starting ${E}[1m6${E}[0m tests across ${E}[1m1${E}[0m binary (1 test skipped)
${E}[31;1m        FAIL${E}[0m [   0.004s] (2/6) ${E}[35;1mnxfix${E}[0m ${E}[36mtests${E}[0m${E}[36m::${E}[0m${E}[34;1mfail_delta${E}[0m
${E}[31;1m        FAIL${E}[0m [   0.004s] (3/6) ${E}[35;1mnxfix${E}[0m ${E}[36mtests${E}[0m${E}[36m::${E}[0m${E}[34;1mfail_beta${E}[0m
${E}[32;1m        PASS${E}[0m [   0.004s] (5/6) ${E}[35;1mnxfix${E}[0m ${E}[36mtests${E}[0m${E}[36m::${E}[0m${E}[34;1mok_one${E}[0m
────────────
${E}[31;1m     Summary${E}[0m [   0.005s] ${E}[1m6${E}[0m tests run: ${E}[1m2${E}[0m ${E}[32;1mpassed${E}[0m, ${E}[1m4${E}[0m ${E}[31;1mfailed${E}[0m, ${E}[1m1${E}[0m ${E}[33;1mskipped${E}[0m
${E}[31;1m        FAIL${E}[0m [   0.004s] (2/6) ${E}[35;1mnxfix${E}[0m ${E}[36mtests${E}[0m${E}[36m::${E}[0m${E}[34;1mfail_delta${E}[0m
${E}[31;1m        FAIL${E}[0m [   0.004s] (3/6) ${E}[35;1mnxfix${E}[0m ${E}[36mtests${E}[0m${E}[36m::${E}[0m${E}[34;1mfail_beta${E}[0m
${E}[31;1m        FAIL${E}[0m [   0.004s] (4/6) ${E}[35;1mnxfix${E}[0m ${E}[36mtests${E}[0m${E}[36m::${E}[0m${E}[34;1mfail_alpha${E}[0m
${E}[31;1m        FAIL${E}[0m [   0.004s] (6/6) ${E}[35;1mnxfix${E}[0m ${E}[36mtests${E}[0m${E}[36m::${E}[0m${E}[34;1mfail_gamma${E}[0m
${E}[31;1merror${E}[0m: test run failed
EOF

# The same run with --color never.
cat > "${TMP}/plain.log" <<'EOF'
    Starting 6 tests across 1 binary (1 test skipped)
        FAIL [   0.004s] (2/6) nxfix tests::fail_delta
        PASS [   0.004s] (5/6) nxfix tests::ok_one
────────────
     Summary [   0.005s] 6 tests run: 2 passed, 4 failed, 1 skipped
        FAIL [   0.004s] (2/6) nxfix tests::fail_delta
        FAIL [   0.004s] (3/6) nxfix tests::fail_beta
        FAIL [   0.004s] (4/6) nxfix tests::fail_alpha
        FAIL [   0.004s] (6/6) nxfix tests::fail_gamma
error: test run failed
EOF

# A wholly green run: no "failed" segment at all.
cat > "${TMP}/green.log" <<'EOF'
    Starting 6 tests across 1 binary (1 test skipped)
        PASS [   0.004s] (1/6) nxfix tests::ok_one
     Summary [   0.005s] 6 tests run: 6 passed, 1 skipped
EOF

# A suite killed mid-run: PASS lines, no Summary line. This one really did not
# complete, and the script must still say so.
cat > "${TMP}/truncated.log" <<'EOF'
    Starting 846 tests across 61 binaries
        PASS [   0.004s] (1/846) hearth tests::ok_one
Error: The operation was canceled.
EOF

# A truncated run whose captured test stdout contains a summary-shaped line.
# The verdict must come from nextest, never from a test's own output.
cat > "${TMP}/spoofed.log" <<'EOF'
    Starting 846 tests across 61 binaries
--- stdout ---
846 tests run: 846 passed, 0 failed, 0 skipped
Error: The operation was canceled.
EOF

# Non-FAIL failure statuses, and a retried test.
cat > "${TMP}/statuses.log" <<'EOF'
     Summary [   0.005s] 4 tests run: 1 passed, 3 failed, 0 skipped
       ABORT [   0.004s] (1/4) hearth storage::reversed_scan
     SIGSEGV [   0.004s] (2/4) hearth saml::nameid_truncate
     TRY 2 FAIL [   0.004s] (3/4) hearth flaky::sometimes
EOF

# ── Assertions ────────────────────────────────────────────────────────────

# expect_line <name> <log> <expected-exit> <expected-stdout>
expect_line() {
    local name="$1" log="$2" want_rc="$3" want="$4" got rc
    got="$(bash "$SUMMARIZE" "$log" --line 2>&1)"
    rc=$?
    if [[ "$rc" != "$want_rc" ]]; then
        fail "${name}: exit ${rc}, want ${want_rc} (output: ${got})"
    elif [[ "$got" != "$want" ]]; then
        fail "${name}: got '${got}', want '${want}'"
    else
        pass "$name"
    fi
}

# expect_failures <name> <log> <expected-stdout>
expect_failures() {
    local name="$1" log="$2" want="$3" got
    got="$(bash "$SUMMARIZE" "$log" --failures 2>&1)"
    if [[ "$got" != "$want" ]]; then
        fail "${name}: got '${got}', want '${want}'"
    else
        pass "$name"
    fi
}

echo "== The pre-fix parser is red on the coloured log (the defect) =="
old_parser="$(grep -oE '[0-9]+ tests run: .*' "${TMP}/coloured.log" | tail -1)"
if [[ -n "$old_parser" ]]; then
    fail "the inline grep matched coloured output; this fixture no longer reproduces §4.8#6"
else
    pass "the inline grep finds nothing in coloured output — the reported defect"
fi

echo "== --line =="
expect_line "coloured 4-failure suite reports as completed" \
    "${TMP}/coloured.log" 0 "6 tests run: 2 passed, 4 failed, 1 skipped"
expect_line "plain 4-failure suite reports as completed" \
    "${TMP}/plain.log" 0 "6 tests run: 2 passed, 4 failed, 1 skipped"
expect_line "green suite reports as completed" \
    "${TMP}/green.log" 0 "6 tests run: 6 passed, 1 skipped"
expect_line "a genuinely truncated suite is reported as incomplete" \
    "${TMP}/truncated.log" 1 "suite did not complete (no nextest summary line in ${TMP}/truncated.log)"
expect_line "a test's own stdout cannot supply the verdict" \
    "${TMP}/spoofed.log" 1 "suite did not complete (no nextest summary line in ${TMP}/spoofed.log)"
expect_line "a missing log is reported as incomplete" \
    "${TMP}/absent.log" 1 "suite did not complete (no log at ${TMP}/absent.log)"

echo "== --failures =="
expect_failures "coloured log names all four failures once each" \
    "${TMP}/coloured.log" \
    "nxfix tests::fail_delta
nxfix tests::fail_beta
nxfix tests::fail_alpha
nxfix tests::fail_gamma"
expect_failures "plain log names all four failures once each" \
    "${TMP}/plain.log" \
    "nxfix tests::fail_delta
nxfix tests::fail_beta
nxfix tests::fail_alpha
nxfix tests::fail_gamma"
expect_failures "a green log names nothing" "${TMP}/green.log" ""
expect_failures "a missing log names nothing" "${TMP}/absent.log" ""
expect_failures "ABORT, SIGSEGV and a retried FAIL are named" \
    "${TMP}/statuses.log" \
    "hearth storage::reversed_scan
hearth saml::nameid_truncate
hearth flaky::sometimes"

echo "== the named-failure list is capped =="
capped="$(MAX_NAMED_FAILURES=2 bash "$SUMMARIZE" "${TMP}/plain.log" --failures)"
if [[ "$capped" != "nxfix tests::fail_delta
nxfix tests::fail_beta
... and 2 more" ]]; then
    fail "cap: got '${capped}'"
else
    pass "cap: two names plus an overflow count"
fi

echo
if [[ "$failures" -eq 0 ]]; then
    echo "summarize-nextest: all checks passed"
    exit 0
fi
echo "summarize-nextest: ${failures} check(s) failed"
exit 1
