#!/usr/bin/env bash
# scripts/tests/mutation-spot-check.test.sh — tests for
# scripts/mutation-spot-check.sh (production-readiness task 24.3 / 24.4).
#
# The runner's whole job is to answer "can this guard's test go red?". A runner
# that answers "yes" unconditionally is worse than none, so every branch of its
# verdict is exercised here against a fixture tree and a stub test runner. No
# cargo build happens; the stub decides pass/fail from the fixture's contents,
# which is exactly what a real test does.
#
#   case 1  a guard whose test notices the mutation           → exit 0
#   case 2  a guard whose test does NOT notice                → exit 1
#   case 3  THE 24.4 CASE: the test is already red at HEAD    → exit 1
#   case 4  the mutation does not compile                     → exit 1
#   case 5  --check rejects a `find` string that is absent
#   case 6  --check rejects a `find` string that is not unique
#   case 7  --check rejects a test name that exists nowhere
#   case 8  every failing run still restores the file byte-identically
#
# Usage: bash scripts/tests/mutation-spot-check.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${SCRIPT_DIR}/mutation-spot-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

# The guarded "source file" the fixture manifest mutates. `GUARD_ACTIVE` stands
# in for the security check; removing it is the mutation.
# `verify(token)` appears TWICE on purpose: case 6 needs a non-unique anchor to
# prove the runner refuses one rather than mutating an unreviewed call site.
GUARDED_SRC='fn admit(token: &str) -> bool {
    // GUARD_ACTIVE
    verify(token)
}

fn admit_legacy(token: &str) -> bool {
    verify(token)
}

#[test]
fn fixture_guard_test() {
    assert!(!admit("forged"));
}
'

# build_fixture <dir> <manifest-body>
build_fixture() {
    local dir="$1" manifest="$2"
    mkdir -p "${dir}/scripts" "${dir}/ci" "${dir}/src" "${dir}/tests" "${dir}/simulation"
    cp "$RUNNER" "${dir}/scripts/mutation-spot-check.sh"
    printf '%s' "$GUARDED_SRC" > "${dir}/src/guarded.rs"
    printf '%s' "$manifest"    > "${dir}/ci/mutations.toml"

    # Stub test runner. $FAKE_MODE selects the behaviour under test.
    cat > "${dir}/fake-nextest" <<'STUB'
#!/usr/bin/env bash
src="${FAKE_SRC:?}"
mode="${FAKE_MODE:-guard}"
case "$mode" in
  always_pass)
    echo "    Starting 1 test across 1 binary"
    echo "        PASS [   0.001s] fixture fixture_guard_test"
    exit 0 ;;
  always_fail)
    echo "    Starting 1 test across 1 binary"
    echo "        FAIL [   0.001s] fixture fixture_guard_test"
    exit 100 ;;
  buildfail)
    if grep -q 'GUARD_ACTIVE' "$src"; then
      echo "    Starting 1 test across 1 binary"
      echo "        PASS [   0.001s] fixture fixture_guard_test"
      exit 0
    fi
    echo "error[E0425]: cannot find value \`nope\` in this scope"
    echo "error: could not compile \`fixture\` (lib test) due to 1 previous error"
    exit 101 ;;
  *)
    # The honest case: the test passes while the guard is present and fails
    # when it has been removed.
    echo "    Starting 1 test across 1 binary"
    if grep -q 'GUARD_ACTIVE' "$src"; then
      echo "        PASS [   0.001s] fixture fixture_guard_test"
      exit 0
    fi
    echo "        FAIL [   0.001s] fixture fixture_guard_test"
    exit 100 ;;
esac
STUB
    chmod +x "${dir}/fake-nextest"
}

GOOD_MANIFEST='[[mutation]]
id = "fixture-guard"
file = "src/guarded.rs"
test = "fixture_guard_test"
cargo_args = ""
why = "the fixture guard"
find = """
    // GUARD_ACTIVE
"""
replace = """
    // guard removed
"""
'

# run_case <name> <expected-exit> <fake-mode> <manifest> [args...] -- [expected]
run_case() {
    local name="$1" want="$2" mode="$3" manifest="$4" expect="$5"
    shift 5
    case_n=$((case_n + 1))
    local dir="${TMP}/case-${case_n}"
    build_fixture "$dir" "$manifest"

    local before after out got=0
    before="$(sha256sum "${dir}/src/guarded.rs" | cut -d' ' -f1)"
    out="$(cd "$dir" && FAKE_MODE="$mode" FAKE_SRC="${dir}/src/guarded.rs" \
        CARGO_NEXTEST="${dir}/fake-nextest" bash scripts/mutation-spot-check.sh "$@" 2>&1)" || got=$?
    after="$(sha256sum "${dir}/src/guarded.rs" | cut -d' ' -f1)"

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
    # case 8, applied to EVERY case: the tree must come back byte-identical
    # whichever branch the runner took.
    if [[ "$before" != "$after" ]]; then
        echo "FAIL: ${name} — src/guarded.rs was not restored byte-identically"
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${name}"
}

# 1 — the honest case: the guard's test notices its removal.
run_case "a guarded check proves red under mutation" 0 guard "$GOOD_MANIFEST" \
    "every guard in the manifest can go red"

# 2 — the finding the instrument exists to make: the check can be deleted and
#     nothing notices.
run_case "an unguarded check is reported, not passed" 1 always_pass "$GOOD_MANIFEST" \
    "STILL PASSES"

# 3 — THE TASK 24.4 CASE. A regression test that is red before the mutation
#     proves nothing by being red after it. The runner must refuse it by name
#     rather than count it as proof.
run_case "a test that is red at HEAD is refused, not counted" 1 always_fail "$GOOD_MANIFEST" \
    "RED AT HEAD"

# 4 — a mutation that does not build exits non-zero for the wrong reason. That
#     is the vacuous-assert class, and it must not read as proof.
run_case "a mutation that does not compile is not proof" 1 buildfail "$GOOD_MANIFEST" \
    "does not compile"

# 5 — --check: the anchor is gone (the source moved on under the manifest).
run_case "--check rejects an absent find string" 1 guard \
'[[mutation]]
id = "fixture-guard"
file = "src/guarded.rs"
test = "fixture_guard_test"
find = """
    // NOT_IN_THE_FILE
"""
replace = """
    // x
"""
' \
    "occurs 0 time(s)" --check

# 6 — --check: two occurrences means the runner would mutate a call site nobody
#     reviewed.
run_case "--check rejects a non-unique find string" 1 guard \
'[[mutation]]
id = "fixture-guard"
file = "src/guarded.rs"
test = "fixture_guard_test"
find = """
    verify(token)
"""
replace = """
    true
"""
' \
    "occurs" --check

# 7 — --check: a renamed test would silently select nothing.
run_case "--check rejects a test name that exists nowhere" 1 guard \
'[[mutation]]
id = "fixture-guard"
file = "src/guarded.rs"
test = "a_test_that_was_renamed_away"
find = """
    // GUARD_ACTIVE
"""
replace = """
    // gone
"""
' \
    "no test function named" --check

echo ""
if [[ $failures -gt 0 ]]; then
    echo "✗ mutation-spot-check self-test: ${failures} case(s) failed"
    exit 1
fi
echo "✓ mutation-spot-check self-test: ${case_n} cases passed (every fixture restored byte-identically)"
exit 0
