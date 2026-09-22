#!/usr/bin/env bash
# scripts/mutation-spot-check.sh — a test suite that cannot fail is not a test
# suite.
#
# Production-readiness task 24.3 (audit 2026-08-28 §9 item 3).
#
# The audit's own words:
#
#   "The mutation spot-check (P29). The brief's sharpest instrument — comment
#    out five security-critical checks and see whether anything goes red — has
#    no passed result. We therefore cannot say whether this test suite can
#    fail."
#
# This script is that instrument, mechanised. For every entry in the manifest
# (ci/mutations.toml):
#
#   1. BASELINE  — run the named test against the unmodified tree. It must
#                  PASS. A test that is already red cannot prove anything by
#                  being red again; this phase is also the task-24.4 red-test
#                  gate for exactly the guards named in the manifest.
#   2. MUTATE    — replace `find` with `replace` in `file`. `find` must occur
#                  exactly once or the manifest is refused.
#   3. VERDICT   — run the same test again. It must FAIL, and it must fail as a
#                  TEST FAILURE. A mutation that does not compile exits
#                  non-zero too, and counting that as proof is exactly the
#                  vacuous-assert class this repository bans.
#   4. RESTORE   — copy the byte snapshot taken before step 2 back over the
#                  file and verify its SHA-256 equals the pre-run digest.
#
# Restoration runs from an EXIT trap, so an interrupt, a build failure or a
# `set -e` abort still leaves the working tree byte-identical. The final digest
# comparison is not decoration: it is what makes it safe to run this against a
# tree with uncommitted work in it.
#
# Usage:
#   bash scripts/mutation-spot-check.sh                 # full run, every entry
#   bash scripts/mutation-spot-check.sh --only <id>     # one entry
#   bash scripts/mutation-spot-check.sh --check         # validate manifest only
#   bash scripts/mutation-spot-check.sh --no-baseline   # skip phase 1 (faster,
#                                                       # weaker — CI must not)
#
# Env:
#   MANIFEST       manifest path (default ci/mutations.toml)
#   CARGO_NEXTEST  runner command (default "cargo nextest")
#   PROTOC         required by build.rs; defaults to `which protoc`

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${MANIFEST:-${REPO_ROOT}/ci/mutations.toml}"
CARGO_NEXTEST="${CARGO_NEXTEST:-cargo nextest}"

MODE="run"
ONLY=""
BASELINE=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)       MODE="check" ;;
        --no-baseline) BASELINE=0 ;;
        --only)        ONLY="${2:-}"; shift ;;
        -h|--help)     sed -n '2,50p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)             echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

if [[ -t 1 ]]; then
    RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
    RED=""; GRN=""; YEL=""; BLD=""; RST=""
fi

if [[ ! -f "$MANIFEST" ]]; then
    echo "FAIL: manifest not found: ${MANIFEST}" >&2
    exit 1
fi

TMP="$(mktemp -d)"
SNAPSHOT_DIR="${TMP}/orig"
mkdir -p "$SNAPSHOT_DIR"

# Files we have snapshotted, as "relpath<TAB>sha256<TAB>snapshotfile" lines.
SNAPSHOT_INDEX="${TMP}/snapshots.tsv"
: > "$SNAPSHOT_INDEX"

restore_all() {
    local rc=0 rel digest snap now
    while IFS=$'\t' read -r rel digest snap; do
        [[ -n "$rel" ]] || continue
        cp -p -- "$snap" "${REPO_ROOT}/${rel}"
        now="$(sha256sum "${REPO_ROOT}/${rel}" | cut -d' ' -f1)"
        if [[ "$now" != "$digest" ]]; then
            echo "${RED}FAIL: ${rel} was NOT restored byte-identically" \
                 "(expected ${digest}, got ${now})${RST}" >&2
            rc=1
        fi
    done < "$SNAPSHOT_INDEX"
    return $rc
}

RESTORE_RC=0
cleanup() {
    restore_all || RESTORE_RC=1
    rm -rf "$TMP"
}
trap cleanup EXIT

# ── Manifest parsing ─────────────────────────────────────────────────────────
# tomllib is stdlib from Python 3.11. Fields come back base64-encoded so that
# newlines and quoting in `find`/`replace` survive the shell.
parse_manifest() {
    python3 - "$MANIFEST" <<'PY'
import base64, sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    sys.stderr.write("FAIL: python3 >= 3.11 (tomllib) is required to read the manifest\n")
    sys.exit(1)

with open(sys.argv[1], "rb") as fh:
    doc = tomllib.load(fh)

entries = doc.get("mutation")
if not entries:
    sys.stderr.write("FAIL: manifest declares no [[mutation]] entries\n")
    sys.exit(1)

required = ("id", "file", "test", "find", "replace")
seen = set()
for i, e in enumerate(entries):
    for key in required:
        if not e.get(key):
            sys.stderr.write(f"FAIL: [[mutation]] #{i + 1} is missing `{key}`\n")
            sys.exit(1)
    if e["id"] in seen:
        sys.stderr.write(f"FAIL: duplicate mutation id `{e['id']}`\n")
        sys.exit(1)
    seen.add(e["id"])
    if e["find"] == e["replace"]:
        sys.stderr.write(f"FAIL: `{e['id']}` replaces `find` with itself\n")
        sys.exit(1)
    b64 = lambda s: base64.b64encode(s.encode()).decode()
    # US (0x1f), not TAB: tab is an IFS *whitespace* character, so bash
    # collapses a run of them and an empty `cargo_args` would silently shift
    # every later field by one — the needle would become the replacement.
    print("\x1f".join([
        e["id"], e["file"], e["test"], e.get("cargo_args", ""),
        b64(e["find"]), b64(e["replace"]), b64(e.get("why", "")),
    ]))
PY
}

ENTRIES="${TMP}/entries.tsv"
if ! parse_manifest > "$ENTRIES"; then
    exit 1
fi

# ── Static validation (runs on every PR; builds nothing) ─────────────────────
validate() {
    local failures=0 id file test cargo_args find_b64 replace_b64 _why
    local found_only=0 occurrences
    while IFS=$'\x1f' read -r id file test cargo_args find_b64 replace_b64 _why; do
        [[ -n "$id" ]] || continue
        if [[ -n "$ONLY" && "$id" != "$ONLY" ]]; then continue; fi
        found_only=1

        if [[ ! -f "${REPO_ROOT}/${file}" ]]; then
            echo "${RED}FAIL: ${id}: file not found: ${file}${RST}"
            failures=$((failures + 1))
            continue
        fi

        # `find` must occur EXACTLY ONCE. Two occurrences means the runner
        # would mutate a call site nobody reviewed.
        occurrences="$(
            printf '%s' "$find_b64" | base64 -d > "${TMP}/needle"
            python3 - "${REPO_ROOT}/${file}" "${TMP}/needle" <<'PY'
import sys
hay = open(sys.argv[1], "rb").read()
needle = open(sys.argv[2], "rb").read()
print(hay.count(needle))
PY
        )"
        if [[ "$occurrences" != "1" ]]; then
            echo "${RED}FAIL: ${id}: \`find\` occurs ${occurrences} time(s) in ${file}; it must occur exactly once${RST}"
            failures=$((failures + 1))
            continue
        fi

        # The named test must exist in the tree. A renamed test would otherwise
        # make the entry silently select nothing.
        if ! grep -rqF -- "fn ${test}(" "${REPO_ROOT}/src" "${REPO_ROOT}/tests" \
                "${REPO_ROOT}/simulation" 2>/dev/null; then
            echo "${RED}FAIL: ${id}: no test function named \`${test}\` in src/, tests/ or simulation/${RST}"
            failures=$((failures + 1))
            continue
        fi

        echo "${GRN}ok${RST}   ${id} — ${file} → ${test} ${cargo_args:+(${cargo_args})}"
    done < "$ENTRIES"

    if [[ -n "$ONLY" && "$found_only" -eq 0 ]]; then
        echo "${RED}FAIL: no manifest entry with id \`${ONLY}\`${RST}"
        failures=$((failures + 1))
    fi
    return $failures
}

if ! validate; then
    echo ""
    echo "${RED}${BLD}mutation manifest: INVALID${RST}"
    exit 1
fi

if [[ "$MODE" == "check" ]]; then
    echo ""
    echo "${GRN}${BLD}mutation manifest: valid${RST} (static check only — nothing was built)"
    exit 0
fi

# ── Full run ─────────────────────────────────────────────────────────────────
snapshot_file() {
    local rel="$1" snap digest
    if cut -f1 "$SNAPSHOT_INDEX" | grep -qxF -- "$rel"; then
        return 0
    fi
    snap="${SNAPSHOT_DIR}/$(printf '%s' "$rel" | tr '/' '_')"
    cp -p -- "${REPO_ROOT}/${rel}" "$snap"
    digest="$(sha256sum "${REPO_ROOT}/${rel}" | cut -d' ' -f1)"
    printf '%s\t%s\t%s\n' "$rel" "$digest" "$snap" >> "$SNAPSHOT_INDEX"
}

apply_mutation() {
    local rel="$1" needle="$2" repl="$3"
    python3 - "${REPO_ROOT}/${rel}" "$needle" "$repl" <<'PY'
import sys
path, needle_p, repl_p = sys.argv[1], sys.argv[2], sys.argv[3]
hay = open(path, "rb").read()
needle = open(needle_p, "rb").read()
repl = open(repl_p, "rb").read()
if hay.count(needle) != 1:
    sys.stderr.write("refusing to mutate: `find` is not unique\n")
    sys.exit(1)
open(path, "wb").write(hay.replace(needle, repl, 1))
PY
}

restore_one() {
    local rel="$1" snap
    snap="$(awk -F'\t' -v r="$rel" '$1 == r { print $3 }' "$SNAPSHOT_INDEX")"
    cp -p -- "$snap" "${REPO_ROOT}/${rel}"
}

# Runs one test and classifies the outcome as pass / test-failure / broken.
# Echoes one of: PASS, TESTFAIL, NOTESTS, BUILDFAIL
run_one_test() {
    local test="$1" cargo_args="$2" logfile="$3"
    local rc
    # `test(=name)` matches nextest's FULL test name, which for a unit test is
    # `module::path::tests::name`. Anchor on a `::` boundary instead so the
    # manifest can name the function and nothing else, while still refusing a
    # partial match against a longer name.
    # shellcheck disable=SC2086 # cargo_args is a deliberate word list
    ( cd "$REPO_ROOT" && \
      PROTOC="${PROTOC:-$(command -v protoc)}" \
      $CARGO_NEXTEST run $cargo_args --color never -E "test(/(^|::)${test}\$/)" \
    ) > "$logfile" 2>&1
    rc=$?

    # Order matters. nextest reports "error: no tests to run" on its own stderr,
    # so a bare `^error:` grep would classify an empty selection as a build
    # failure. The presence of a "Starting N tests" line is the only reliable
    # signal that the binary was built AND something ran.
    if grep -qE 'Starting [1-9][0-9]* test' "$logfile"; then
        if [[ $rc -eq 0 ]]; then
            echo PASS
        else
            echo TESTFAIL
        fi
    elif grep -qE 'could not compile|^error\[' "$logfile"; then
        echo BUILDFAIL
    else
        echo NOTESTS
    fi
}

entry_count=0
pass_count=0
declare -a FAILED_IDS=()

echo "${BLD}mutation spot-check${RST} — manifest ${MANIFEST#"${REPO_ROOT}/"}"
echo ""

while IFS=$'\x1f' read -r id file test cargo_args find_b64 replace_b64 why_b64; do
    [[ -n "$id" ]] || continue
    if [[ -n "$ONLY" && "$id" != "$ONLY" ]]; then continue; fi
    entry_count=$((entry_count + 1))

    why="$(printf '%s' "$why_b64" | base64 -d)"
    printf '%s' "$find_b64"    | base64 -d > "${TMP}/needle"
    printf '%s' "$replace_b64" | base64 -d > "${TMP}/repl"

    echo "${BLD}── ${id}${RST}"
    echo "   guard: ${why}"
    echo "   file:  ${file}"
    echo "   test:  ${test}"

    snapshot_file "$file"

    # Phase 1 — baseline.
    if [[ $BASELINE -eq 1 ]]; then
        outcome="$(run_one_test "$test" "$cargo_args" "${TMP}/${id}.baseline.log")"
        case "$outcome" in
            PASS) echo "   ${GRN}baseline: PASS${RST} (the guard's test is green at HEAD)" ;;
            TESTFAIL)
                echo "   ${RED}baseline: RED AT HEAD${RST} — ${test} fails on the unmodified tree."
                echo "   ${RED}A regression test committed red proves nothing. Fix it or remove it.${RST}"
                tail -n 25 "${TMP}/${id}.baseline.log" | sed 's/^/     | /'
                FAILED_IDS+=("${id} (baseline red)")
                echo ""
                continue ;;
            NOTESTS)
                echo "   ${RED}baseline: NO TEST MATCHED${RST} — \`test(=${test})\` selected nothing."
                FAILED_IDS+=("${id} (no test matched)")
                echo ""
                continue ;;
            BUILDFAIL)
                echo "   ${RED}baseline: BUILD FAILED${RST} on the unmodified tree."
                tail -n 25 "${TMP}/${id}.baseline.log" | sed 's/^/     | /'
                FAILED_IDS+=("${id} (baseline build failed)")
                echo ""
                continue ;;
        esac
    fi

    # Phase 2 — mutate.
    if ! apply_mutation "$file" "${TMP}/needle" "${TMP}/repl"; then
        echo "   ${RED}mutation could not be applied${RST}"
        FAILED_IDS+=("${id} (mutation not applied)")
        echo ""
        continue
    fi

    # Phase 3 — verdict.
    outcome="$(run_one_test "$test" "$cargo_args" "${TMP}/${id}.mutated.log")"

    # Phase 4 — restore immediately, before reporting, so a later abort cannot
    # leave a mutated file behind even for a moment longer than necessary.
    restore_one "$file"

    case "$outcome" in
        TESTFAIL)
            echo "   ${GRN}mutated:  FAIL — the guard is guarded${RST}"
            pass_count=$((pass_count + 1)) ;;
        PASS)
            echo "   ${RED}mutated:  STILL PASSES${RST}"
            echo "   ${RED}The check named above can be deleted and ${test} does not notice.${RST}"
            echo "   ${RED}That guard is unguarded — fix the test, not this manifest.${RST}"
            FAILED_IDS+=("${id} (survived the mutation)") ;;
        BUILDFAIL)
            echo "   ${YEL}mutated:  BUILD FAILED${RST} — the mutation does not compile, so the"
            echo "   ${YEL}non-zero exit proves nothing. Rewrite \`replace\` so it builds.${RST}"
            tail -n 25 "${TMP}/${id}.mutated.log" | sed 's/^/     | /'
            FAILED_IDS+=("${id} (mutation did not compile)") ;;
        NOTESTS)
            echo "   ${RED}mutated:  NO TEST MATCHED${RST}"
            FAILED_IDS+=("${id} (no test matched under mutation)") ;;
    esac
    echo ""
done < "$ENTRIES"

# ── Summary ──────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────────────────────────────"
echo "entries run: ${entry_count}   proven: ${pass_count}   failed: ${#FAILED_IDS[@]}"

if [[ ${#FAILED_IDS[@]} -gt 0 ]]; then
    for f in "${FAILED_IDS[@]}"; do
        echo "  ${RED}✗${RST} ${f}"
    done
    echo ""
    echo "${RED}${BLD}mutation spot-check: FAILED${RST}"
    # cleanup() restores and verifies; its result is folded in below.
    trap - EXIT
    cleanup
    exit 1
fi

if [[ $entry_count -eq 0 ]]; then
    echo "${RED}${BLD}mutation spot-check: no entries ran${RST}"
    trap - EXIT
    cleanup
    exit 1
fi

trap - EXIT
cleanup
if [[ $RESTORE_RC -ne 0 ]]; then
    echo "${RED}${BLD}mutation spot-check: every guard was proven, but a source file was"
    echo "not restored byte-identically. Inspect the tree before committing.${RST}"
    exit 1
fi

echo ""
echo "${GRN}${BLD}mutation spot-check: every guard in the manifest can go red${RST}"
echo "every mutated file was restored byte-identically (SHA-256 verified)"
exit 0
