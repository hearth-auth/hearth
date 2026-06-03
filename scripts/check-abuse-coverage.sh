#!/usr/bin/env bash
# scripts/check-abuse-coverage.sh — §3.41 adversarial test-quality gate.
#
# Fails if any A-N row in docs/plans/HEA-1114-abuse-prevention.md lacks at
# least one negative-scenario test in tests/abuse_*.rs.
#
# Each test file must contain the row identifier (e.g. "A-2") somewhere in its
# source — typically in a test function name (fn a2_rate_limit_exceeded) or a
# comment (// A-2: ...).
#
# Rollback: set SKIP_ABUSE_COVERAGE_CHECK=1 in the environment or as a GitHub
# Actions secret/env var. The flag is logged visibly in CI so bypass is
# observable. Document the reason and tracking issue when activating it.
#
# Usage:
#   ./scripts/check-abuse-coverage.sh                         # default paths
#   PLAN_DOC=path/to/plan.md ./scripts/check-abuse-coverage.sh
#   TEST_GLOB='tests/abuse_*.rs' ./scripts/check-abuse-coverage.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'
  BLD=$'\033[1m';    RST=$'\033[0m'
else
  RED=''; GRN=''; YEL=''; BLD=''; RST=''
fi

PLAN_DOC="${PLAN_DOC:-docs/plans/HEA-1114-abuse-prevention.md}"
TEST_GLOB="${TEST_GLOB:-tests/abuse_*.rs}"

# ── Escape hatch ──────────────────────────────────────────────────────────────
if [[ "${SKIP_ABUSE_COVERAGE_CHECK:-0}" == "1" ]]; then
  printf "%s⚠  SKIP_ABUSE_COVERAGE_CHECK=1 — §3.41 abuse coverage gate disabled.%s\n" "$YEL" "$RST" >&2
  printf "   Document the reason and tracking issue in the enabling PR.\n" >&2
  exit 0
fi

# ── Validate inputs ───────────────────────────────────────────────────────────
if [[ ! -f "$PLAN_DOC" ]]; then
  printf "%s%s✗ Plan doc not found: %s%s\n" "$RED" "$BLD" "$PLAN_DOC" "$RST" >&2
  printf "  Expected path: docs/plans/HEA-1114-abuse-prevention.md\n" >&2
  printf "  This file must exist and contain an A-N row table (see HEA-1114).\n" >&2
  exit 1
fi

# ── Extract A-N identifiers ───────────────────────────────────────────────────
# Match whole-word occurrences of A-\d+ (e.g. A-2, A-15, A-100).
# Word-boundary \b prevents partial matches like RA-2 or A-21 matching A-2.
mapfile -t IDENTIFIERS < <(grep -oP '\bA-\d+\b' "$PLAN_DOC" | sort -t- -k2 -n | uniq)

if [[ ${#IDENTIFIERS[@]} -eq 0 ]]; then
  printf "%s%s✗ No A-N identifiers found in %s%s\n" "$RED" "$BLD" "$PLAN_DOC" "$RST" >&2
  printf "  The plan doc must contain rows with identifiers matching A-<number>.\n" >&2
  exit 1
fi

printf "Checking %d A-N row(s) against %s ...\n" "${#IDENTIFIERS[@]}" "$TEST_GLOB"

# ── Collect test files ────────────────────────────────────────────────────────
# Expand the glob; fail clearly if no test files exist at all.
# shellcheck disable=SC2206  # intentional word-splitting of glob
TEST_FILES=( $TEST_GLOB )
if [[ ${#TEST_FILES[@]} -eq 0 || ! -f "${TEST_FILES[0]:-}" ]]; then
  printf "\n%s%s✗ No test files found matching: %s%s\n" "$RED" "$BLD" "$TEST_GLOB" "$RST" >&2
  printf "\n  Missing adversarial tests for ALL rows:\n" >&2
  printf "    %s\n" "${IDENTIFIERS[@]}" >&2
  printf "\n  Add tests in tests/abuse_*.rs that reference each identifier.\n" >&2
  printf "  See docs/plans/HEA-1114-abuse-prevention.md for the full row list.\n" >&2
  exit 1
fi

# ── Check coverage per row ────────────────────────────────────────────────────
FAILURES=()
for id in "${IDENTIFIERS[@]}"; do
  # -q: suppress output  -l: print filename (ensures grep stops at first match)
  if ! grep -qlP "\b${id}\b" "${TEST_FILES[@]}" 2>/dev/null; then
    FAILURES+=("$id")
  fi
done

# ── Report ────────────────────────────────────────────────────────────────────
if [[ ${#FAILURES[@]} -gt 0 ]]; then
  printf "\n%s%s✗ §3.41 abuse coverage gate FAILED%s\n" "$RED" "$BLD" "$RST" >&2
  printf "\n  The following A-N row(s) have no adversarial test in tests/abuse_*.rs:\n\n" >&2
  for id in "${FAILURES[@]}"; do
    printf "    %s\n" "$id" >&2
  done
  printf "\n  Each row must be referenced by its identifier in at least one test.\n" >&2
  printf "  Example: a test function named \`fn %s_rate_limit_exceeded()\`\n" \
    "$(echo "${FAILURES[0]}" | tr '[:upper:]-' '[:lower:]_')" >&2
  printf "  or a comment \`// %s: <description>\`.\n" "${FAILURES[0]}" >&2
  printf "\n  Full row table: %s\n" "$PLAN_DOC" >&2
  printf "  To bypass temporarily: SKIP_ABUSE_COVERAGE_CHECK=1 (document the reason).\n" >&2
  exit 1
fi

printf "\n%s✓ §3.41 gate: all %d A-N row(s) have at least one adversarial test.%s\n" \
  "$GRN" "${#IDENTIFIERS[@]}" "$RST"
