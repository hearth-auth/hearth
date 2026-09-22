#!/usr/bin/env bash
# scripts/tests/check-branch-protection.test.sh — tests for check-branch-protection.sh.
#
# The guard exists to stop audit finding §4.8#3 recurring, so it must be shown
# to FAIL on the exact shape the audit found: an always-on admin bypass over a
# single required context. Case 2 is that shape, verbatim from the ruleset as
# it stood on 2026-09-06 before the fix.
#
# Usage: bash scripts/tests/check-branch-protection.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-branch-protection.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0

# run_case <name> <expected-exit> <rulesets-json> [expected-substring]
run_case() {
    local name="$1" want="$2" json="$3" expect="${4:-}"
    local fixture="$TMP/case-$((RANDOM))-$$.json"
    printf '%s\n' "$json" > "$fixture"
    local out got=0
    out="$(RULESETS_JSON_FILE="$fixture" bash "$CHECK" 2>&1)" || got=$?
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

GOOD='[{
  "name": "Protect main", "target": "branch", "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": false,
      "required_status_checks": [{"context": "required-summary"}]}}
  ],
  "bypass_actors": []
}]'

# 1 — the remediated shape passes.
run_case "clean ruleset passes" 0 "$GOOD" "OK: merges to refs/heads/main are blocked"

# 2 — THE REGRESSION. RepositoryRole 5 with bypass_mode always: the exact
#     configuration that let the audited commit merge 41 minutes before its
#     required check reported failure.
run_case "always-on admin bypass is rejected" 1 \
    "$(jq '.[0].bypass_actors = [
        {"actor_id": null, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request"},
        {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
    ]' <<<"$GOOD")" \
    "bypass_mode 'always'"

# 3 — a pull_request-mode bypass alone is still a merge-before-the-verdict.
run_case "pull_request-mode bypass is rejected" 1 \
    "$(jq '.[0].bypass_actors = [
        {"actor_id": null, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request"}
    ]' <<<"$GOOD")" \
    "bypass_mode 'pull_request'"

# 4 — dropping the required context fails.
run_case "missing required-summary context is rejected" 1 \
    "$(jq '(.[0].rules[] | select(.type == "required_status_checks")
        | .parameters.required_status_checks) = [{"context": "some-other-check"}]' <<<"$GOOD")" \
    "requires the context 'required-summary'"

# 5 — dropping the required_status_checks rule entirely fails.
run_case "missing status-check rule is rejected" 1 \
    "$(jq '.[0].rules |= map(select(.type != "required_status_checks"))' <<<"$GOOD")" \
    "requires the context 'required-summary'"

# 6 — dropping the pull_request rule fails: direct pushes meet no check.
run_case "missing pull_request rule is rejected" 1 \
    "$(jq '.[0].rules |= map(select(.type != "pull_request"))' <<<"$GOOD")" \
    "carries a pull_request rule"

# 7 — a disabled ruleset guards nothing.
run_case "disabled enforcement is rejected" 1 \
    "$(jq '.[0].enforcement = "disabled"' <<<"$GOOD")" \
    "no active ruleset targets refs/heads/main"

# 8 — no ruleset covering main at all.
run_case "empty ruleset list is rejected" 1 "[]" \
    "no active ruleset targets refs/heads/main"

# 9 — a ruleset on another ref does not satisfy the check for main.
run_case "ruleset on another ref is rejected" 1 \
    "$(jq '.[0].conditions.ref_name.include = ["refs/heads/release"]' <<<"$GOOD")" \
    "no active ruleset targets refs/heads/main"

# 10 — ~DEFAULT_BRANCH is accepted as covering main.
run_case "~DEFAULT_BRANCH alias passes" 0 \
    "$(jq '.[0].conditions.ref_name.include = ["~DEFAULT_BRANCH"]' <<<"$GOOD")" \
    "OK: merges to refs/heads/main are blocked"

# 11 — a garbage payload is a failure, not a pass.
run_case "non-array payload is rejected" 1 '{"not": "an array"}' \
    "not a JSON array"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "OK: all check-branch-protection.sh cases passed."
exit 0
