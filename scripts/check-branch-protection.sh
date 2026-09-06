#!/usr/bin/env bash
# scripts/check-branch-protection.sh — the merge gate must be able to say no.
#
# Audit 2026-08-28 finding §4.8#3 (HIGH):
#
#   No CI check blocked the audited commit's merge: one required context, zero
#   reviews, an always-on bypass, and a merge 41 minutes before that context
#   reported failure.
#
# The mechanism was the "Protect main" ruleset granting RepositoryRole 5 (admin)
# `bypass_mode: always`. `gh pr merge --admin` walked past the one required
# check while it was still running. The check reported failure 41 minutes after
# the commit was already on main.
#
# Spec (build-release-integrity): every merge to the default branch SHALL be
# blocked until a required check has reported success on that exact commit, and
# a bypass MUST NOT be always-on.
#
# Four rules, applied to every ACTIVE ruleset that targets refs/heads/main:
#
#   R1  At least one active ruleset targets refs/heads/main at all.
#   R2  A `pull_request` rule exists — changes reach main only through a PR.
#   R3  A `required_status_checks` rule exists and includes the context
#       `required-summary` (the always-reporting aggregate in ci.yml; see
#       scripts/ci-required-checks-migrate.sh for why only that context).
#   R4  The ruleset carrying those rules has NO bypass actors. `always` mode is
#       the audited defect verbatim; `pull_request` mode still offers a
#       "merge without waiting for requirements" button, which is the same
#       merge-before-the-verdict the audit reproduced.
#
# Review count is deliberately NOT asserted. The repo has one human;
# GitHub forbids self-approval, so a required review deadlocks every PR
# (see 2026-08-06 ruleset history). The gate is CI, not a reviewer who
# cannot exist. The emergency escape is editing the ruleset in repository
# settings — an explicit, logged admin action, not a standing button.
#
# Usage:  bash scripts/check-branch-protection.sh
# Env:    GH_TOKEN / GITHUB_TOKEN   auth for the live API fetch
#         RULESETS_JSON_FILE        path to a JSON array of full ruleset
#                                   objects (tests only; skips the API)
#         PROTECTED_REF             ref to assert on (default refs/heads/main)
#         REQUIRED_CONTEXT          context to assert on (default required-summary)

set -uo pipefail

PROTECTED_REF="${PROTECTED_REF:-refs/heads/main}"
REQUIRED_CONTEXT="${REQUIRED_CONTEXT:-required-summary}"

command -v jq >/dev/null || { echo "FAIL: jq is required."; exit 1; }

# ── Obtain the full ruleset objects ──────────────────────────────────────────
# The list endpoint omits rules and bypass_actors, so live mode fetches each
# ruleset by id. An unreachable API is a FAIL, not a skip: a guard that skips
# when it cannot see the ruleset is the fail-open shape the audit condemns.
if [[ -n "${RULESETS_JSON_FILE:-}" ]]; then
    rulesets="$(cat "$RULESETS_JSON_FILE")" || { echo "FAIL: cannot read ${RULESETS_JSON_FILE}"; exit 1; }
else
    command -v gh >/dev/null || { echo "FAIL: gh CLI is required for the live check."; exit 1; }
    repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)}"
    [[ -n "$repo" ]] || { echo "FAIL: cannot determine the repository."; exit 1; }
    ids="$(gh api "repos/${repo}/rulesets" --jq '.[].id' 2>&1)" \
        || { echo "FAIL: cannot list rulesets for ${repo}: ${ids}"; exit 1; }
    rulesets="[]"
    for id in $ids; do
        one="$(gh api "repos/${repo}/rulesets/${id}" 2>&1)" \
            || { echo "FAIL: cannot fetch ruleset ${id}: ${one}"; exit 1; }
        rulesets="$(jq --argjson one "$one" '. + [$one]' <<<"$rulesets")"
    done
fi

jq -e 'type == "array"' <<<"$rulesets" >/dev/null \
    || { echo "FAIL: ruleset payload is not a JSON array."; exit 1; }

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

# Active branch rulesets whose include list covers the protected ref.
# `~DEFAULT_BRANCH` is GitHub's alias for it.
main_rulesets="$(jq --arg ref "$PROTECTED_REF" '[ .[]
    | select(.target == "branch" and .enforcement == "active")
    | select((.conditions.ref_name.include // [])
        | any(. == $ref or . == "~DEFAULT_BRANCH" or . == "~ALL")) ]' <<<"$rulesets")"

count="$(jq 'length' <<<"$main_rulesets")"

# ── R1: the ref is covered at all. ───────────────────────────────────────────
if [[ "$count" -eq 0 ]]; then
    fail "no active ruleset targets ${PROTECTED_REF}." \
        $'\n      Without one, nothing blocks a merge — audit finding §4.8#3.'
fi

# ── R2: changes reach the ref only through a PR. ─────────────────────────────
if [[ "$count" -gt 0 ]] && ! jq -e '[ .[].rules[]? | select(.type == "pull_request") ] | length > 0' \
        <<<"$main_rulesets" >/dev/null; then
    fail "no active ruleset on ${PROTECTED_REF} carries a pull_request rule." \
        $'\n      A direct push never meets a required check.'
fi

# ── R3: the required context is required. ────────────────────────────────────
if [[ "$count" -gt 0 ]] && ! jq -e --arg ctx "$REQUIRED_CONTEXT" '[ .[].rules[]?
        | select(.type == "required_status_checks")
        | .parameters.required_status_checks[]?
        | select(.context == $ctx) ] | length > 0' <<<"$main_rulesets" >/dev/null; then
    fail "no active ruleset on ${PROTECTED_REF} requires the context '${REQUIRED_CONTEXT}'." \
        $'\n      With no required context, a red commit merges clean.'
fi

# ── R4: no bypass actors on any ruleset guarding the ref. ────────────────────
while IFS=$'\t' read -r rname atype amode; do
    [[ -z "$rname" ]] && continue
    fail "ruleset '${rname}' grants ${atype} bypass_mode '${amode}' on ${PROTECTED_REF}." \
        $'\n      A bypass is a merge before the verdict — the audited commit merged' \
        $'\n      41 minutes before its required check reported failure (§4.8#3).' \
        $'\n      Emergency path: edit the ruleset in repository settings, explicitly.'
done < <(jq -r '.[] | .name as $n | .bypass_actors[]?
    | [$n, .actor_type, .bypass_mode] | @tsv' <<<"$main_rulesets")

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} branch-protection violation(s) on ${PROTECTED_REF}."
    echo "See scripts/check-branch-protection.sh for the rules and the audit citation."
    exit 1
fi
echo "OK: merges to ${PROTECTED_REF} are blocked until '${REQUIRED_CONTEXT}' reports success, and no bypass exists."
exit 0
