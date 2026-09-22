#!/usr/bin/env bash
# scripts/await-green-commit.sh — wait for a named check to report success on a commit.
#
# Audit 2026-08-28 blockers B2 (§4.8#1) and B6 (§4.12#1). B6 is the sharper one:
# the v1.6.11 container image and Helm chart were published 37 minutes BEFORE the
# project's own release-validation job wrote "Release is NOT cleared to publish".
# The publish jobs did not read the verdict, and they did not wait for it either.
#
# This script is the wait. A publish job runs it first and only ships if it exits 0.
#
# It fails closed on every ambiguous state:
#
#   verdict is failure/cancelled/timed_out  -> exit 1
#   verdict never arrives before the deadline -> exit 1
#   the GitHub API cannot be reached at all   -> exit 1
#
# A missing verdict is not a pass. That distinction is the whole fix: the old
# behaviour was "no verdict yet, publish anyway".
#
# Env:
#   CHECK_NAME        required — the check-run name to await, e.g. "required-summary"
#   COMMIT_SHA        required — the commit the artefact is built from
#   REPO              owner/repo (default $GITHUB_REPOSITORY)
#   TIMEOUT_SECONDS   how long to wait for the verdict (default 7200)
#   POLL_SECONDS      seconds between polls (default 30)
#   GH_BIN            gh executable (default gh) — tests substitute a stub

set -uo pipefail

CHECK_NAME="${CHECK_NAME:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-7200}"
POLL_SECONDS="${POLL_SECONDS:-30}"
GH_BIN="${GH_BIN:-gh}"

die() { echo "::error::$*" >&2; exit 1; }

[[ -n "$CHECK_NAME" ]] || die "CHECK_NAME is required."
[[ -n "$COMMIT_SHA" ]] || die "COMMIT_SHA is required."
[[ -n "$REPO" ]] || die "REPO (or GITHUB_REPOSITORY) is required."

# Without jq every poll would read as "no verdict yet" and the wait would end in
# a timeout. That still fails closed, but it reports the wrong reason.
command -v jq >/dev/null 2>&1 || die "jq is required to read the Checks API response."

response="$(mktemp)"
trap 'rm -f "$response"' EXIT

started="$SECONDS"
attempts=0
api_reached=0

echo "Waiting for check '${CHECK_NAME}' on ${REPO}@${COMMIT_SHA}"
echo "Deadline: ${TIMEOUT_SECONDS}s   Poll interval: ${POLL_SECONDS}s"

while :; do
    attempts=$((attempts + 1))

    if "$GH_BIN" api \
        "repos/${REPO}/commits/${COMMIT_SHA}/check-runs?per_page=100" \
        > "$response" 2>/dev/null
    then
        api_reached=1

        # Re-runs produce several check runs with one name. The newest wins:
        # an old failure that has since been re-run green must not block, and a
        # stale success must not clear a newer failure.
        read -r status conclusion <<<"$(
            jq -r --arg name "$CHECK_NAME" '
                [ .check_runs[]? | select(.name == $name) ]
                | sort_by(.started_at)
                | last
                | if . == null then "absent -" else "\(.status) \(.conclusion // "-")" end
            ' "$response" 2>/dev/null
        )"
        status="${status:-absent}"
        conclusion="${conclusion:--}"

        case "$status" in
            completed)
                if [[ "$conclusion" == "success" ]]; then
                    echo "Verdict: ${CHECK_NAME} = success. Publishing is cleared."
                    exit 0
                fi
                die "Verdict: ${CHECK_NAME} = ${conclusion}. This commit is not cleared to publish."
                ;;
            absent)
                echo "  [${attempts}] ${CHECK_NAME} has not started yet."
                ;;
            *)
                echo "  [${attempts}] ${CHECK_NAME} is ${status}."
                ;;
        esac
    else
        # A transient API error must not end the wait, and must never pass.
        echo "  [${attempts}] GitHub API call failed; retrying."
    fi

    if (( SECONDS - started >= TIMEOUT_SECONDS )); then
        if [[ "$api_reached" -eq 0 ]]; then
            die "The GitHub API was never reached in ${TIMEOUT_SECONDS}s. Refusing to publish."
        fi
        die "No verdict from '${CHECK_NAME}' within ${TIMEOUT_SECONDS}s. Refusing to publish."
    fi

    sleep "$POLL_SECONDS"
done
