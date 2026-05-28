#!/usr/bin/env bash
# cleanup-stale-code-scanning-analyses.sh — delete stale GitHub Code Scanning
# analyses whose source workflows no longer exist or whose categories were
# renamed during the HEA-680 security-workflow consolidation.
#
# HEA-716 / HEA-717. The Code Scanning UI keeps showing
# "Actions workflow … is missing" / "stale tool" warnings whenever an
# `analysis_key` references a workflow path that no longer exists on `main`.
# Renaming or consolidating workflows does not retroactively clean up the
# already-uploaded analyses — they have to be deleted via the REST API.
#
# Per-tool stale predicates (anything matching is in scope for deletion):
#
#   CodeQL
#     - category in {/language:java-kotlin, /language:actions}
#       (no Kotlin in the repo; the actions database is the noisy one this
#       script was written to drain), OR
#     - analysis_key starts with `.github/workflows/codeql.yml`
#       (legacy single-purpose CodeQL workflow, replaced by security.yml), OR
#     - analysis_key starts with `dynamic/`
#       (legacy GitHub-managed default-setup analyses from before the manual
#       workflow took over).
#
#   Trivy
#     - analysis_key starts with `.github/workflows/trivy.yml`
#       (replaced by the consolidated security.yml).
#
#   osv-scanner
#     - analysis_key starts with `.github/workflows/osv-scanner.yml`
#       (replaced by the consolidated security.yml).
#
#   Snyk Open Source
#     - all analyses (Snyk is no longer used by Hearth — see the
#       "no Snyk" policy in `.github/workflows/security.yml`).
#
# Modes:
#   --dry-run         Default. List the analyses that WOULD be deleted; no
#                     mutating API calls are issued.
#   --confirm         Issue DELETE calls. Walks the `confirm_delete_url`
#                     / `next_analysis_url` chain returned by GitHub so the
#                     last analysis in each (tool, ref, analysis_key) triple
#                     is also drained (a single-pass DELETE leaves a tail).
#   --tool <name>     Restrict the run to a single tool. One of: CodeQL,
#                     Trivy, osv-scanner, "Snyk Open Source". May be passed
#                     multiple times. If omitted, runs against all four.
#
# Logging:
#   Each deletion (and dry-run candidate) is logged as a single JSON line:
#     {id, tool, category, ref, analysis_key, deletable}
#   Lines go to stdout; summary counts go to stderr.
#
# Idempotency:
#   Re-running after a successful --confirm pass is a no-op: the matching
#   analyses are already gone, so the listing endpoint returns nothing in
#   scope and the script exits 0 with a "nothing to do" line.
#
# Auth:
#   Uses the ambient `GITHUB_TOKEN` via the `gh` CLI. The script never reads
#   or prints the token. Requires `gh auth status` to be green and the
#   authenticated identity to have `security_events: write` on the repo
#   (Admin role, or a fine-grained PAT with that scope).
#
# Repo:
#   Defaults to hearth-auth/hearth. Override with HEARTH_OWNER / HEARTH_REPO
#   for fork testing.

set -euo pipefail

OWNER="${HEARTH_OWNER:-therecluse26}"
REPO="${HEARTH_REPO:-hearth}"

MODE="dry-run"
TOOLS=()

usage() {
  sed -n '2,70p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run"; shift ;;
    --confirm) MODE="confirm"; shift ;;
    --tool)
      [[ $# -ge 2 ]] || { echo "error: --tool requires a value" >&2; exit 2; }
      TOOLS+=("$2"); shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage 2 ;;
  esac
done

if [[ ${#TOOLS[@]} -eq 0 ]]; then
  TOOLS=("CodeQL" "Trivy" "osv-scanner" "Snyk Open Source")
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI not found in PATH" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq not found in PATH" >&2
  exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh is not authenticated (run 'gh auth login')" >&2
  exit 2
fi

# is_stale <tool> <category> <analysis_key>
# Returns 0 (true) if the analysis matches a per-tool stale predicate.
is_stale() {
  local tool="$1" category="$2" key="$3"
  case "$tool" in
    "CodeQL")
      [[ "$category" == "/language:java-kotlin" ]] && return 0
      [[ "$category" == "/language:actions" ]] && return 0
      [[ "$key" == .github/workflows/codeql.yml* ]] && return 0
      [[ "$key" == dynamic/* ]] && return 0
      return 1 ;;
    "Trivy")
      [[ "$key" == .github/workflows/trivy.yml* ]] && return 0
      return 1 ;;
    "osv-scanner")
      [[ "$key" == .github/workflows/osv-scanner.yml* ]] && return 0
      return 1 ;;
    "Snyk Open Source")
      return 0 ;;
    *)
      return 1 ;;
  esac
}

# process_tool <tool>
# Pages through /repos/:owner/:repo/code-scanning/analyses?tool_name=<tool>,
# emits a JSON line per stale candidate, and (in --confirm mode) DELETEs each
# one. After the first non-deletable hit is deleted, GitHub flips the next
# analysis to deletable on the next listing — so we re-list per tool until
# no more candidates are returned.
process_tool() {
  local tool="$1"
  local pass=0
  local total_seen=0
  local total_deleted=0

  while :; do
    pass=$((pass + 1))
    local found_in_pass=0

    # `gh api --paginate` walks the Link header. We sort by created-asc so
    # the oldest analysis per (tool, ref, analysis_key) is encountered first;
    # GitHub's REST docs require deleting from oldest to newest within a key.
    local analyses
    analyses=$(gh api --paginate \
      "/repos/${OWNER}/${REPO}/code-scanning/analyses?tool_name=$(printf '%s' "$tool" | jq -sRr @uri)&direction=asc&sort=created&per_page=100" \
      2>/dev/null || true)

    if [[ -z "$analyses" || "$analyses" == "[]" ]]; then
      break
    fi

    # `gh api --paginate` concatenates JSON arrays back-to-back: `[...][...]`.
    # `jq -s '. | add'` flattens them into a single stream we can iterate.
    while IFS= read -r row; do
      [[ -z "$row" ]] && continue
      total_seen=$((total_seen + 1))

      local id category ref key deletable
      id=$(jq -r '.id'            <<<"$row")
      category=$(jq -r '.category // ""'      <<<"$row")
      ref=$(jq -r '.ref // ""'                <<<"$row")
      key=$(jq -r '.analysis_key // ""'       <<<"$row")
      deletable=$(jq -r '.deletable'          <<<"$row")

      if ! is_stale "$tool" "$category" "$key"; then
        continue
      fi

      found_in_pass=$((found_in_pass + 1))

      jq -cn \
        --argjson id "$id" \
        --arg tool "$tool" \
        --arg category "$category" \
        --arg ref "$ref" \
        --arg analysis_key "$key" \
        --argjson deletable "$deletable" \
        '{id: $id, tool: $tool, category: $category, ref: $ref, analysis_key: $analysis_key, deletable: $deletable}'

      if [[ "$MODE" == "confirm" ]]; then
        # The DELETE call returns 200 with the next analysis to delete, or 204
        # when the tool's chain is fully drained. Either way we treat it as
        # success; the outer while loop re-lists and exits when nothing is
        # left in scope.
        if gh api -X DELETE \
          "/repos/${OWNER}/${REPO}/code-scanning/analyses/${id}?confirm_delete=true" \
          >/dev/null 2>&1; then
          total_deleted=$((total_deleted + 1))
        else
          echo "warning: DELETE failed for analysis id=${id} tool=${tool}" >&2
        fi
      fi
    done < <(jq -c '. | add // .[] // empty' <<<"$analyses" 2>/dev/null \
              || jq -c '.[]' <<<"$analyses" 2>/dev/null \
              || true)

    # Dry-run never mutates, so one pass is enough — re-listing would just
    # re-emit the same rows. In --confirm mode, exit the loop once a pass
    # finds nothing in scope (idempotent steady state).
    if [[ "$MODE" != "confirm" ]]; then
      break
    fi
    if [[ "$found_in_pass" -eq 0 ]]; then
      break
    fi
  done

  echo "tool='${tool}' mode='${MODE}' seen=${total_seen} deleted=${total_deleted}" >&2
}

for tool in "${TOOLS[@]}"; do
  process_tool "$tool"
done

if [[ "$MODE" == "dry-run" ]]; then
  echo "note: --dry-run only. Re-run with --confirm to actually delete." >&2
fi
