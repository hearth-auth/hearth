#!/usr/bin/env bash
# ci-required-checks-migrate.sh — switch the `main` branch protection's
# required_status_checks list from the legacy / pre-consolidation names to the
# post-HEA-672-consolidation names emitted by ci.yml + security.yml.
#
# HEA-684. Run AFTER all consolidation PRs (HEA-676, HEA-680, HEA-687, HEA-689)
# have landed on `main`. Requires a CTO request_confirmation acceptance on the
# Paperclip issue thread before the PATCH path is executed in production.
#
# Modes:
#   --dry-run       Print the proposed new list and a unified diff vs the
#                   current required-checks list. Does NOT call PATCH. Default
#                   when no flag is given.
#   --apply         Send the PATCH to GitHub. Requires GH_TOKEN / `gh auth` with
#                   `repo` scope (Admin on hearth-auth/hearth or owner-scoped).
#   --rollback FILE Restore required_status_checks from a JSON snapshot file
#                   captured by a prior --apply (written to
#                   `scripts/.hea-684-rollback-<timestamp>.json`).
#
# Idempotency:
#   --apply re-reads the live list before sending PATCH and exits 0 with
#   "no change" if the live list already matches the target. Safe to re-run.
#
# Rollback:
#   Every --apply run writes the previous list to
#   `scripts/.hea-684-rollback-<UTC-timestamp>.json` BEFORE issuing the PATCH.
#   To revert: `scripts/ci-required-checks-migrate.sh --rollback <that-file>`.
#
# Required-checks rationale:
#   See `scripts/ci-required-checks-migrate.sh` header in PR description and
#   the CTO request_confirmation comment on HEA-684 for the per-check
#   justification (filter-gating, skip-on-no-relevant-files behaviour, etc).

set -euo pipefail

OWNER="${HEARTH_OWNER:-therecluse26}"
REPO="${HEARTH_REPO:-hearth}"
BRANCH="${HEARTH_BRANCH:-main}"

# ──────────────────────────────────────────────────────────────────────────────
# Target required-checks list (post-consolidation, HEA-672 family)
#
# Format: GitHub `<workflow.name> / <job.name>` (with matrix interpolation
# resolved). Values verified against:
#   .github/workflows/ci.yml          (workflow.name "CI")
#   .github/workflows/security.yml    (workflow.name "Security")
#
# Notes:
#   - `CI / filter (paths-filter)` ALWAYS runs and acts as the fail-closed
#     guard for downstream gated jobs (HEA-687). Requiring it forces every PR
#     to compute filter outputs; downstream jobs then run-or-skip from there.
#   - `Security / codeql (java-kotlin)` was removed in HEA-689; only 4 CodeQL
#     legs remain (rust, go, javascript-typescript, python).
#   - `bench-regression` and `fuzz` workflows live in their own files and are
#     intentionally NOT in the required list — they're heavy / scheduled and
#     PR enforcement is via the Benchmark Regression Gate workflow check on
#     direct pushes to main, not on PRs.
#   - `Scorecard supply-chain security` is schedule-only — cannot be a required
#     PR check; left out by design.
# ──────────────────────────────────────────────────────────────────────────────
TARGET_CHECKS=(
  "CI / filter (paths-filter)"
  "CI / quality (clippy + fmt + nextest + css/proto check)"
  "CI / ui (Playwright — smoke + regression + accessibility + exploratory)"
  "CI / sdk-node (18.x)"
  "CI / sdk-node (20.x)"
  "CI / sdk-node (22.x)"
  "CI / sdk-conformance (docs/sdk-spec.md)"
  "Security / codeql (rust)"
  "Security / codeql (go)"
  "Security / codeql (javascript-typescript)"
  "Security / codeql (python)"
  "Security / trivy"
  "Security / osv-scanner"
)

usage() {
  cat <<EOF
Usage: $(basename "$0") [--dry-run | --apply | --rollback FILE]

Default (no flag): --dry-run
EOF
  exit 64
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: \`$1\` is required but not on PATH" >&2
    exit 127
  }
}

require_cmd gh
require_cmd jq

fetch_current() {
  gh api "repos/${OWNER}/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
    --jq '.checks | sort_by(.context) | map(.context)'
}

build_target_json() {
  # Emits the PATCH body GitHub expects:
  #   { "strict": true, "checks": [ { "context": "..." }, ... ] }
  jq -n --argjson checks "$(printf '%s\n' "${TARGET_CHECKS[@]}" | jq -R . | jq -s 'sort')" '
    {
      strict: true,
      checks: ($checks | map({ context: . }))
    }'
}

show_diff() {
  local current target
  current=$(fetch_current)
  target=$(printf '%s\n' "${TARGET_CHECKS[@]}" | jq -R . | jq -s 'sort')

  echo "── Current required_status_checks (${OWNER}/${REPO}@${BRANCH}) ──"
  echo "${current}" | jq -r '.[] | "  - " + .'
  echo
  echo "── Target required_status_checks (HEA-684 post-consolidation) ──"
  echo "${target}" | jq -r '.[] | "  - " + .'
  echo
  echo "── Diff (- removed, + added) ──"
  diff -u \
    <(echo "${current}" | jq -r '.[]') \
    <(echo "${target}"  | jq -r '.[]') \
    || true
}

cmd_dry_run() {
  show_diff
  echo
  echo "Dry-run only. Re-run with --apply (after CTO confirmation) to PATCH."
}

cmd_apply() {
  local current target_json snapshot_path
  current=$(fetch_current)
  target_json=$(build_target_json)

  # Idempotency check: if current list already equals target, exit clean.
  local target_sorted
  target_sorted=$(echo "${target_json}" | jq -c '.checks | map(.context) | sort')
  local current_sorted
  current_sorted=$(echo "${current}" | jq -c 'sort')
  if [[ "${current_sorted}" == "${target_sorted}" ]]; then
    echo "No change required — live list already matches HEA-684 target."
    return 0
  fi

  snapshot_path="scripts/.hea-684-rollback-$(date -u +%Y%m%dT%H%M%SZ).json"
  echo "${current}" | jq '{ strict: true, checks: (. | map({ context: . })) }' > "${snapshot_path}"
  echo "Wrote rollback snapshot → ${snapshot_path}"

  echo "PATCHing required_status_checks…"
  echo "${target_json}" | gh api \
    -X PATCH \
    "repos/${OWNER}/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
    --input - \
    --jq '.checks | sort_by(.context) | map(.context)' \
    > /dev/null

  echo "Post-PATCH live list:"
  fetch_current | jq -r '.[] | "  - " + .'
  echo
  echo "Done. Rollback file: ${snapshot_path}"
}

cmd_rollback() {
  local snapshot="${1:?--rollback requires a snapshot file}"
  [[ -f "${snapshot}" ]] || { echo "ERROR: snapshot file not found: ${snapshot}" >&2; exit 2; }

  echo "Rolling back required_status_checks from: ${snapshot}"
  gh api \
    -X PATCH \
    "repos/${OWNER}/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
    --input "${snapshot}" \
    --jq '.checks | sort_by(.context) | map(.context)' \
    > /dev/null

  echo "Post-rollback live list:"
  fetch_current | jq -r '.[] | "  - " + .'
}

case "${1:-}" in
  ""|--dry-run) cmd_dry_run ;;
  --apply)      cmd_apply ;;
  --rollback)   cmd_rollback "${2:-}" ;;
  -h|--help)    usage ;;
  *)            usage ;;
esac
