#!/usr/bin/env bash
# scripts/tests/check-publish-gating.test.sh — tests for scripts/check-publish-gating.sh.
#
# The guard exists to stop audit blockers B2 and B6 recurring, so it must be shown
# to FAIL on the exact shape the audit found: a tag-triggered job that publishes
# without waiting for a verdict. Case 1 is that shape.
#
# Cases 4 and 8 pin the two ways a guard like this goes vacuous: treating a
# dry-run as a publish, and treating a PR smoke build as a release channel. A
# guard that fires on those gets disabled, and then it guards nothing.
#
# Usage: bash scripts/tests/check-publish-gating.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-publish-gating.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0

# run_case <name> <expected-exit> <manifest> <workflow-body> [expected-substring]
run_case() {
    local name="$1" want="$2" manifest="$3" body="$4" expect="${5:-}"
    local dir="$TMP/case-$((RANDOM))-$$"
    mkdir -p "$dir"
    printf '%s\n' "$body" > "$dir/wf.yml"
    local out got=0
    out="$(WORKFLOW_DIR="$dir" PUBLISH_WORKFLOWS_OVERRIDE="$manifest" \
        bash "$CHECK" 2>&1)" || got=$?
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

TAG_TRIGGER='on:
  push:
    tags:
      - "v[0-9]+.[0-9]+.[0-9]+"
'

GATE_JOB='  gate:
    name: Await a green verdict
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/await-green-commit
'

# 1 — THE REGRESSION. A tag-triggered publish job with no gate: the exact shape
#     that shipped the v1.6.11 image 37 minutes ahead of its own verdict.
run_case "ungated publish job is rejected" 1 "" \
"${TAG_TRIGGER}jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance --access public
" \
    "job 'publish' publishes without waiting for a verdict"

# 2 — the same workflow with a direct gate dependency passes.
run_case "publish gated directly passes" 0 "" \
"${TAG_TRIGGER}jobs:
${GATE_JOB}  publish:
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance --access public
" \
    "OK: every publish job waits"

# 3 — the gate may be reached transitively, as it is in release.yml.
run_case "publish gated transitively passes" 0 "" \
"${TAG_TRIGGER}jobs:
${GATE_JOB}  build:
    needs: [gate]
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  publish:
    needs:
      - build
    runs-on: ubuntu-latest
    steps:
      - run: cargo publish
" \
    "OK: every publish job waits"

# 4 — a dry-run is not a publish. Firing here would make the guard unusable.
run_case "dry-run publish is not a release" 0 "" \
"${TAG_TRIGGER}jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --dry-run --provenance
      - run: cargo publish --dry-run
      - run: gradle publishToMavenLocal
" \
    "OK: every publish job waits"

# 5 — R1: a manifest channel with no gate job anywhere is rejected, even when no
#     publish command appears. This is what covers the Go and PHP SDKs, whose
#     registries publish from the git tag rather than from a workflow step.
run_case "manifest workflow without any gate is rejected" 1 "wf.yml" \
"${TAG_TRIGGER}jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - run: go build ./...
" \
    "declares no gate job"

# 6 — R1: a manifest channel whose file is gone is rejected, not silently skipped.
run_case "manifest workflow that is absent is rejected" 1 "wf.yml vanished.yml" \
"${TAG_TRIGGER}jobs:
${GATE_JOB}" \
    "vanished.yml: listed in PUBLISH_WORKFLOWS but absent"

# 7 — an in-workflow validation job marked `# publish-gate` satisfies the rule.
run_case "in-workflow validation marked as the gate passes" 0 "wf.yml" \
"${TAG_TRIGGER}jobs:
  validation:
    # publish-gate — this job produces the verdict the publish jobs wait for.
    runs-on: ubuntu-latest
    steps:
      - run: make check
  release:
    needs: [validation]
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1.0.0
" \
    "OK: every publish job waits"

# 7b — REGRESSION: a BRANCH-push release workflow is in scope, not just tag-push.
#      This is the semantic-release.yml shape: it runs on every push to main,
#      creates the SDK Release objects, and pushes the tags that trigger every
#      other channel. An R2 scoped to tag triggers walks straight past it, which
#      is how the whole release chain stayed ungated at its source.
run_case "branch-push release workflow is in scope" 1 "" \
'on:
  push:
    branches: [main]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npx semantic-release
' \
    "job 'release' publishes without waiting for a verdict"

# 8 — a PR-only workflow is not a release channel; R2 must not reach it.
run_case "PR-only workflow with a publish marker is out of scope" 0 "" \
'on:
  pull_request:
    branches: [main]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - run: cosign sign --yes example
' \
    "OK: every publish job waits"

# 9 — a gate that is itself the publisher does not gate anything, but a job that
#     both gates and publishes is accepted: the wait still precedes the push.
run_case "a job that gates and then publishes passes" 0 "" \
"${TAG_TRIGGER}jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/await-green-commit
      - run: helm push chart.tgz oci://example
" \
    "OK: every publish job waits"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "all check-publish-gating.sh test cases passed."
exit 0
