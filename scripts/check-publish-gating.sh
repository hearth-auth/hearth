#!/usr/bin/env bash
# scripts/check-publish-gating.sh — every publish job must wait for a green verdict.
#
# Audit 2026-08-28 blockers B2 (§4.8#1) and B6 (§4.12#1):
#
#   B2  The container image, the Helm chart, seven SDK releases and two registry
#       packages shipped from a commit whose own suite failed four tests. Only the
#       binary channel in release.yml was gated.
#   B6  The v1.6.11 image and chart were published 37 minutes BEFORE the project's
#       own release-validation job wrote "Release is NOT cleared to publish".
#
# Both have one root cause: a publish job that neither waits for the verdict nor
# reads it. This guard makes that state fail the build instead of shipping.
#
# Two rules:
#
#   R1  Every workflow named in PUBLISH_WORKFLOWS must contain a gate job.
#       Pins the known channels, so deleting the gate is a failure, not a silence.
#   R2  In any push-triggered workflow, every job carrying a publish marker must
#       reach a gate job through its `needs:` chain.
#       Catches a NEW publishing workflow the manifest does not know about.
#
# R2 covers branch pushes, not only tag pushes. semantic-release.yml is why: it
# runs on every push to main, creates the seven SDK Release objects, and pushes
# the tags that trigger every other channel. A rule scoped to tag triggers would
# have walked straight past the workflow that starts the whole release.
#
# A gate job is a job whose block contains either:
#   - `await-green-commit`  — the shared wait-for-verdict action, or
#   - `# publish-gate`      — an in-workflow validation job that produces the verdict.
#
# R1 is what covers sdk-publish-go.yml and sdk-publish-php.yml. Neither runs a
# publish command: the Go module proxy and Packagist publish from the git tag
# itself, so no marker exists for R2 to find. Their gate cannot stop the registry
# — it turns an ungreen tag into a red run an operator can see. That limit is
# real and is stated in docs/ops/RELEASE_VALIDATION.md.
#
# Usage:  bash scripts/check-publish-gating.sh
# Env:    WORKFLOW_DIR                directory to scan (default .github/workflows)
#         PUBLISH_WORKFLOWS_OVERRIDE  space-separated R1 manifest (tests only)

set -uo pipefail

WORKFLOW_DIR="${WORKFLOW_DIR:-.github/workflows}"

# R1 manifest — every release channel the audit enumerated.
PUBLISH_WORKFLOWS=(
    release.yml               # GitHub Release binaries + SBOM + signatures
    docker.yml                # ghcr.io/hearth-auth/hearth container image
    helm.yml                  # ghcr.io/hearth-auth/charts/hearth OCI chart
    sdk-publish-go.yml        # Go module proxy (tag-driven)
    sdk-publish-kotlin.yml    # Maven Central
    sdk-publish-node.yml      # npm
    sdk-publish-php.yml       # Packagist (tag-driven)
    sdk-publish-python.yml    # PyPI
    sdk-publish-rust.yml      # crates.io
    sdk-publish-typescript.yml # npm
    semantic-release.yml      # creates the Release objects and pushes every tag
)

# The manifest is overridable so the guard's own tests can build small synthetic
# workflow trees. Production runs never set this.
# Set-but-empty means "no manifest", which is a valid test fixture, so test for
# the variable being set rather than for it being non-empty.
if [[ -n "${PUBLISH_WORKFLOWS_OVERRIDE+set}" ]]; then
    PUBLISH_WORKFLOWS=()
    read -r -a PUBLISH_WORKFLOWS <<<"$PUBLISH_WORKFLOWS_OVERRIDE"
fi

# R2 markers — a line that ships bytes to somewhere an operator can install from.
# Dry-run forms are excluded by is_publish_line below.
PUBLISH_MARKERS='gh release create|helm push |npm publish|cargo publish|twine upload|pypa/gh-action-pypi-publish|gradle publish|cosign sign|cosign attest|push=true|push-by-digest=true|imagetools create|npx semantic-release'

failures=0

fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

# is_publish_line <line> — true when the line ships, false for its dry-run twin.
is_publish_line() {
    local line="$1"
    case "$line" in
        *--dry-run*) return 1 ;;
        *publishToMavenLocal*) return 1 ;;
        *push=false*) return 1 ;;
    esac
    [[ "$line" =~ $PUBLISH_MARKERS ]]
}

# split_jobs <workflow-file> <outdir> — write one <outdir>/<job>.block per job.
split_jobs() {
    awk -v outdir="$2" '
        /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
        !in_jobs { next }
        # A job header is a two-space-indented bare key.
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            name = $1
            sub(/:$/, "", name)
            out = outdir "/" name ".block"
            print name >> (outdir "/.jobs")
            next
        }
        out { print >> out }
    ' "$1"
}

# needs_of <block-file> — print each job name the block declares in `needs:`.
# Handles `needs: a`, `needs: [a, b]` and a block sequence of `- a` lines.
needs_of() {
    awk '
        /^[[:space:]]*needs:[[:space:]]*\[/ {
            line = $0
            sub(/^[^[]*\[/, "", line)
            sub(/\].*$/, "", line)
            gsub(/[[:space:]]/, "", line)
            n = split(line, parts, ",")
            for (i = 1; i <= n; i++) if (parts[i] != "") print parts[i]
            next
        }
        /^[[:space:]]*needs:[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*$/ {
            print $2
            next
        }
        /^[[:space:]]*needs:[[:space:]]*$/ { seq = 1; next }
        seq && /^[[:space:]]*-[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*$/ { print $2; next }
        seq { seq = 0 }
    ' "$1"
}

check_workflow() {
    local wf="$1" base
    base="$(basename "$wf")"

    local tmp
    tmp="$(mktemp -d)"
    split_jobs "$wf" "$tmp"
    [[ -f "$tmp/.jobs" ]] || { rm -rf "$tmp"; return; }

    # Read with a loop rather than mapfile: mapfile is bash 4+, and macOS still
    # ships bash 3.2, where `make ci-local-fast` would otherwise die here.
    local jobs=() gates=() publishers=()
    while IFS= read -r _job_name; do
        [[ -n "$_job_name" ]] && jobs+=("$_job_name")
    done < "$tmp/.jobs"

    local job block
    for job in "${jobs[@]}"; do
        block="$tmp/$job.block"
        [[ -f "$block" ]] || continue
        if grep -qE 'await-green-commit|# publish-gate' "$block"; then
            gates+=("$job")
        fi
        while IFS= read -r line; do
            if is_publish_line "$line"; then
                publishers+=("$job")
                break
            fi
        done < "$block"
    done

    # ── R1: a manifest workflow must have a gate at all. ──────────────────────
    local manifest_member=0 w
    for w in "${PUBLISH_WORKFLOWS[@]}"; do
        [[ "$w" == "$base" ]] && manifest_member=1
    done
    if [[ "$manifest_member" -eq 1 && "${#gates[@]}" -eq 0 ]]; then
        fail "${base}: publishes a release channel but declares no gate job." \
            $'\n      Add a job using ./.github/actions/await-green-commit, or mark the' \
            $'\n      in-workflow validation job with the comment `# publish-gate`.'
    fi

    # ── R2: a publish job must reach a gate through `needs:`. ─────────────────
    # Scoped to push-triggered workflows. A PR-only workflow that matches a
    # marker is running a dry-run smoke build, not shipping a release.
    if ! grep -qE '^[[:space:]]{2}push:' "$wf"; then
        rm -rf "$tmp"
        return
    fi

    local p is_gate closure frontier next_frontier g dep seen
    for p in "${publishers[@]}"; do
        is_gate=0
        for g in "${gates[@]}"; do [[ "$g" == "$p" ]] && is_gate=1; done
        [[ "$is_gate" -eq 1 ]] && continue

        # Walk the needs graph from this job; stop at the first gate reached.
        closure=" "
        frontier="$p"
        while [[ -n "$frontier" ]]; do
            next_frontier=""
            for dep in $frontier; do
                while IFS= read -r seen; do
                    [[ -z "$seen" ]] && continue
                    [[ "$closure" == *" $seen "* ]] && continue
                    closure="${closure}${seen} "
                    next_frontier="$next_frontier $seen"
                done < <(needs_of "$tmp/$dep.block" 2>/dev/null)
            done
            frontier="$next_frontier"
        done

        local reached=0
        for g in "${gates[@]}"; do
            [[ "$closure" == *" $g "* ]] && reached=1
        done
        if [[ "$reached" -eq 0 ]]; then
            fail "${base}: job '${p}' publishes without waiting for a verdict." \
                $'\n      Its `needs:` chain reaches no gate job. Publishing a commit whose' \
                $'\n      suite has not reported is audit blocker B2/B6.'
        fi
    done

    rm -rf "$tmp"
}

if [[ ! -d "$WORKFLOW_DIR" ]]; then
    echo "FAIL: workflow directory not found: ${WORKFLOW_DIR}"
    exit 1
fi

# R1 also fails when a manifest workflow is missing entirely — a channel cannot
# be gated by a file that is not there, and a silent skip is how B2 happened.
for w in "${PUBLISH_WORKFLOWS[@]}"; do
    if [[ ! -f "${WORKFLOW_DIR}/${w}" ]]; then
        fail "${w}: listed in PUBLISH_WORKFLOWS but absent from ${WORKFLOW_DIR}."
    fi
done

for wf in "${WORKFLOW_DIR}"/*.yml "${WORKFLOW_DIR}"/*.yaml; do
    [[ -f "$wf" ]] || continue
    check_workflow "$wf"
done

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} publish-gating violation(s)."
    echo "See scripts/check-publish-gating.sh for the rule and the audit citation."
    exit 1
fi
echo "OK: every publish job waits for a green verdict on its own commit."
exit 0
