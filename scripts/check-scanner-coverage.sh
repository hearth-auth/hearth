#!/usr/bin/env bash
# scripts/check-scanner-coverage.sh — scanner configuration must not overstate coverage.
#
# Audit 2026-08-28 findings §4.8#16 and §4.12#15 (Informational/LOW):
#
#   Four ways the scanner configuration claimed cover it did not have:
#
#     1. Fifteen `github.event_name == 'schedule'` conditions in ci.yml, a
#        workflow with no `schedule:` trigger. The header comment claimed
#        "on pushes to main and scheduled runs we bypass the filter"; no
#        scheduled run has ever existed, so the full matrix never ran on one.
#     2. Trivy was advisory-only. It scanned at severity CRITICAL,HIGH and
#        uploaded SARIF, but carried no `exit-code`, so a finding produced a
#        `success` job. The workflow header called each scanner "required to
#        remain green independently".
#     3. The published container image was never scanned. Trivy ran `scan-type:
#        fs` over the checkout only; nothing inspected the image layers that
#        ship to operators (base OS packages, the linked binary).
#     4. Two [[IgnoredVulns]] suppressions named packages absent from the tree
#        their rationale described. RUSTSEC-2023-0071's reason described the
#        server's use of `rsa`, but `rsa` is not in the root Cargo.lock at all.
#        GHSA-g7r4-m6w7-qqqr suppressed `esbuild`, which is not installed in
#        any scanned lockfile — it appears only as an optional peer dependency
#        of vite. A suppression that matches nothing is coverage on paper.
#
# Spec (build-release-integrity): advisory gates SHALL be able to fail a run.
# This guard extends that to the scanners that report through SARIF, and to
# the configuration that describes their scope.
#
# Four rules:
#
#   R1  A workflow may reference `github.event_name == 'schedule'` only if it
#       declares an `on.schedule:` trigger.
#   R2  Every Trivy invocation is armed: the action's `with:` block sets
#       `exit-code: '1'`, so a finding at the configured severity fails the job.
#   R3  The published container image is scanned. docker.yml carries a Trivy
#       step with `scan-type: image`.
#   R4  Every [[IgnoredVulns]] entry in osv-scanner.toml carries a
#       `# guard: package=<name> lockfile=<path>` annotation on the line above
#       it, the lockfile is one security.yml actually scans, and the package
#       name appears in that lockfile.
#
# Usage:  bash scripts/check-scanner-coverage.sh
# Env:    WORKFLOW_DIR   directory to scan (default .github/workflows)
#         OSV_CONFIG     osv-scanner config (default osv-scanner.toml)

set -uo pipefail

WORKFLOW_DIR="${WORKFLOW_DIR:-.github/workflows}"
OSV_CONFIG="${OSV_CONFIG:-osv-scanner.toml}"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

if [[ ! -d "$WORKFLOW_DIR" ]]; then
    echo "FAIL: workflow directory not found: ${WORKFLOW_DIR}"
    exit 1
fi

# declares_schedule <workflow-file> — true when the file has an `on:` block
# containing a `schedule:` key. Indentation distinguishes the trigger from a
# job-level or step-level key: `on:` children sit at two spaces.
declares_schedule() {
    awk '
        /^on:[[:space:]]*$/ { in_on = 1; next }
        /^[A-Za-z]/         { in_on = 0 }
        in_on && /^  schedule:[[:space:]]*$/ { found = 1 }
        END { exit !found }
    ' "$1"
}

# ── R1: no dead schedule condition. ──────────────────────────────────────────
for wf in "${WORKFLOW_DIR}"/*.yml "${WORKFLOW_DIR}"/*.yaml; do
    [[ -f "$wf" ]] || continue
    base="$(basename "$wf")"
    # Comment lines are excluded: prose that names the condition is not the
    # condition. Only a real `if:`/expression line counts.
    hits="$(grep -vE '^[[:space:]]*#' "$wf" \
        | grep -cE "event_name[[:space:]]*[!=]=[[:space:]]*'schedule'")"
    [[ "$hits" -gt 0 ]] || continue
    if ! declares_schedule "$wf"; then
        fail "${base}: ${hits} condition(s) test github.event_name == 'schedule'," \
            $'\n      but the workflow declares no on.schedule: trigger. The branch is' \
            $'\n      unreachable, so the coverage it describes does not exist (§4.8#16).'
    fi
done

# ── R2: every Trivy invocation can fail its job. ─────────────────────────────
# A Trivy step is a `uses:` of aquasecurity/trivy-action. Its `with:` block must
# set exit-code: '1'. The step block runs to the next step dash at the same or
# lower indentation.
trivy_steps_found=0
for wf in "${WORKFLOW_DIR}"/*.yml "${WORKFLOW_DIR}"/*.yaml; do
    [[ -f "$wf" ]] || continue
    base="$(basename "$wf")"
    grep -q 'aquasecurity/trivy-action' "$wf" || continue
    trivy_steps_found=1
    unarmed="$(awk '
        /^[[:space:]]*-[[:space:]]+(name|uses|id):/ {
            if (in_step && is_trivy && !armed) print label
            in_step = 1; is_trivy = 0; armed = 0
            label = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", label)
        }
        in_step && /aquasecurity\/trivy-action/ { is_trivy = 1 }
        in_step && /^[[:space:]]*exit-code:[[:space:]]*.?1.?[[:space:]]*$/ { armed = 1 }
        END { if (in_step && is_trivy && !armed) print label }
    ' "$wf")"
    if [[ -n "$unarmed" ]]; then
        while IFS= read -r step; do
            fail "${base}: Trivy step is advisory-only — no exit-code: '1'." \
                $'\n      A finding at the configured severity produces a success job (§4.8#16).' \
                $'\n      Step: '"${step}"
        done <<< "$unarmed"
    fi
done
if [[ "$trivy_steps_found" -eq 0 ]]; then
    fail "no Trivy step found in ${WORKFLOW_DIR}; R2 and R3 have nothing to check."
fi

# ── R3: the published image is scanned. ──────────────────────────────────────
DOCKER_FILE="${WORKFLOW_DIR}/docker.yml"
if [[ ! -f "$DOCKER_FILE" ]]; then
    fail "docker.yml not found in ${WORKFLOW_DIR}; the image build has no home."
elif ! grep -qE '^[[:space:]]*scan-type:[[:space:]]*image[[:space:]]*$' "$DOCKER_FILE"; then
    fail "docker.yml: nothing runs a Trivy scan-type: image." \
        $'\n      The filesystem scan in security.yml reads the checkout, not the layers' \
        $'\n      that ship to operators. The published image is unscanned (§4.8#16).'
fi

# ── R4: every suppression names a package that is in the tree. ───────────────
if [[ ! -f "$OSV_CONFIG" ]]; then
    fail "osv-scanner config not found: ${OSV_CONFIG}"
else
    SECURITY_FILE="${WORKFLOW_DIR}/security.yml"
    while IFS='|' read -r lineno pkg lock vuln_id; do
        [[ -n "$vuln_id" ]] || continue
        if [[ -z "$pkg" || -z "$lock" ]]; then
            fail "${OSV_CONFIG}:${lineno}: suppression ${vuln_id} has no" \
                $'\n      "# guard: package=<name> lockfile=<path>" annotation, so no check can' \
                $'\n      confirm the package is in a scanned tree (§4.12#15).'
            continue
        fi
        if [[ ! -f "$lock" ]]; then
            fail "${OSV_CONFIG}:${lineno}: ${vuln_id} names lockfile '${lock}'," \
                $'\n      which does not exist.'
            continue
        fi
        if [[ -f "$SECURITY_FILE" ]] && ! grep -qF -- "--lockfile=${lock}" "$SECURITY_FILE"; then
            fail "${OSV_CONFIG}:${lineno}: ${vuln_id} names lockfile '${lock}'," \
                $'\n      which security.yml does not scan. The suppression can never fire.'
            continue
        fi
        # Delimited match, not a substring one: bare `grep -F rsa` would be
        # satisfied by "parsable", which is the exact class of false coverage
        # this rule exists to catch. A package name is bounded by a quote or
        # whitespace in every lockfile format we scan.
        pkg_re="$(printf '%s' "$pkg" | sed 's/[][\.^$*+?(){}|\\]/\\&/g')"
        if ! grep -qE -- "(\"|^|[[:space:]])${pkg_re}(\"|[[:space:]]|\$)" "$lock"; then
            fail "${OSV_CONFIG}:${lineno}: ${vuln_id} suppresses package '${pkg}'," \
                $'\n      which is absent from '"${lock}"$'.' \
                $'\n      A suppression that matches nothing is coverage on paper (§4.12#15).'
        fi
    done < <(awk '
        /^#[[:space:]]*guard:/ {
            pkg = ""; lock = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^package=/)  { pkg  = substr($i, 9) }
                if ($i ~ /^lockfile=/) { lock = substr($i, 10) }
            }
            pending_pkg = pkg; pending_lock = lock
            next
        }
        /^\[\[IgnoredVulns\]\]/ {
            open = 1; start = NR
            ann_pkg = pending_pkg; ann_lock = pending_lock
            pending_pkg = ""; pending_lock = ""
            next
        }
        open && /^id[[:space:]]*=/ {
            id = $0
            sub(/^id[[:space:]]*=[[:space:]]*"/, "", id)
            sub(/"[[:space:]]*$/, "", id)
            print start "|" ann_pkg "|" ann_lock "|" id
            open = 0
        }
        /^[[:space:]]*$/ { next }
    ' "$OSV_CONFIG")
fi

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} scanner-coverage violation(s)."
    echo "See scripts/check-scanner-coverage.sh for the rules and the audit citation."
    exit 1
fi
echo "OK: scanner configuration describes the coverage it actually has."
exit 0
