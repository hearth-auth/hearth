#!/usr/bin/env bash
# scripts/tests/check-chart-image-tag.test.sh — tests for
# scripts/check-chart-image-tag.sh (audit 2026-08-28 §4.8#4, §4.12#6).
#
# The guard is the deliverable, so it needs a test that proves it FAILS on the
# pre-fix chart — not just that it passes on the fixed one, which an `exit 0`
# stub would also satisfy.
#
# The defect: `hearth.imageTag` defaulted to the bare `AppVersion`, rendering
# `ghcr.io/hearth-auth/hearth:1.6.8`. The Docker workflow publishes
# `type=semver,pattern=v{{version}}` — `v1.6.11` — so the chart's default tag
# named an image that does not exist and `helm install` could not pull.
#
# Usage: bash scripts/tests/check-chart-image-tag.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-chart-image-tag.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0

# Builds a throwaway fixture tree under $TMP/<name> and echoes its path.
# make_fixture <name> <chart-version> <app-version> <helper-default> <crate-version> <docker-tag-pattern>
make_fixture() {
    local name="$1" chart_ver="$2" app_ver="$3" helper="$4" crate_ver="$5" docker_pat="$6"
    local root="$TMP/$name"
    mkdir -p "$root/deploy/helm/hearth/templates" "$root/.github/workflows"
    cat > "$root/deploy/helm/hearth/Chart.yaml" <<EOF
apiVersion: v2
name: hearth
type: application
version: ${chart_ver}
appVersion: "${app_ver}"
EOF
    cat > "$root/deploy/helm/hearth/templates/_helpers.tpl" <<EOF
{{- define "hearth.imageTag" -}}
${helper}
{{- end }}
EOF
    cat > "$root/Cargo.toml" <<EOF
[package]
name = "hearth"
version = "${crate_ver}"
EOF
    cat > "$root/.github/workflows/docker.yml" <<EOF
          tags: |
            ${docker_pat}
            type=sha,prefix=sha-,format=short
EOF
    echo "$root"
}

# run_case <name> <expected-exit> <fixture-root> [expected-substring]
run_case() {
    local name="$1" want="$2" root="$3" expect="${4:-}"
    local out got
    out="$(cd "$root" && bash "$CHECK" 2>&1)"
    got=$?
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

GOOD_HELPER='{{- .Values.image.tag | default (printf "v%s" .Chart.AppVersion) }}'
BARE_HELPER='{{- .Values.image.tag | default .Chart.AppVersion }}'
SEMVER_PAT='type=semver,pattern=v{{version}}'

# 1 — a correct chart passes.
run_case "correct chart passes" 0 \
    "$(make_fixture good 1.6.11 1.6.11 "$GOOD_HELPER" 1.6.11 "$SEMVER_PAT")" \
    "OK:"

# 2 — REGRESSION: the pre-fix helper renders a bare version the workflow never
#     publishes. This is the exact shape the audit found.
run_case "bare AppVersion default is rejected" 1 \
    "$(make_fixture bare 1.6.11 1.6.11 "$BARE_HELPER" 1.6.11 "$SEMVER_PAT")" \
    "does not carry the 'v' prefix"

# 3 — a stale appVersion is rejected even when the prefix is right.
run_case "stale appVersion is rejected" 1 \
    "$(make_fixture stale 1.6.8 1.6.8 "$GOOD_HELPER" 1.6.11 "$SEMVER_PAT")" \
    "appVersion 1.6.8 does not match the crate version 1.6.11"

# 4 — chart version and appVersion must agree; the publish workflow stamps both
#     from one tag, so a divergence in-repo is a lie about what ships.
run_case "chart version diverging from appVersion is rejected" 1 \
    "$(make_fixture diverge 1.6.9 1.6.11 "$GOOD_HELPER" 1.6.11 "$SEMVER_PAT")" \
    "version 1.6.9 does not match appVersion 1.6.11"

# 5 — if the Docker workflow stops publishing the v-prefixed semver tag, the
#     chart's default becomes unpullable again; the guard must catch that too.
run_case "docker workflow without the v-prefixed semver tag is rejected" 1 \
    "$(make_fixture nopat 1.6.11 1.6.11 "$GOOD_HELPER" 1.6.11 'type=semver,pattern={{version}}')" \
    "does not publish"

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} test case(s) failed."
    exit 1
fi
echo "all check-chart-image-tag.sh test cases passed."
exit 0
