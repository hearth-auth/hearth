#!/usr/bin/env bash
# scripts/check-chart-image-tag.sh — the Helm chart's default image tag must be
# one the Docker workflow actually publishes.
#
# Audit 2026-08-28 findings §4.8#4 and §4.12#6 (MEDIUM):
#
#   The Helm chart renders an image tag the image workflow never publishes, so
#   a default `helm install` cannot pull an image.
#
# `hearth.imageTag` defaulted to the bare `.Chart.AppVersion`, rendering
# `ghcr.io/hearth-auth/hearth:1.6.8`. The Docker workflow publishes
# `type=semver,pattern=v{{version}}` — `v1.6.11` — and nothing else that is
# version-shaped. The stamped chart is no better: the publish workflow sets
# `--app-version` to the tag with the leading `v` stripped, so a released chart
# reproduced the same unpullable reference.
#
# This gate is offline and needs no cluster: it reads the chart, the crate
# version, and the Docker workflow, and refuses a combination that cannot pull.
#
# Usage:  bash scripts/check-chart-image-tag.sh
# Env:    CHART_DIR       (default deploy/helm/hearth)
#         CARGO_TOML      (default Cargo.toml)
#         DOCKER_WORKFLOW (default .github/workflows/docker.yml)

set -uo pipefail

CHART_DIR="${CHART_DIR:-deploy/helm/hearth}"
CARGO_TOML="${CARGO_TOML:-Cargo.toml}"
DOCKER_WORKFLOW="${DOCKER_WORKFLOW:-.github/workflows/docker.yml}"

CHART_YAML="${CHART_DIR}/Chart.yaml"
HELPERS_TPL="${CHART_DIR}/templates/_helpers.tpl"

for f in "$CHART_YAML" "$HELPERS_TPL" "$CARGO_TOML" "$DOCKER_WORKFLOW"; do
    [[ -f "$f" ]] || { echo "FAIL: ${f} not found."; exit 1; }
done

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

chart_version="$(grep -m1 '^version:' "$CHART_YAML" | awk '{print $2}' | tr -d '"')"
app_version="$(grep -m1 '^appVersion:' "$CHART_YAML" | awk '{print $2}' | tr -d '"')"
crate_version="$(grep -m1 '^version = ' "$CARGO_TOML" | sed 's/.*"\(.*\)".*/\1/')"

[[ -n "$chart_version" ]] || fail "no 'version:' in ${CHART_YAML}."
[[ -n "$app_version" ]]   || fail "no 'appVersion:' in ${CHART_YAML}."
[[ -n "$crate_version" ]] || fail "no crate version in ${CARGO_TOML}."

# 1. The default tag must carry the 'v' prefix the registry uses.
#    Everything between the `hearth.imageTag` define and its `end` is the body.
helper_body="$(awk '/define "hearth.imageTag"/{f=1;next} f&&/{{- end }}/{exit} f' "$HELPERS_TPL")"
if [[ -z "$helper_body" ]]; then
    fail "no 'hearth.imageTag' definition in ${HELPERS_TPL}."
elif [[ "$helper_body" != *'printf "v%s" .Chart.AppVersion'* ]]; then
    fail "the 'hearth.imageTag' default does not carry the 'v' prefix the registry uses.
      Found: ${helper_body}
      A default render must produce v<appVersion>, e.g. v${crate_version}, because
      the Docker workflow publishes only v-prefixed semver tags."
fi

# 2. An in-repo render must not name a version that is not shipping.
if [[ -n "$app_version" && -n "$crate_version" && "$app_version" != "$crate_version" ]]; then
    fail "Chart appVersion ${app_version} does not match the crate version ${crate_version}.
      A default render would point at an image built from a different commit."
fi

# 3. The publish workflow stamps --version and --app-version from one tag, so a
#    divergence in the committed chart is a claim that cannot come true.
if [[ -n "$chart_version" && -n "$app_version" && "$chart_version" != "$app_version" ]]; then
    fail "Chart version ${chart_version} does not match appVersion ${app_version}.
      The publish workflow sets both from the release tag; keep them equal in-repo."
fi

# 4. The tag form the chart depends on must actually be published.
if ! grep -q 'type=semver,pattern=v{{version}}' "$DOCKER_WORKFLOW"; then
    fail "${DOCKER_WORKFLOW} does not publish a v-prefixed semver tag
      (expected 'type=semver,pattern=v{{version}}'). The chart's default tag
      would name an image that is never pushed."
fi

if [[ "$failures" -ne 0 ]]; then
    echo ""
    echo "${failures} chart image-tag problem(s) found."
    exit 1
fi

echo "OK: the chart's default image tag is v${app_version}, a tag ${DOCKER_WORKFLOW} publishes."
exit 0
