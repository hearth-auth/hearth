#!/usr/bin/env bash
# scripts/tests/conformance-oidf.test.sh — tests for scripts/conformance-oidf.sh
# (#639). They need no Docker and no network.
#
# The OIDF run is a release gate, so its guards must be able to go red:
#   * the script refuses dev mode, and a stack that would boot Hearth without
#     TLS, with a KEK in the file, or with a demo seeder;
#   * the verdict is FAIL on any failed condition, on a plan that did not
#     report, and on a runner failure;
#   * a recorded warning decision covers only the properties (or ID token
#     claims) it names, and expected-warnings.json can hold only warnings,
#     each with a decision;
#   * a recorded skip names one test module and has a decision, and a module
#     with a recorded skip that does not skip fails the check;
#   * the per-test browser overrides resolve, and a test is in one group only.
#
# Usage: bash scripts/tests/conformance-oidf.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${SCRIPT_DIR}/conformance-oidf.sh"
STACK="${SCRIPT_DIR}/conformance-oidf"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# expect <name> <want-exit> <want-substring> <command...>
expect() {
    local name="$1" want="$2" substr="$3" out rc
    shift 3
    out="$("$@" 2>&1)"
    rc=$?
    if [[ "$rc" != "$want" ]]; then
        fail "${name}: exit ${rc}, want ${want}"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    if [[ -n "$substr" ]] && ! grep -qF -- "$substr" <<<"$out"; then
        fail "${name}: output does not mention '${substr}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    pass "$name"
}

# stack_copy <name>: a copy of the shipped stack files to break.
stack_copy() {
    local dir="${TMP}/$1"
    cp -r "$STACK" "$dir"
    echo "$dir"
}

echo "== the shipped stack passes =="
expect "shipped stack files" 0 "stack files OK" bash "$SCRIPT" --check-config

echo "== dev mode is refused =="
expect "--dev" 2 "refuses --dev" bash "$SCRIPT" --dev
expect "--dev=true" 2 "refuses --dev" bash "$SCRIPT" --dev=true
expect "--dev after --plan" 2 "refuses --dev" bash "$SCRIPT" --plan basic --dev
d="$(stack_copy dev-command)"
sed -i 's/command: \["serve", "-c", "\/conformance\/hearth.yaml"\]/command: ["serve", "--dev", "-c", "\/conformance\/hearth.yaml"]/' "${d}/compose.yaml"
expect "compose command with --dev" 2 "refuses --dev" \
    env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config
d="$(stack_copy bare-serve)"
sed -i 's/command: \["serve", "-c", "\/conformance\/hearth.yaml"\]/command: ["serve"]/' "${d}/compose.yaml"
expect "compose command without -c" 2 '"serve", "-c"' \
    env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config
d="$(stack_copy entrypoint)"
sed -i 's/^    command: \["serve", "-c", "\/conformance\/hearth.yaml"\]/&\n    entrypoint: ["\/bin\/sh"]/' "${d}/compose.yaml"
expect "compose replaces the entrypoint" 2 "entrypoint" \
    env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config

echo "== production config is enforced =="
d="$(stack_copy no-tls)"
sed -i '/tls_cert_path:/d' "${d}/hearth.yaml"
expect "no TLS certificate" 2 "TLS is off" env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config
d="$(stack_copy commented-tls)"
sed -i 's/^\(  tls_key_path:\)/#\1/' "${d}/hearth.yaml"
expect "TLS key commented out" 2 "TLS is off" env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config
d="$(stack_copy demo)"
printf 'demo:\n  enabled: true\n' >> "${d}/hearth.yaml"
expect "demo seeder" 2 "demo block" env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config
d="$(stack_copy kek-in-file)"
printf 'security:\n  key_encryption_key: "%s"\n' "$(printf '0%.0s' {1..64})" >> "${d}/hearth.yaml"
expect "KEK in the file" 2 "HEARTH_KEK" env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config
d="$(stack_copy no-fsync)"
printf 'storage:\n  fsync: false\n' >> "${d}/hearth.yaml"
expect "fsync off" 2 "fsync" env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config
d="$(stack_copy no-plan)"
rm "${d}/plans/dynamic.json"
expect "missing plan file" 2 "plans/dynamic.json" env OIDF_CONFIG_DIR="$d" bash "$SCRIPT" --check-config

echo "== arguments =="
expect "unknown plan" 2 "unknown plan" bash "$SCRIPT" --plan implicit
expect "unknown argument" 2 "unknown argument" bash "$SCRIPT" --fast

echo "== the verdict =="
# Runner output in the suite's own format (timestamps, colour codes).
ok_line() { printf '2026-11-08 20:24:10 \033[1mOverall totals: ran %s test modules. Conditions: 39 successes, %s failures, 1 warnings. 0.3 seconds\033[0m\n' "$1" "$2"; }
{ ok_line 2 0; } > "${TMP}/pass.log"
expect "one plan, no failure" 0 "PASS" bash "$SCRIPT" --judge "${TMP}/pass.log" --plan config
{ ok_line 2 0; ok_line 40 1; } > "${TMP}/fail.log"
expect "a failed condition" 1 "1 failed conditions" \
    bash "$SCRIPT" --judge "${TMP}/fail.log" --plan config --plan basic
expect "a plan did not report" 1 "1 of 2 plans" \
    bash "$SCRIPT" --judge "${TMP}/pass.log" --plan config --plan basic
{ ok_line 2 0; echo '2026-11-08 20:24:10 ** Exiting with failure - some test modules have unexpected condition failures/warnings **'; } > "${TMP}/warn.log"
expect "an unexpected warning" 1 "unexpected condition" \
    bash "$SCRIPT" --judge "${TMP}/warn.log" --plan config
: > "${TMP}/empty.log"
expect "an empty log" 1 "0 of 1 plans" bash "$SCRIPT" --judge "${TMP}/empty.log" --plan config

echo "== recorded warning decisions =="
printf 'OIDF_USER_PASSWORD=x\nOIDF_CLIENT_SECRET=x\nOIDF_CLIENT2_SECRET=x\n' > "${TMP}/run.env"
mkdir -p "${TMP}/out"
render() { python3 -I "${STACK}/render-plans.py" --config-dir "$1" --env-file "${TMP}/run.env" --out "${TMP}/out" --plans config basic dynamic; }
expect "shipped plans render" 0 "" render "$STACK"
if grep -q 'OIDF_' "${TMP}/out/basic.json"; then fail "basic.json keeps a placeholder"; else pass "placeholders filled"; fi
d="$(stack_copy expected-failure)"
sed -i 's/"expected-result": "warning"/"expected-result": "failure"/' "${d}/expected-warnings.json"
expect "an expected failure is refused" 1 "warnings only" render "$d"
d="$(stack_copy no-decision)"
python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); [e.pop("decision") for e in d]; json.dump(d, open(p, "w"))' "${d}/expected-warnings.json"
expect "a warning with no decision is refused" 1 "no decision" render "$d"
d="$(stack_copy skip-no-decision)"
python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); [e.pop("decision") for e in d]; json.dump(d, open(p, "w"))' "${d}/expected-skips.json"
expect "a skip with no decision is refused" 1 "has no decision" render "$d"
d="$(stack_copy skip-pattern)"
python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d[0]["test-name"]="oidcc-*"; json.dump(d, open(p, "w"))' "${d}/expected-skips.json"
expect "a skip for a pattern is refused" 1 "one test module" render "$d"

echo "== per-test browser overrides =="
render "$STACK" >/dev/null 2>&1
if python3 -I - "${TMP}/out/basic.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
steps = doc["override"]["oidcc-response-type-missing"]["browser"][0]["tasks"]
assert steps[0]["task"] == "Login", steps[0]
assert steps[1]["task"] == "Expect the error page", steps[1]
assert "${OIDF_" not in json.dumps(doc["override"]), "a placeholder is left in the overrides"
PY
then pass "overrides resolve @task: and fill placeholders"; else fail "overrides do not resolve"; fi
d="$(stack_copy override-unknown-task)"
sed -i 's/"@task:Consent"/"@task:No such task"/' "${d}/plans/overrides.json"
expect "an override names an unknown task" 1 "unknown task" render "$d"
d="$(stack_copy override-twice)"
python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["reauthentication"]["tests"].append(d["error_page"]["tests"][0]); json.dump(d, open(p, "w"))' "${d}/plans/overrides.json"
expect "a test in two override groups" 1 "two override groups" render "$d"

# export_zip <file> <property...>: one exported plan with one metadata warning.
export_zip() {
    local zip="$1"; shift
    python3 -I - "$zip" "$@" <<'EOF'
import json, sys, zipfile
zip_path, props = sys.argv[1], sys.argv[2:]
log = {"testInfo": {"testName": "oidcc-discovery-endpoint-verification", "result": "WARNING"},
       "results": [{"src": "GetDynamicServerConfiguration", "result": "SUCCESS"},
                   {"src": "CheckForUnexpectedParametersInServerMetadata", "result": "WARNING",
                    "msg": "Unknown properties", "unknown_properties": [{"property": p} for p in props]}]}
with zipfile.ZipFile(zip_path, "w") as z:
    z.writestr("test-log-oidcc-discovery-endpoint-verification-x.json", json.dumps(log))
EOF
}
mkdir -p "${TMP}/export-ok" "${TMP}/export-extra"
export_zip "${TMP}/export-ok/oidcc-config-certification-test-plan--x.zip" resource_indicators_supported
export_zip "${TMP}/export-extra/oidcc-config-certification-test-plan--x.zip" resource_indicators_supported new_unregistered_name
expect "warning names only the decided property" 0 "WARNING 1" \
    python3 -I "${STACK}/check-export.py" --export "${TMP}/export-ok" --expected "${STACK}/expected-warnings.json" --expected-skips "${STACK}/expected-skips.json"
expect "warning names a property with no decision" 1 "new_unregistered_name" \
    python3 -I "${STACK}/check-export.py" --export "${TMP}/export-extra" --expected "${STACK}/expected-warnings.json" --expected-skips "${STACK}/expected-skips.json"

# module_zip <file> <test-name> <result> [claim...]: one exported module.
module_zip() {
    python3 -I - "$@" <<'PY'
import json, sys, zipfile
zip_path, name, result, claims = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
log = {"testInfo": {"testName": name, "result": result},
       "results": [{"src": "EnsureIdTokenDoesNotContainNonRequestedClaims", "result": "WARNING",
                    "msg": f"id_token contains non-requested claim '{c}'"} for c in claims]}
with zipfile.ZipFile(zip_path, "w") as z:
    z.writestr(f"test-log-{name}-x.json", json.dumps(log))
PY
}
check() {
    python3 -I "${STACK}/check-export.py" --export "$1" \
        --expected "${STACK}/expected-warnings.json" --expected-skips "${STACK}/expected-skips.json"
}
first_skip() { python3 -I -c 'import json,sys; e=json.load(open(sys.argv[1]))[0]; print(e["test-name"] if sys.argv[2] == "name" else e["configuration-filename"].split("/")[-1][:-5])' "${STACK}/expected-skips.json" "$1"; }
skip_name="$(first_skip name)"
skip_plan="$(first_skip plan)"
mkdir -p "${TMP}/export-skip" "${TMP}/export-skip-failed" "${TMP}/export-claims" "${TMP}/export-claim-extra"
module_zip "${TMP}/export-skip/oidcc-${skip_plan}-certification-test-plan-x.zip" "$skip_name" SKIPPED
module_zip "${TMP}/export-skip-failed/oidcc-${skip_plan}-certification-test-plan-x.zip" "$skip_name" FAILED
expect "a recorded skip that skips" 0 "SKIPPED 1" check "${TMP}/export-skip"
expect "a recorded skip that fails" 1 "records a skip" check "${TMP}/export-skip-failed"
module_zip "${TMP}/export-claims/oidcc-basic-certification-test-plan-x.zip" oidcc-server WARNING token_type tid scope
module_zip "${TMP}/export-claim-extra/oidcc-basic-certification-test-plan-x.zip" oidcc-server WARNING token_type address
expect "ID token claims with a decision" 0 "WARNING 3" check "${TMP}/export-claims"
expect "an ID token claim with no decision" 1 "the claim address" check "${TMP}/export-claim-extra"
mkdir -p "${TMP}/export-none"
expect "no export at all" 1 "no exported plan results" \
    python3 -I "${STACK}/check-export.py" --export "${TMP}/export-none" --expected "${STACK}/expected-warnings.json" --expected-skips "${STACK}/expected-skips.json"

echo
if [[ "$failures" -gt 0 ]]; then
    echo "conformance-oidf.test.sh: ${failures} failed"
    exit 1
fi
echo "conformance-oidf.test.sh: all passed"
