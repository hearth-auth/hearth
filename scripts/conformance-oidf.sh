#!/usr/bin/env bash
# scripts/conformance-oidf.sh — run the OpenID Foundation (OIDF) conformance
# suite against a production-mode Hearth (#639, OpenSpec change
# trusted-core-confidence, tasks 2.1-2.6).
#
# The stack is the suite's own docker-compose-prebuilt.yml at a pinned tag,
# plus scripts/conformance-oidf/compose.yaml: Hearth runs `serve -c` with TLS,
# a real KEK and a real host key, on the suite's Docker network. The suite's
# own runner (scripts/run-test-plan.py) drives each plan headless, with the
# browser steps in scripts/conformance-oidf/plans/browser.json.
#
# Usage:
#   scripts/conformance-oidf.sh [--plan config|basic|dynamic|all]... [options]
#
# Options:
#   --plan NAME      Plan to run. Repeat it for more plans. Default: all.
#   --image IMAGE    Hearth image to test (for example a release image).
#                    Default: build the working tree as hearth-oidf:local.
#   --results DIR    Where to put the run log, the summary and the suite's
#                    export. Default: target/conformance-oidf/<timestamp>.
#   --keep           Do not stop the stack at the end (to read the suite UI
#                    at https://localhost.emobix.co.uk:${OIDF_HOST_PORT:-8443}).
#   --down           Stop a stack that --keep left up, and exit.
#   --check-config   Check the stack files and exit. Needs no Docker.
#   --judge LOG      Judge a saved runner log and exit. Needs no Docker.
#
# Exit codes: 0 every plan passed (no failed condition, no warning without a
# recorded decision); 1 a plan failed or did not complete; 2 usage or
# configuration error (this includes a request for dev mode).
#
# Environment: OIDF_SUITE_DIR (suite checkout cache, default
# ${XDG_CACHE_HOME:-$HOME/.cache}/hearth/oidf-suite/<tag>), OIDF_HOST_PORT
# (suite UI port on 127.0.0.1, default 8443), OIDF_CONFIG_DIR (stack files,
# default scripts/conformance-oidf; the self-test points it at bad copies),
# OIDF_MAX_CONSECUTIVE_FAILURES (the runner stops a plan after this many test
# modules in a row do not finish; default 3; raise it to see every module of
# a broken run).
#
# Warnings: the runner treats a warning as a failure unless
# scripts/conformance-oidf/expected-warnings.json lists it. Each entry there
# is a decision recorded in the run report (reports/oidf-conformance-*.md).
# Add an entry only with a reason in that report. The same applies to a
# skipped test module and scripts/conformance-oidf/expected-skips.json: a
# recorded skip must name one module, and its result must be SKIPPED.

set -euo pipefail

# ── Pins ─────────────────────────────────────────────────────────────────────
# The suite tag and the commit it must resolve to. Bump both together, and
# re-run every plan in the same PR.
SUITE_TAG="release-v5.3.4"
SUITE_COMMIT="23353b36957d6466010de767c812d2c91ed37638"
SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"
MONGODB_IMAGE="mongo:6.0.13"
PROJECT="hearth-oidf"

# The plan names and the runner arguments for each. Hearth supports only
# response_type=code, so Implicit OP and Hybrid OP are out (design decision 2).
declare -A PLAN_ARGS=(
    [config]="oidcc-config-certification-test-plan"
    [basic]="oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
    [dynamic]="oidcc-dynamic-certification-test-plan[response_type=code]"
)
PLAN_ORDER=(config basic dynamic)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${OIDF_CONFIG_DIR:-${REPO_ROOT}/scripts/conformance-oidf}"
SUITE_DIR="${OIDF_SUITE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/hearth/oidf-suite/${SUITE_TAG}}"

die()  { echo "conformance-oidf: $*" >&2; exit 2; }
info() { echo "conformance-oidf: $*"; }

# ── Configuration checks (no Docker) ─────────────────────────────────────────

# check_config: the stack must test a production-mode Hearth. Refuse a
# command or a config that would put it in dev mode, or that drops TLS or the
# KEK. Pure text checks, so the self-test can run them anywhere.
check_config() {
    local compose="${CONFIG_DIR}/compose.yaml" yaml="${CONFIG_DIR}/hearth.yaml" f
    for f in "$compose" "$yaml" "${CONFIG_DIR}/runner.Dockerfile" "${CONFIG_DIR}/render-plans.py" "${CONFIG_DIR}/check-export.py" \
             "${CONFIG_DIR}/expected-warnings.json" "${CONFIG_DIR}/expected-skips.json" \
             "${CONFIG_DIR}/plans/browser.json" "${CONFIG_DIR}/plans/overrides.json"; do
        [[ -f "$f" ]] || die "missing stack file: ${f}"
    done
    for f in "${PLAN_ORDER[@]}"; do
        [[ -f "${CONFIG_DIR}/plans/${f}.json" ]] || die "missing plan file: plans/${f}.json"
    done

    # The Hearth service command, with comments removed.
    local cmd
    cmd="$(awk '/^  hearth:/{h=1;next} h&&/^  [a-z]/{h=0} h' "$compose" \
        | sed 's/#.*//' | grep -E '^[[:space:]]*(command|entrypoint):' || true)"
    [[ -n "$cmd" ]] || die "compose.yaml: the hearth service has no command"
    if grep -qE -- '--dev\b' <<<"$cmd"; then
        die "compose.yaml: the hearth command asks for dev mode; this script refuses --dev"
    fi
    grep -qE '"serve",[[:space:]]*"-c"' <<<"$cmd" \
        || die "compose.yaml: the hearth command must be [\"serve\", \"-c\", <config>]"
    if grep -qE '^[[:space:]]*entrypoint:' <<<"$cmd"; then
        die "compose.yaml: the hearth service must not replace the image entrypoint"
    fi

    local body
    body="$(sed 's/#.*//' "$yaml")"
    grep -qE '^[[:space:]]+tls_cert_path:[[:space:]]*"?[^"[:space:]]' <<<"$body" \
        || die "hearth.yaml: TLS is off (server.tls_cert_path is not set)"
    grep -qE '^[[:space:]]+tls_key_path:[[:space:]]*"?[^"[:space:]]' <<<"$body" \
        || die "hearth.yaml: TLS is off (server.tls_key_path is not set)"
    if grep -qE '^[[:space:]]*demo:' <<<"$body"; then
        die "hearth.yaml: a demo block is not allowed"
    fi
    if grep -qE '^[[:space:]]+fsync:[[:space:]]*false' <<<"$body"; then
        die "hearth.yaml: storage.fsync: false is not allowed"
    fi
    if grep -qE '^[[:space:]]+key_encryption_key:' <<<"$body"; then
        die "hearth.yaml: the KEK must come from HEARTH_KEK (a fresh value each run), not the file"
    fi
}

# ── Judging ──────────────────────────────────────────────────────────────────

# judge_log LOG EXPECTED_PLANS RUNNER_RC: decide the verdict from the runner's
# own output. The runner already exits non-zero on an unexpected failure or
# warning. This check adds two things it does not do: every requested plan
# must report its totals, and no condition may fail at all.
judge_log() {
    local raw="$1" want="$2" rc="$3" log totals failures bad=0
    # The runner colours its output. Judge the plain text.
    log="$(mktemp)"
    sed 's/\x1b\[[0-9;]*m//g' "$raw" > "$log"
    totals="$(grep -cE 'Overall totals: ran [0-9]+ test modules' "$log" || true)"
    if [[ "$totals" -lt "$want" ]]; then
        echo "FAIL: ${totals} of ${want} plans reported totals (a plan did not run)"
        bad=1
    fi
    failures="$(grep -oE 'Conditions: [0-9]+ successes, [0-9]+ failures' "$log" \
        | awk '{s += $4} END {print s + 0}')"
    if [[ "$failures" -gt 0 ]]; then
        echo "FAIL: ${failures} failed conditions"
        bad=1
    fi
    if grep -qE 'did not run to completion|Exiting with failure' "$log"; then
        echo "FAIL: the runner reports: $(grep -m1 -oE '\*\* Exiting with failure[^*]*' "$log" || echo 'incomplete tests')"
        bad=1
    fi
    if [[ "$rc" -ne 0 ]]; then
        echo "FAIL: the runner exited ${rc}"
        bad=1
    fi
    rm -f "$log"
    if [[ "$bad" -eq 0 ]]; then
        echo "PASS: ${totals} plans, 0 failed conditions, every warning has a recorded decision"
    fi
    return "$bad"
}

# ── Arguments ────────────────────────────────────────────────────────────────

plans=()
image=""
results=""
keep=0
mode="run"
judge_file=""
for arg in "$@"; do
    # Refuse dev mode in any spelling, before anything else runs.
    case "$arg" in
        --dev|--dev=*) die "refuses --dev: the suite must test a production-mode Hearth (serve -c, TLS, real KEK)" ;;
    esac
done
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plan)
            [[ $# -ge 2 ]] || die "--plan needs a value"
            case "$2" in
                all) plans=("${PLAN_ORDER[@]}") ;;
                config|basic|dynamic) plans+=("$2") ;;
                *) die "unknown plan: $2 (use config, basic, dynamic or all)" ;;
            esac
            shift 2 ;;
        --image) [[ $# -ge 2 ]] || die "--image needs a value"; image="$2"; shift 2 ;;
        --results) [[ $# -ge 2 ]] || die "--results needs a value"; results="$2"; shift 2 ;;
        --keep) keep=1; shift ;;
        --down) mode="down"; shift ;;
        --check-config) mode="check"; shift ;;
        --judge) [[ $# -ge 2 ]] || die "--judge needs a value"; mode="judge"; judge_file="$2"; shift 2 ;;
        -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ ${#plans[@]} -gt 0 ]] || plans=("${PLAN_ORDER[@]}")
# Remove duplicates, keep the order.
declare -A seen=()
uniq_plans=()
for p in "${plans[@]}"; do
    [[ -n "${seen[$p]:-}" ]] || { uniq_plans+=("$p"); seen[$p]=1; }
done
plans=("${uniq_plans[@]}")

if [[ "$mode" == "judge" ]]; then
    [[ -f "$judge_file" ]] || die "no such log: ${judge_file}"
    judge_log "$judge_file" "${#plans[@]}" 0
    exit $?
fi

if [[ "$mode" == "down" ]]; then
    # Compose needs a value for each required variable, also to stop a stack.
    OIDF_RUN_DIR=/nonexistent OIDF_CONFIG_DIR="$CONFIG_DIR" OIDF_SUITE_DIR="$SUITE_DIR" \
    HEARTH_IMAGE=none IMAGE_TAG="$SUITE_TAG" \
        docker compose -p "$PROJECT" --profile runner \
            -f "${SUITE_DIR}/docker-compose-prebuilt.yml" -f "${CONFIG_DIR}/compose.yaml" \
            down -v --remove-orphans
    exit $?
fi

check_config
if [[ "$mode" == "check" ]]; then
    info "stack files OK (production mode, TLS on, KEK from the environment)"
    exit 0
fi

for tool in docker git openssl python3; do
    command -v "$tool" >/dev/null || die "needs ${tool}"
done

# ── Suite checkout at the pinned tag ─────────────────────────────────────────

if [[ ! -d "${SUITE_DIR}/.git" ]]; then
    info "cloning the suite at ${SUITE_TAG} into ${SUITE_DIR}"
    mkdir -p "$(dirname "$SUITE_DIR")"
    git clone -q --depth 1 --branch "$SUITE_TAG" "$SUITE_REPO" "$SUITE_DIR"
fi
got="$(git -C "$SUITE_DIR" rev-parse HEAD)"
[[ "$got" == "$SUITE_COMMIT" ]] \
    || die "suite checkout ${SUITE_DIR} is at ${got}, want ${SUITE_COMMIT} (${SUITE_TAG})"
[[ -z "$(git -C "$SUITE_DIR" status --porcelain)" ]] \
    || die "suite checkout ${SUITE_DIR} has local changes"

# ── Run directory: TLS, secrets, plan configs ────────────────────────────────

stamp="$(date +%Y%m%d-%H%M%S)"
results="${results:-${REPO_ROOT}/target/conformance-oidf/${stamp}}"
mkdir -p "$results"
results="$(cd "$results" && pwd)"
run_dir="$(mktemp -d "${TMPDIR:-/tmp}/hearth-oidf-XXXXXX")"
# Hearth runs as UID 10001 and reads tls/ through a bind mount, so the run
# directory is traversable. The secrets file (secrets.env) stays owner-only.
chmod 711 "$run_dir"

# compose runs in a subshell: the run's secrets reach compose's environment
# (for the hearth service's `environment:` block) and nothing else.
compose() (
    if [[ -f "${run_dir}/secrets.env" ]]; then
        set -a
        # shellcheck disable=SC1091
        . "${run_dir}/secrets.env"
        set +a
    fi
    OIDF_RUN_DIR="$run_dir" OIDF_CONFIG_DIR="$CONFIG_DIR" OIDF_SUITE_DIR="$SUITE_DIR" \
    HEARTH_IMAGE="$image" IMAGE_TAG="$SUITE_TAG" MONGODB_IMAGE="$MONGODB_IMAGE" \
        docker compose -p "$PROJECT" \
            -f "${SUITE_DIR}/docker-compose-prebuilt.yml" \
            -f "${CONFIG_DIR}/compose.yaml" "$@"
)

cleanup() {
    local rc=$?
    if [[ -n "${image}" ]]; then
        compose logs --no-color hearth > "${results}/hearth.log" 2>&1 || true
        if [[ "$keep" -eq 0 ]]; then
            compose --profile runner down -v --remove-orphans >/dev/null 2>&1 || true
        else
            info "--keep: the stack is still up (stop it with: $0 --down)"
        fi
    fi
    rm -rf "$run_dir"
    exit "$rc"
}
trap cleanup EXIT

mkdir -m 755 "${run_dir}/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=hearth" \
    -addext "subjectAltName=DNS:hearth,DNS:localhost,IP:127.0.0.1" \
    -keyout "${run_dir}/tls/hearth.key" -out "${run_dir}/tls/hearth.crt" 2>/dev/null
# A throwaway key for one run on a private Docker network. Hearth (UID 10001)
# must read it.
chmod 644 "${run_dir}/tls/hearth.key" "${run_dir}/tls/hearth.crt"

# Fresh secrets for each run. They go to secrets.env (owner-only), to the
# hearth container's environment and to the rendered plan configs in the run
# directory. They are never printed.
(
    umask 077
    {
        echo "HEARTH_KEK=$(openssl rand -hex 32)"
        echo "HEARTH_MASTER_KEY=$(openssl rand -hex 32)"
        echo "OIDF_CLIENT_SECRET=$(openssl rand -hex 24)"
        echo "OIDF_CLIENT2_SECRET=$(openssl rand -hex 24)"
        echo "OIDF_USER_PASSWORD=Oidf-$(openssl rand -hex 16)"
    } > "${run_dir}/secrets.env"
)

mkdir -m 755 "${run_dir}/plans" "${run_dir}/export"
python3 -I "${CONFIG_DIR}/render-plans.py" \
    --config-dir "$CONFIG_DIR" --env-file "${run_dir}/secrets.env" --out "${run_dir}/plans" \
    --plans "${plans[@]}"
chmod 644 "${run_dir}"/plans/*.json

# ── Images and stack ─────────────────────────────────────────────────────────

if [[ -z "$image" ]]; then
    image="hearth-oidf:local"
    info "building ${image} from ${REPO_ROOT}"
    docker build -q -t "$image" "$REPO_ROOT" >/dev/null
fi
info "Hearth image: ${image} ($(docker image inspect "$image" --format '{{.Id}}' | cut -c1-19))"

compose --profile runner build -q runner
compose up -d --quiet-pull mongodb server nginx hearth

# Wait for Hearth's realm discovery document and for the suite's API.
compose --profile runner run --rm -T runner python -I -c '
import json, ssl, sys, time, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
targets = {
    "hearth": "https://hearth:8420/realms/conformance/.well-known/openid-configuration",
    "suite": "https://localhost.emobix.co.uk:8443/api/runner/available",
}
deadline = time.time() + 240
for name, url in targets.items():
    while True:
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=5) as r:
                if r.status == 200:
                    print("conformance-oidf: " + name + " is up")
                    break
        except Exception as e:
            last = e
        if time.time() > deadline:
            print("conformance-oidf: " + name + " did not start: " + str(last), file=sys.stderr)
            sys.exit(1)
        time.sleep(2)
' || { info "the stack did not start; see ${results}/hearth.log"; exit 1; }

# ── Run ──────────────────────────────────────────────────────────────────────

runner_args=()
for p in "${plans[@]}"; do
    runner_args+=("${PLAN_ARGS[$p]}" "/run-dir/plans/${p}.json")
done
info "running: ${plans[*]} (suite ${SUITE_TAG})"
log="${results}/runner.log"
set +e
compose --profile runner run --rm -T runner python -u /suite/scripts/run-test-plan.py \
    --export-dir /run-dir/export --verbose \
    --expected-failures-file /run-dir/plans/expected-warnings.json \
    --expected-skips-file /run-dir/plans/expected-skips.json \
    "${runner_args[@]}" > "$log" 2>&1
runner_rc=$?
set -e
rm -rf "${results}/export"; mkdir -p "${results}/export"
cp -r "${run_dir}/export/." "${results}/export/" 2>/dev/null || true

sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -E '(Test \[[0-9]+:[0-9]+\]|Overall totals|Unexpected|Block name|\*\* )' \
    | cut -c21- > "${results}/summary.txt" || true
cat "${results}/summary.txt"
info "results: ${results}"
verdict=0
judge_log "$log" "${#plans[@]}" "$runner_rc" || verdict=1
python3 -I "${CONFIG_DIR}/check-export.py" --export "${results}/export" \
    --expected "${run_dir}/plans/expected-warnings.json" \
    --expected-skips "${run_dir}/plans/expected-skips.json" | tee "${results}/results.txt" \
    || verdict=1
exit "$verdict"
