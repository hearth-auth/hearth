#!/usr/bin/env bash
# scripts/tests/check-systemd-units.test.sh — tests for
# scripts/check-systemd-units.sh (audit 2026-08-28 §4.8#14).
#
# The guard is the deliverable, so it needs a test that proves it FAILS on the
# pre-fix unit — not just that it passes on the fixed one.
#
# The defect: deploy/systemd/hearth.service put StartLimitBurst and
# StartLimitIntervalSec in [Service]. systemd reads both in [Unit] only and
# logs "Unknown key ... ignoring", so the documented "give up after 3 rapid
# restarts in 60 s" bound was never in force — systemd's own 10 s default
# window applied instead.
#
# Usage: bash scripts/tests/check-systemd-units.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-systemd-units.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

# run_case <name> <expected-exit> <unit-file> [expected-substring]
run_case() {
    local name="$1" want="$2" unit="$3" expect="${4:-}" out rc
    out="$(bash "$CHECK" "$unit" 2>&1)"
    rc=$?
    if [[ "$rc" != "$want" ]]; then
        fail "${name}: exit ${rc}, want ${want}"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    if [[ -n "$expect" ]] && ! printf '%s\n' "$out" | grep -qF "$expect"; then
        fail "${name}: output does not mention '${expect}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    pass "$name"
}

echo "== the pre-fix unit fails (the defect) =="
cat > "${TMP}/prefix.service" <<'EOF'
[Unit]
Description=Hearth
After=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/hearth serve
Restart=on-failure
RestartSec=5s
# Give up after 3 rapid restarts in 60 s to avoid runaway crash loops.
StartLimitBurst=3
StartLimitIntervalSec=60

[Install]
WantedBy=multi-user.target
EOF
run_case "StartLimit* in [Service] is caught" \
    1 "${TMP}/prefix.service" "systemd reads it in [Unit] only"

echo "== the fixed unit passes =="
cat > "${TMP}/fixed.service" <<'EOF'
[Unit]
Description=Hearth
After=network-online.target
StartLimitBurst=3
StartLimitIntervalSec=60

[Service]
Type=exec
ExecStart=/usr/local/bin/hearth serve
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
run_case "StartLimit* in [Unit] is accepted" 0 "${TMP}/fixed.service" "OK:"

echo "== a restart policy with no limiter is refused =="
cat > "${TMP}/unbounded.service" <<'EOF'
[Unit]
Description=Hearth

[Service]
ExecStart=/usr/local/bin/hearth serve
Restart=always
EOF
run_case "Restart=always with no StartLimitBurst" \
    1 "${TMP}/unbounded.service" "unbounded"

cat > "${TMP}/half.service" <<'EOF'
[Unit]
Description=Hearth
StartLimitBurst=3

[Service]
ExecStart=/usr/local/bin/hearth serve
Restart=on-failure
EOF
run_case "StartLimitBurst with no interval falls back to systemd's default window" \
    1 "${TMP}/half.service" "default window applies"

echo "== other [Unit]-only directives are caught too =="
cat > "${TMP}/onfailure.service" <<'EOF'
[Unit]
Description=Hearth
StartLimitBurst=3
StartLimitIntervalSec=60

[Service]
ExecStart=/usr/local/bin/hearth serve
Restart=on-failure
OnFailure=hearth-alert.service
EOF
run_case "OnFailure in [Service]" 1 "${TMP}/onfailure.service" "'OnFailure' is in [Service]"

echo "== a unit with no restart policy needs no limiter =="
cat > "${TMP}/oneshot.service" <<'EOF'
[Unit]
Description=One-shot

[Service]
Type=oneshot
ExecStart=/usr/local/bin/prune
EOF
run_case "a oneshot unit passes" 0 "${TMP}/oneshot.service" "OK:"

echo "== comments naming a directive are not configuration =="
cat > "${TMP}/comment.service" <<'EOF'
[Unit]
Description=Hearth
StartLimitBurst=3
StartLimitIntervalSec=60

[Service]
# The crash-loop limiter is StartLimitBurst / StartLimitIntervalSec in [Unit].
ExecStart=/usr/local/bin/hearth serve
Restart=on-failure
EOF
run_case "a [Service] comment mentioning StartLimitBurst" 0 "${TMP}/comment.service" "OK:"

echo "== the shipped units pass =="
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    pass "every unit under deploy/ and scripts/"
else
    fail "a shipped unit does not pass"
    printf '%s\n' "$out" | sed 's/^/         /'
fi

echo
if [[ "$failures" -eq 0 ]]; then
    echo "check-systemd-units: all checks passed"
    exit 0
fi
echo "check-systemd-units: ${failures} check(s) failed"
exit 1
