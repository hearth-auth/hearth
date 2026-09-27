#!/usr/bin/env bash
# Runs a long command (the full test suite, a --workspace build, the load test)
# detached from the calling process, and waits for it without holding it.
#
# Why: Claude Code's background-task monitor stops a background command when
# the host's *free* memory is low. On a build machine most memory is page cache
# from the cargo target dir, which the kernel reclaims on demand, so the
# monitor kills `cargo nextest run --workspace` while tens of GB are still
# available. A command started here is owned by the user's systemd manager
# (or a new session via setsid), not by the caller, so the monitor never sees
# it — and if the waiter is killed, the command keeps running and `wait` can be
# called again. The kernel OOM killer and systemd-oomd still protect the host.
#
# Usage:
#   scripts/run-detached.sh run    <name> -- <command...>   start, then wait
#   scripts/run-detached.sh start  <name> -- <command...>   start; print the id
#   scripts/run-detached.sh wait   <id> [timeout-seconds]   wait; exit with its code
#   scripts/run-detached.sh status <id>                     running | exited <code>
#   scripts/run-detached.sh log    <id>                     print the log path
#
# The command runs in the current directory with the caller's exported
# environment. Output goes to $HEARTH_DETACHED_DIR/<id>.log (default
# ${TMPDIR:-/tmp}/hearth-detached); the exit code to <id>.rc.
set -euo pipefail

DIR="${HEARTH_DETACHED_DIR:-${TMPDIR:-/tmp}/hearth-detached}"
mkdir -p "$DIR"

usage() {
  cat >&2 << 'EOF'
usage: scripts/run-detached.sh run    <name> -- <command...>
       scripts/run-detached.sh start  <name> -- <command...>
       scripts/run-detached.sh wait   <id> [timeout-seconds]
       scripts/run-detached.sh status <id>
       scripts/run-detached.sh log    <id>
EOF
  exit 2
}

start() {
  local name="$1"
  shift
  [[ "${1:-}" == "--" ]] && shift
  [[ $# -gt 0 ]] || usage
  local id
  id="hearth-${name//[^A-Za-z0-9_-]/-}-$(date +%Y%m%d-%H%M%S)-$$"
  local log="$DIR/$id.log" rc="$DIR/$id.rc" envf="$DIR/$id.env" cmdf="$DIR/$id.cmd"
  rm -f "$rc"
  # The caller's exported environment, minus read-only variables a new bash
  # already defines (sourcing those would fail).
  export -p | grep -v '^declare -[a-zA-Z]*r' > "$envf"
  printf '%q ' "$@" > "$cmdf"
  local body
  body="set -a; source $(printf '%q' "$envf"); set +a; cd $(printf '%q' "$PWD");"
  body+=" bash -c \"\$(cat $(printf '%q' "$cmdf"))\" > $(printf '%q' "$log") 2>&1;"
  body+=" echo \$? > $(printf '%q' "$rc")"
  if command -v systemd-run > /dev/null 2>&1 \
     && systemctl --user show-environment > /dev/null 2>&1; then
    systemd-run --user --collect --quiet --unit="$id" bash -c "$body"
  else
    setsid nohup bash -c "$body" > /dev/null 2>&1 < /dev/null &
  fi
  echo "$id"
}

status() {
  local id="$1"
  if [[ -f "$DIR/$id.rc" ]]; then
    echo "exited $(cat "$DIR/$id.rc")"
  else
    echo "running"
  fi
}

wait_for() {
  local id="$1" timeout="${2:-0}" waited=0
  while [[ ! -f "$DIR/$id.rc" ]]; do
    if [[ "$timeout" -gt 0 && "$waited" -ge "$timeout" ]]; then
      echo "still running after ${timeout}s: $id (log: $DIR/$id.log)" >&2
      return 124
    fi
    sleep 5
    waited=$((waited + 5))
  done
  local code
  code="$(cat "$DIR/$id.rc")"
  # nextest / cargo summary lines, so a caller sees the verdict without the log.
  grep -E '^\s+Summary|^error(\[|:)|test result:|FAIL \[' "$DIR/$id.log" | tail -40 || true
  echo "exit $code — log: $DIR/$id.log"
  return "$code"
}

cmd="${1:-}"
shift || true
case "$cmd" in
  run)
    [[ $# -ge 1 ]] || usage
    id="$(start "$@")"
    echo "started $id (log: $DIR/$id.log)" >&2
    wait_for "$id"
    ;;
  start) [[ $# -ge 1 ]] || usage; start "$@" ;;
  wait) [[ $# -ge 1 ]] || usage; wait_for "$@" ;;
  status) [[ $# -eq 1 ]] || usage; status "$1" ;;
  log) [[ $# -eq 1 ]] || usage; echo "$DIR/$1.log" ;;
  *) usage ;;
esac
