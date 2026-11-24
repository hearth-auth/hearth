#!/usr/bin/env bash
# The order of `authentik.sh up` (#913), with a fake docker and curl (no
# container, no network). At its first start Authentik applies its own
# blueprints in the worker, each in one transaction, and the server's and the
# worker's start both queue a blueprint discovery, so the same blueprints are
# applied twice; with the worker's 2 threads two of them overlapped, PostgreSQL
# found a deadlock (flow-oobe.yaml and flow-default-authentication-flow.yaml
# both update the stages default-authentication-login and
# default-password-change-write) and a blueprint stayed in `error`: about 1 in
# 2 fresh starts failed, and a seed failure stops the whole AWS session.
# Checks:
#   - the worker starts alone, with 1 thread, and the server and the worker's
#     usual 2 threads only after every blueprint is applied and no blueprint
#     task is left (so the blueprints are applied one at a time)
#   - the server starts once (after tls.yaml, so it serves the run's leaf at its
#     start): no restart
#   - compose.yaml: the worker's threads come from AK_WORKER_THREADS, 2 (the
#     default) unless `up` sets it; the server has no such setting
#   - a blueprint in `error` stops `up` at once, naming it, and the server is not
#     started
#   - a ramp (realm.done in the bundle) starts the same way and writes no realm
# No secret is printed.
#
# Usage: bash loadtest/compare/authentik/test_up.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

mkdir -p "$tmp/bin"
# docker: logs each compose command (with the worker threads it was given) to
# $FAKE_LOG; answers up's SQL from FAKE_STATE (the blueprints: busy, failed or
# done) and FAKE_ERROR (the blueprints not applied).
cat > "$tmp/bin/docker" << 'EOF'
#!/usr/bin/env bash
args=("$@")
# Drop "compose -f <file> --env-file <file>".
[ "${args[0]}" = compose ] && args=("${args[@]:5}")
case "${args[0]}" in
  exec)
    q=${args[-1]}
    printf 'sql %s\n' "$(tr -s ' \n' ' ' <<< "$q" | cut -c1-80)" >> "$FAKE_LOG"
    case $q in
      *CASE*) printf '%s\n' "${FAKE_STATE:-done}" ;;
      *"<> 'successful'"*) [ -z "${FAKE_ERROR:-}" ] || printf '%s\n' "$FAKE_ERROR" ;;
      *count*) echo 0 ;;
    esac
    ;;
  *) printf 'compose threads=%s %s\n' "${AK_WORKER_THREADS:-}" "${args[*]}" >> "$FAKE_LOG" ;;
esac
exit 0
EOF
# curl: the server answers with the run's leaf.
printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/curl"
chmod 0755 "$tmp/bin/docker" "$tmp/bin/curl"

# A bundle `up` keeps as it is (no tls.sh, no realm.py: realm.done).
bundle() {
  local b=$tmp/$1
  mkdir -p "$b/tls"
  chmod 0700 "$b"
  printf 'DB_PASSWORD=x\nAUTHENTIK_SECRET_KEY=x\nBOOTSTRAP_TOKEN=x\nADMIN_EMAIL=x\nADMIN_PASSWORD_HASH=x\n' > "$b/server.env"
  printf 'PRODUCT=authentik\nSTRESS_LOGIN_USERS=0\n' > "$b/generator.env"
  touch "$b/realm.done"
  echo "$b"
}

# Runs `up` with the fakes; its log goes to $tmp/<name>.log, its output to
# $tmp/<name>.out.
up() {
  local name=$1 b
  shift
  b=$(bundle "$name")
  : > "$tmp/$name.log"
  env "$@" PATH="$tmp/bin:$PATH" FAKE_LOG="$tmp/$name.log" BUNDLE="$b" \
    timeout 30 bash "$here/authentik.sh" up < /dev/null > "$tmp/$name.out" 2>&1 && return 0
  echo "exit $? (124: still waiting after 30 s)" >> "$tmp/$name.out"
  return 1
}

# The line number of the first log line that matches (empty: none).
at() { grep -n -m1 -E -- "$2" "$tmp/$1.log" | cut -d: -f1 || true; }

if up fresh; then
  first=$(grep -m1 '^compose .* up ' "$tmp/fresh.log")
  done_at=$(at fresh '^sql .*CASE')
  server_at=$(at fresh '^compose threads= .*up -d$|^compose threads=(2)? .*up -d .*server')
  case $first in
    "compose threads=1 up -d worker") pass "the worker starts alone with 1 thread" ;;
    *) fail "the first start is '$first', not the worker alone with 1 thread" ;;
  esac
  if [ -n "$done_at" ] && [ -n "$server_at" ] && [ "$done_at" -lt "$server_at" ]; then
    pass "the server and the worker's 2 threads start after the blueprints are applied"
  else
    fail "the server and the worker's 2 threads do not start after the blueprints are applied (log: blueprints checked at line ${done_at:-never}, server at ${server_at:-never})"
  fi
  if grep -q 'restart' "$tmp/fresh.log"; then
    fail "up restarts a container"
  else
    pass "up restarts no container"
  fi
else
  fail "up failed: $(tail -n 3 "$tmp/fresh.out")"
fi

# compose.yaml: the worker's threads, and the server has none.
worker=$(sed -n '/^  worker:/,/^  [a-z]*:$/p' "$here/compose.yaml")
server=$(sed -n '/^  server:/,/^  worker:/p' "$here/compose.yaml" | grep -v '^ *#')
# shellcheck disable=SC2016 # the text of compose.yaml, not expanded
if grep -qF 'AUTHENTIK_WORKER__THREADS: ${AK_WORKER_THREADS:-2}' <<< "$worker" &&
  ! grep -q 'THREADS' <<< "$server"; then
  pass "compose.yaml: the worker's threads are AK_WORKER_THREADS, 2 by default"
else
  fail "compose.yaml: the worker has no AUTHENTIK_WORKER__THREADS: \${AK_WORKER_THREADS:-2}, or the server has a threads setting"
fi

start=$(date +%s)
if up error FAKE_STATE=failed 'FAKE_ERROR=default/flow-oobe.yaml (error)'; then
  fail "up passed with a blueprint in error"
elif ! grep -q 'default/flow-oobe.yaml' "$tmp/error.out"; then
  fail "up failed with a blueprint in error, but did not name it: $(tail -n 2 "$tmp/error.out")"
elif grep -qE '^compose .*up -d$|^compose .*up -d .*server' "$tmp/error.log"; then
  fail "up started the server with a blueprint in error"
elif [ $(($(date +%s) - start)) -gt 10 ]; then
  fail "up took $(($(date +%s) - start)) s to stop on a blueprint in error"
else
  pass "a blueprint in error stops up at once, named, before the server starts"
fi

if up ramp && [ "$(grep -m1 '^compose .* up ' "$tmp/ramp.log")" = "compose threads=1 up -d worker" ] &&
  ! grep -qE 'run --rm' "$tmp/ramp.log"; then
  pass "a ramp (realm.done) starts the same way and applies no realm blueprint"
else
  fail "a ramp (realm.done) does not start the same way: $(tail -n 2 "$tmp/ramp.out")"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all up checks passed"
