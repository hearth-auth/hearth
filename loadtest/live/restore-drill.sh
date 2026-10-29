#!/usr/bin/env bash
# The restore drill (#651) on one Linux host. It runs a production-mode Hearth server,
# imports about 1,000,000 users into one realm, and backs the server up the way
# docs/guides/backup.md tells operators to back up a live server: POST /admin/backup, then
# hearth backup verify and hearth backup sign. It stops the server, restores the archive
# into an empty data directory with hearth backup restore, and starts a server on it with
# the same config ("Restoring to a new node"). restore_drill.py then compares the two
# servers. Each step is timed.
#
# The weekly workflow (.github/workflows/restore-drill.yml) runs it on a GitHub-hosted
# runner. It needs passwordless sudo once: the generated config uses /opt/hearth and
# /var/lib/hearth, as on the AWS server, and both must not exist yet.
#
# Usage: restore-drill.sh <hearth binary> <out dir>
#
# Environment (default):
#   USERS             users to import (1000000)
#   IMPORT_BATCH      users per POST /admin/users/import request (5000)
#   IMPORT_WORKERS    import requests at a time (4)
#   SAMPLE_EVERY      compare every Nth imported user in full (1000)
#   LOGIN_USERS       users with a password, declared as seed_users (3)
#   READY_TIMEOUT_S   the longest start the drill waits for (3600)
#   REQUIRE_WEBHOOKS  1: a webhook subscription that the restore loses fails the drill (0).
#                     Until backups carry webhook subscriptions (#664), a loss is advisory.
#
# The out dir receives summary.md, timings.json, findings.json, compare.txt, before.json,
# after.json, steps.txt, facts.txt, the two server logs and the output of each hearth
# backup command. The archive, the keys and the passwords stay in a private temporary
# directory that the drill deletes. Exit status: 0 when the restored server gives back the
# same data, 1 when it does not, 2 when the drill could not run.
set -euo pipefail

usage="usage: restore-drill.sh <hearth binary> <out dir>"
hearth=$(realpath "${1:?$usage}")
mkdir -p "${2:?$usage}"
out=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")" && pwd)

USERS=${USERS:-1000000}
IMPORT_BATCH=${IMPORT_BATCH:-5000}
IMPORT_WORKERS=${IMPORT_WORKERS:-4}
SAMPLE_EVERY=${SAMPLE_EVERY:-1000}
LOGIN_USERS=${LOGIN_USERS:-3}
READY_TIMEOUT_S=${READY_TIMEOUT_S:-3600}
REQUIRE_WEBHOOKS=${REQUIRE_WEBHOOKS:-0}

for var in USERS IMPORT_BATCH IMPORT_WORKERS SAMPLE_EVERY LOGIN_USERS READY_TIMEOUT_S; do
  if ! [[ ${!var} =~ ^[1-9][0-9]*$ ]]; then
    echo "restore-drill: $var must be a positive integer" >&2
    exit 2
  fi
done

data=/var/lib/hearth/data
: > "$out/steps.txt"
: > "$out/facts.txt"

log() { printf 'restore-drill: %s\n' "$*" >&2; }
drill() { python3 "$here/restore_drill.py" "$@"; }
now() { date +%s.%N; }
# step <name> <start>: the seconds from <start> to now, into steps.txt.
step() {
  printf '%s %s\n' "$1" "$(awk -v a="$2" -v b="$(now)" 'BEGIN { printf "%.3f", b - a }')" \
    >> "$out/steps.txt"
}
fact() { printf '%s %s\n' "$1" "$2" >> "$out/facts.txt"; }
report() {
  drill report --steps "$out/steps.txt" --facts "$out/facts.txt" --json "$out/timings.json" \
    --markdown "$out/summary.md" "$@" || log "the report failed"
}
die() {
  log "FAILED: $*"
  report --status "DID NOT FINISH: $*"
  exit 2
}

for dir in /opt/hearth /var/lib/hearth; do
  [ ! -e "$dir" ] || die "$dir exists; the drill needs a host without a Hearth install"
done

work=$(mktemp -d)
server=
cleanup() {
  [ -z "$server" ] || kill "$server" 2> /dev/null || true
  wait 2> /dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# A hearth CLI command with the server's environment: HEARTH_MASTER_KEY unwraps the
# archive's key and HEARTH_KEK opens the data directory (docs/guides/backup.md).
hearth_cli() {
  (
    set -a
    # shellcheck disable=SC1091
    . /opt/hearth/hearth.env
    set +a
    exec "$hearth" "$@"
  )
}

# start_server <log file>
start_server() {
  (
    set -a
    # shellcheck disable=SC1091
    . /opt/hearth/hearth.env
    set +a
    exec "$hearth" serve --config /opt/hearth/hearth.yaml
  ) > "$1" 2>&1 &
  server=$!
}

ready() {
  curl -fsS -o /dev/null --max-time 4 --cacert /opt/hearth/ca.crt \
    --resolve hearth.stress.test:8443:127.0.0.1 https://hearth.stress.test:8443/readyz 2> /dev/null
}

# wait_ready <log file>: polls /readyz once a second for at most READY_TIMEOUT_S.
wait_ready() {
  local deadline=$((SECONDS + READY_TIMEOUT_S))
  until ready; do
    if ! kill -0 "$server" 2> /dev/null; then
      tail -n 40 "$1" >&2
      return 1
    fi
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 1
  done
}

# stop_server: SIGTERM, then a wait of at most 10 minutes for the exit.
stop_server() {
  local deadline=$((SECONDS + 600))
  kill -TERM "$server"
  while kill -0 "$server" 2> /dev/null; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 1
  done
  wait "$server" 2> /dev/null || true
  server=
}

fact date "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact hearth_version "$("$hearth" --version 2>&1 | head -n 1)"
fact commit "${GITHUB_SHA:-$(git -C "$here" rev-parse HEAD 2> /dev/null || echo unknown)}"
fact cpus "$(nproc)"
fact memory_bytes "$(awk '/^MemTotal:/ { print $2 * 1024 }' /proc/meminfo)"
# restore_drill.py verifies the pre-backup token with openssl.
fact openssl_version "$(openssl version)"
fact users "$USERS"

log "generating a production config ($LOGIN_USERS seed users with a password)"
bash "$here/gen-config.sh" "$work/bundle" 127.0.0.1 "$LOGIN_USERS"
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 /opt/hearth /var/lib/hearth
cp -r "$work/bundle/server/." /opt/hearth/
cp "$work/bundle/ca.crt" /opt/hearth/ca.crt
target=(--target "$work/bundle/generator.env" --ca /opt/hearth/ca.crt)
state=$work/state
mkdir -m 0700 "$state" "$work/archive"
archive=$work/archive/hearth.hearth-backup

# The key that signs the archive, and the verify_key that keygen prints for it (backup.md,
# "Signed archives").
hearth_cli backup keygen --output "$work/backup-signing.pem" > "$out/backup-keygen.txt" 2>&1 \
  || die "hearth backup keygen failed (see backup-keygen.txt)"
verify_key=$(drill verify-key "$out/backup-keygen.txt") \
  || die "no verify_key in the hearth backup keygen output (see backup-keygen.txt)"

log "starting hearth ($hearth)"
t=$(now)
start_server "$out/server-original.log"
wait_ready "$out/server-original.log" || die "the original server is not ready"
step original_start_to_ready "$t"

log "seeding $USERS users ($IMPORT_WORKERS requests of $IMPORT_BATCH at a time)"
t=$(now)
drill seed "${target[@]}" --state "$state" --users "$USERS" --batch "$IMPORT_BATCH" \
  --workers "$IMPORT_WORKERS" --sample-every "$SAMPLE_EVERY" || die "the seeding failed"
step seed "$t"

drill snapshot "${target[@]}" --state "$state" --phase before --out "$out/before.json" \
  || die "the snapshot of the original server failed"

log "backup: POST /admin/backup, hearth backup verify, hearth backup sign"
t=$(now)
drill backup "${target[@]}" --output "$archive" || die "POST /admin/backup failed"
step backup_create "$t"
fact archive_bytes "$(stat -c %s "$archive")"
t=$(now)
hearth_cli backup verify --input "$archive" > "$out/backup-verify.txt" 2>&1 \
  || die "hearth backup verify failed (see backup-verify.txt)"
step backup_verify "$t"
t=$(now)
hearth_cli backup sign --input "$archive" --key-file "$work/backup-signing.pem" \
  > "$out/backup-sign.txt" 2>&1 || die "hearth backup sign failed (see backup-sign.txt)"
step backup_sign "$t"

log "stopping the original server"
t=$(now)
stop_server || die "the original server did not stop within 10 minutes"
step server_stop "$t"
fact data_bytes_before "$(du -sb "$data" | cut -f1)"

# A new node: the same config and an empty data directory (backup.md, "Restoring to a new
# node"). The original data stays on the disk, out of the server's way.
mv "$data" /var/lib/hearth/data-original
install -d -m 0700 "$data"
log "restoring into an empty data directory"
t=$(now)
restore_exit=0
hearth_cli backup restore --input "$archive" --verify-key "$verify_key" --data-dir "$data" \
  > "$out/restore.txt" 2>&1 || restore_exit=$?
step restore "$t"
fact restore_exit "$restore_exit"
fact data_bytes_after "$(du -sb "$data" | cut -f1)"
[ "$restore_exit" -eq 0 ] || log "hearth backup restore exited $restore_exit (see restore.txt)"

log "starting hearth on the restored data"
t=$(now)
start_server "$out/server-restored.log"
wait_ready "$out/server-restored.log" \
  || die "the server on the restored data is not ready (see server-restored.log)"
step restored_start_to_ready "$t"

drill snapshot "${target[@]}" --state "$state" --phase after --out "$out/after.json" \
  || die "the snapshot of the restored server failed"

compare_args=(--token-file "$state/token.json" --restore-exit "$restore_exit"
  --findings "$out/findings.json")
[ "$REQUIRE_WEBHOOKS" != 1 ] || compare_args+=(--require-webhooks)
status=0
drill compare "${compare_args[@]}" "$out/before.json" "$out/after.json" \
  | tee "$out/compare.txt" || status=$?
report --findings "$out/findings.json"
log "exit status $status"
exit "$status"
