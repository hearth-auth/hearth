#!/usr/bin/env bash
# Runs `lein run "$@"` in /jepsen, then gives the files the run wrote (store/,
# target/) back to the owner of the mounted /jepsen: the container runs as
# root, the checkout belongs to the host user. Exits with lein's status.
set -uo pipefail

cd /jepsen || exit 1
lein run "$@" < /dev/null
status=$?
owner=$(stat -c %u:%g /jepsen)
for dir in store target .lein-failures; do
  [ -e "$dir" ] && chown -R "$owner" "$dir"
done
exit "$status"
