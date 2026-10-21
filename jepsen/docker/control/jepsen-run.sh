#!/usr/bin/env bash
# Runs `lein run "$@"` in /jepsen (`jepsen-run unit`: `lein test`, the unit
# tests), then gives the files the run wrote (store/, target/) back to the
# owner of the mounted /jepsen: the container runs as root, the checkout
# belongs to the host user. Exits with lein's status.
set -uo pipefail

cd /jepsen || exit 1
if [ "${1:-}" = unit ]; then
  lein test < /dev/null
else
  lein run "$@" < /dev/null
fi
status=$?
owner=$(stat -c %u:%g /jepsen)
for dir in store target .lein-failures; do
  [ -e "$dir" ] && chown -R "$owner" "$dir"
done
exit "$status"
