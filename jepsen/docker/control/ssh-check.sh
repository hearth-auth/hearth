#!/usr/bin/env bash
# Proves the control link (task 1.1): `ssh <node> true` exits 0 on every node.
set -uo pipefail

nodes=${*:-n1 n2 n3 n4 n5}
failed=0
for node in $nodes; do
  if ssh "$node" true; then
    echo "ssh $node true: ok"
  else
    echo "ssh $node true: FAILED (exit $?)" >&2
    failed=1
  fi
done
exit "$failed"
