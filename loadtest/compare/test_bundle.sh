#!/usr/bin/env bash
# The bundle of each product script (#913): `<product>.sh bundle` runs the
# same make_bundle as `up`, without Docker. Checks, for Keycloak, Zitadel, Ory
# and Authentik:
#   - no directory (local use): the bundle is made
#   - an empty directory, as remote.sh data-new leaves /data/bundle on a seed
#     server: the bundle is made in it (the first AWS session's Ory seed found
#     /data/bundle empty and stopped: no server.env)
#   - a whole bundle, as remote.sh restore copies /pristine/bundle on a ramp
#     server: it stays as it is (its passwords match the seeded store)
# No secret is printed.
#
# Usage: bash loadtest/compare/test_bundle.sh
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

# Runs `<product>.sh bundle` with BUNDLE=$2; its output goes to $tmp/<name>.out.
run_bundle() {
  local p=$1 dir=$2 name=$3
  if BUNDLE=$dir bash "$here/$p/$p.sh" bundle < /dev/null > "$tmp/$name.out" 2>&1; then return 0; fi
  # The scripts print no secret; tls.sh and the scripts' own messages only.
  echo "--- $p bundle in $name failed:"
  tail -n 5 "$tmp/$name.out"
  return 1
}

# A bundle the product's `up` can use: the env files, the CA and the TLS leaf,
# the directory owner-only.
whole() {
  local p=$1 dir=$2 f
  for f in server.env generator.env ca.crt tls/https.crt tls/https.key; do
    [ -s "$dir/$f" ] || { echo "$f is missing"; return 1; }
  done
  grep -qx "PRODUCT=$p" "$dir/generator.env" || { echo "generator.env has no PRODUCT=$p"; return 1; }
  [ "$(stat -c %a "$dir")" = 700 ] || { echo "mode $(stat -c %a "$dir"), not 700"; return 1; }
}

# Every file's path, mode, size, mtime and content hash, compared, not printed.
state() { (cd "$1" && find . -printf '%p %m %s %T@\n' | sort && find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum; }

for p in keycloak zitadel ory authentik; do
  new=$tmp/$p-new why=""
  if run_bundle "$p" "$new" "$p-new" && why=$(whole "$p" "$new"); then
    pass "$p: a bundle in a new directory"
  else
    fail "$p: a bundle in a new directory: ${why:-bundle failed}"
  fi

  empty=$tmp/$p-empty
  mkdir -p "$empty"
  chmod 0700 "$empty"
  why=""
  if run_bundle "$p" "$empty" "$p-empty" && why=$(whole "$p" "$empty"); then
    pass "$p: a bundle in an empty directory (a seed server's /data/bundle)"
  else
    fail "$p: a bundle in an empty directory (a seed server's /data/bundle): ${why:-bundle failed}"
  fi

  [ -s "$new/server.env" ] || continue
  copy=$tmp/$p-copy
  cp -a "$new" "$copy"
  before=$(state "$copy")
  if run_bundle "$p" "$copy" "$p-copy" && [ "$(state "$copy")" = "$before" ]; then
    pass "$p: a whole bundle (a ramp server's copy of /pristine/bundle) stays as it is"
  else
    fail "$p: a whole bundle (a ramp server's copy of /pristine/bundle) changed"
  fi
done

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all bundle checks passed"
