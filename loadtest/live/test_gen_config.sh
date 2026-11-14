#!/usr/bin/env bash
# Tests for gen-config.sh's REALMS setting (#647 round B: 1M users in 10 realms).
#
#   case 1  REALMS unset: hearth.yaml, hearth.env and generator.env are byte-identical
#           to testdata/gen-config-realms-1/, which the gen-config.sh of main wrote
#           before REALMS existed (round A and C bundles must not change)
#   case 2  REALMS=1: the same bytes
#   case 3  REALMS=3: three realms (stress, stress2, stress3), each with the same
#           clients and seed users; generator.env names each realm's client IDs
#           (UUID v5 of "<realm>/<key>") and API secret, and keeps realm 1's lines
#   case 4  REALMS=0 and REALMS=x are refused
#
# testdata/bin/openssl stands in for openssl, so the secrets are the same on each run.
#
# Usage: bash loadtest/live/test_gen_config.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
golden=$here/testdata/gen-config-realms-1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

# Runs gen-config.sh with the fake openssl. $1: output dir; the rest: env assignments.
gen() {
  local out=$1
  shift
  env -u REALMS "$@" PATH="$here/testdata/bin:$PATH" FAKE_OPENSSL_STATE="$out.n" \
    bash "$here/gen-config.sh" "$out" 10.0.0.5 3 2> "$out.err"
}

same_as_golden() {
  local label=$1 out=$2 f
  for f in server/hearth.yaml server/hearth.env generator.env; do
    if cmp -s "$golden/${f##*/}" "$out/$f"; then
      pass "$label: $f is byte-identical to main's"
    else
      fail "$label: $f differs from main's:"
      diff -u "$golden/${f##*/}" "$out/$f" | head -n 20
    fi
  done
}

uuid5() {
  python3 -c 'import sys, uuid; print(uuid.uuid5(uuid.UUID("8b074e8c-3e6a-5a8e-961d-8f2baae71bf4"), sys.argv[1]))' "$1"
}

# The lines of realm $2's block in hearth.yaml $1, without its first line.
realm_block() {
  awk -v key="  $2:" '
    $0 == key { on = 1; next }
    on && /^  [^ ]/ { on = 0 }
    on { print }' "$1"
}

# case 1 and 2
if gen "$tmp/unset"; then same_as_golden "REALMS unset" "$tmp/unset"; else
  fail "REALMS unset: gen-config.sh failed: $(cat "$tmp/unset.err")"
fi
if gen "$tmp/one" REALMS=1; then same_as_golden "REALMS=1" "$tmp/one"; else
  fail "REALMS=1: gen-config.sh failed: $(cat "$tmp/one.err")"
fi

# case 3
if gen "$tmp/three" REALMS=3; then
  yaml=$tmp/three/server/hearth.yaml
  genv=$tmp/three/generator.env
  realms=$(sed -n '/^realms:$/,$p' "$yaml" | grep -E '^  [^ ]' | tr -d ' :' | tr '\n' ' ')
  [ "$realms" = "stress stress2 stress3 " ] && pass "REALMS=3: realms are stress stress2 stress3" \
    || fail "REALMS=3: realms are '$realms', want 'stress stress2 stress3 '"
  first=$(realm_block "$yaml" stress)
  [ "$first" = "$(realm_block "$golden/hearth.yaml" stress)" ] \
    && pass "REALMS=3: realm stress is the one-realm block" \
    || fail "REALMS=3: realm stress differs from the one-realm block"
  for r in stress2 stress3; do
    [ "$(realm_block "$yaml" "$r")" = "$first" ] && pass "REALMS=3: $r has the same clients and seed users" \
      || fail "REALMS=3: $r's block differs from stress's"
  done
  n=$(grep -c '^      - email: "user' "$yaml")
  [ "$n" = 9 ] && pass "REALMS=3: 3 login users in each realm" || fail "REALMS=3: $n login users, want 9"
  # Realm 1's lines come first and are unchanged.
  if head -n "$(wc -l < "$golden/generator.env")" "$genv" | cmp -s - "$golden/generator.env"; then
    pass "REALMS=3: generator.env starts with the one-realm lines"
  else
    fail "REALMS=3: generator.env does not start with the one-realm lines"
  fi
  secret=$(sed -n 's/^STRESS_API_SECRET=//p' "$genv")
  want="STRESS_REALMS=3"
  for k in 2 3; do
    want+=$'\n'"STRESS_REALM_$k=stress$k"
    want+=$'\n'"STRESS_APP_CLIENT_ID_$k=$(uuid5 "stress$k/app")"
    want+=$'\n'"STRESS_API_CLIENT_ID_$k=$(uuid5 "stress$k/api")"
    want+=$'\n'"STRESS_API_SECRET_$k=$secret"
  done
  got=$(tail -n +"$(($(wc -l < "$golden/generator.env") + 1))" "$genv")
  if [ "$got" = "$want" ]; then
    pass "REALMS=3: generator.env names realms 2 and 3, their client IDs and API secrets"
  else
    fail "REALMS=3: generator.env's realm lines:"
    diff -u <(echo "$want") <(echo "$got")
  fi
  ids=$(grep -E '^STRESS_(APP|API)_CLIENT_ID' "$genv" | cut -d= -f2 | sort -u | wc -l)
  [ "$ids" = 6 ] && pass "REALMS=3: 6 distinct client IDs" || fail "REALMS=3: $ids distinct client IDs, want 6"
  cmp -s "$golden/hearth.env" "$tmp/three/server/hearth.env" && pass "REALMS=3: hearth.env unchanged" \
    || fail "REALMS=3: hearth.env differs from the one-realm file"
else
  fail "REALMS=3: gen-config.sh failed: $(cat "$tmp/three.err")"
fi

# case 4
for bad in 0 x; do
  gen "$tmp/bad-$bad" REALMS=$bad
  rc=$?
  [ "$rc" = 2 ] && pass "REALMS=$bad: refused (exit 2)" || fail "REALMS=$bad: exit $rc, want 2"
done

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
