#!/usr/bin/env bash
# compare.sh seed hearth keeps the seed's bundle (its config, keys and
# passwords) in the session state, and the ramp runs deploy it with the seeded
# store (#913). A seed that runs again after an earlier attempt failed must
# replace that attempt's bundle whole: `cp -a` into the existing directory put
# the new bundle in hearth-bundle/bundle/, the ramp runs deployed the old
# admin password, and k6 signed in with the new one (401). Checks, with
# DRY_RUN=1 (no AWS, no SSH), three seeds of one session:
#   - the first fails after it saved its bundle (at the store's settle)
#   - the second fails in the middle of the save (the fetch of the
#     generator's generator.env): the saved bundle is still the first's, whole
#   - the third succeeds: the saved bundle is its own, whole, with the
#     generator's generator.env, and no partial copy is left in the state
#
# Usage: bash loadtest/compare/aws/test_seed_bundle.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

mkdir -p "$tmp/repo"
tar -C "$repo" --exclude=.build --exclude=results --exclude=__pycache__ -cf - loadtest/compare loadtest/live \
  | tar -C "$tmp/repo" -xf -
c=$tmp/repo/loadtest/compare/aws/compare.sh
saved=$tmp/repo/loadtest/compare/.build/aws-dryb/hearth-bundle
runs=$tmp/repo/loadtest/live/.build
export SESSION=dryb DRY_RUN=1 DRY_STATE=$tmp/dry AWS_PROFILE=hearth-stress IMAGE=hearth-stress:dry
unset STRESS_RUN AWS_MAX_HOURS AWS_MAX_MINUTES JOURNEYS DRY_FAIL

seed() { bash "$c" seed hearth < /dev/null > "$tmp/$1.out" 2>&1; }
# Whether the saved bundle is seed run $1's whole: the same files with the same
# contents, but generator.env (the generator's copy, fetched).
whole() {
  diff -r -x generator.env "$runs/run-dryb-seed-hearth-$1/bundle" "$saved" > "$tmp/diff" 2>&1 \
    && grep -q '^PRODUCT=dry$' "$saved/generator.env" 2> /dev/null
}
why() { head -n 3 "$tmp/diff" | tr '\n' ' '; }

DRY_FAIL='remote.sh settle' seed seed1 && fail "the first seed did not fail at the settle"
whole 1 && pass "a seed that fails after the save leaves its bundle" || fail "first seed's bundle: $(why)"

DRY_FAIL=':/opt/stress/generator.env' seed seed2 && fail "the second seed did not fail at the generator.env fetch"
cmp -s "$runs/run-dryb-seed-hearth-1/bundle/server/hearth.env" "$runs/run-dryb-seed-hearth-2/bundle/server/hearth.env" \
  && fail "the two seeds' bundles have the same hearth.env: the checks below prove nothing"
whole 1 && pass "a seed that fails in the middle of the save leaves the earlier bundle whole" \
  || fail "after a failed save, the saved bundle is not the first seed's whole: $(why)"

if seed seed3; then
  whole 3 && pass "a seed after failed ones saves its own bundle whole (its hearth.env, the generator's generator.env)" \
    || fail "after a resumed seed, the saved bundle is not its own whole: $(why)"
  left=$(find "$(dirname "$saved")" -mindepth 1 -maxdepth 1 -name 'hearth-bundle?*')
  [ -z "$left" ] && pass "no partial copy of a bundle is left in the state" || fail "left in the state: $left"
else
  fail "the third seed failed: $(grep -v '^DRY' "$tmp/seed3.out" | tail -n 3 | tr '\n' ' ')"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all seed bundle checks passed"
