#!/usr/bin/env bash
# Runs compare.sh end to end with DRY_RUN=1 (#913): no AWS, no SSH, no
# network. The shims in dryrun/ print every AWS call and remote command and
# make up the k6 output, in which every step at DRY_FAIL_RATE (400/s) or more
# is too slow. Checks:
#   - a product's seed: a server-only run with the seed lifetime, the data
#     volume, a snapshot, the seed record, torn down
#   - its size 1 ramps: the ladder (coarse doubling, the first failing step,
#     3 fine steps), the clean rate, "at least" when all 8 coarse steps pass
#   - Hearth's seed and ramp, the cold read's working set
#   - the cost ledger (every instance closed), cost.txt, the $15 stop
#   - snapshot deletion: only the session's own, and only when asked
#
# Usage: bash loadtest/compare/aws/test_dryrun.sh [keep]   (keep: leave the
# temporary tree and print its path)
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
tmp=$(mktemp -d)
[ "${1:-}" = keep ] && echo "tree: $tmp" || trap 'rm -rf "$tmp"' EXIT

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
out=$tmp/repo/loadtest/live/results/compare-dry
state=$tmp/repo/loadtest/compare/.build/aws-dry
export SESSION=dry DRY_RUN=1 DRY_STATE=$tmp/dry AWS_PROFILE=hearth-stress IMAGE=hearth-stress:dry
unset STRESS_RUN AWS_MAX_HOURS AWS_MAX_MINUTES JOURNEYS

step() {
  local name=$1
  shift
  if "$@" < /dev/null > "$tmp/$name.out" 2>&1; then return 0; fi
  echo "--- $name failed; last lines:"
  grep -v '^DRY' "$tmp/$name.out" | tail -n 15
  return 1
}
# A step that is meant to fail: no output.
try() {
  local name=$1
  shift
  "$@" < /dev/null > "$tmp/$name.out" 2>&1
}
jv() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2:]: v=v[k]
print(v)' "$@"; }

# A product's seed.
step seed-keycloak bash "$c" seed keycloak || fail "seed keycloak"
launch=$(awk '/^DRY aws .*run-instances/' "$tmp/seed-keycloak.out")
grep -q -- '--instance-initiated-shutdown-behavior terminate' <<< "$launch" \
  && grep -q 'shutdown, -h, "+68"' "$tmp/seed-keycloak.out" \
  && pass "the seed server terminates itself after its estimate plus 50 % (45 -> 68 min)" \
  || fail "seed launch: $launch"
grep -q 'DeviceName=/dev/sdf,Ebs={VolumeSize=40' <<< "$launch" && pass "the seed server gets the data volume" \
  || fail "no data volume on the seed server"
[ "$(grep -c 'run-instances' <<< "$launch")" = 1 ] && pass "a seed runs on the server alone" || fail "seed launched generators"
grep -q 'DRY ssh .*remote.sh product keycloak seed 0 1000000' "$tmp/seed-keycloak.out" \
  && pass "the seed goes through keycloak.sh seed" || fail "no keycloak.sh seed call"
grep -q 'DRY aws .*create-snapshot --volume-id vol-0dry0000000000001' "$tmp/seed-keycloak.out" \
  && pass "the data volume is snapshotted" || fail "no snapshot of the data volume"
[ "$(jv "$out/seed-keycloak.json" idle_rss_kb)" = 204800 ] && [ "$(jv "$out/seed-keycloak.json" store_bytes)" = 4000000000 ] \
  && pass "the seed record has the idle RSS and the store size" || fail "seed record: $(cat "$out/seed-keycloak.json")"
grep -q 'terminate-instances' "$tmp/seed-keycloak.out" && pass "the seed run is torn down" || fail "seed run left up"

# Its ramps: refresh fails at 400/s (coarse 25..3200), login (2..256) never does.
JOURNEYS="refresh login" step ramps-keycloak bash "$c" ramps keycloak 1 || fail "ramps keycloak"
r=$out/keycloak-s1/refresh.json
[ "$(jv "$r" clean_rate)" = 350.0 ] && [ "$(jv "$r" at_least)" = False ] \
  && pass "refresh: coarse fails at 400, fine 250/300/350, clean rate 350" \
  || fail "refresh result: clean $(jv "$r" clean_rate), at least $(jv "$r" at_least)"
coarse=$(python3 -I -c 'import json,sys; print([v["rate"] for v in json.load(open(sys.argv[1]))])' "$out/keycloak-s1/refresh.coarse.json")
[ "$coarse" = "[25.0, 50.0, 100.0, 200.0, 400.0]" ] && pass "judging stops at the first failing step" \
  || fail "coarse verdicts: $coarse"
l=$out/keycloak-s1/login.json
[ "$(jv "$l" clean_rate)" = 256.0 ] && [ "$(jv "$l" at_least)" = True ] && [ ! -e "$out/keycloak-s1/login.fine.json" ] \
  && pass "login: all 8 coarse steps clean, 'at least' 256, no fine phase" || fail "login result"
pm=$(sed -n 's/^RATES_PM=//p' "$tmp"/repo/loadtest/live/results/dry-keycloak-s1-1/refresh-coarse-1/params.env)
[ "$pm" = "1500,1500,3000,6000,12000,24000,48000,96000,192000" ] \
  && pass "the coarse run: a warm-up minute at 25/s, then the doubling ladder" || fail "RATES_PM $pm"
grep -q 'K6_ENV=PRESENT=chain' "$tmp"/repo/loadtest/live/results/dry-keycloak-s1-1/refresh-coarse-1/params.env \
  && pass "PRESENT=chain" || fail "the ramp does not present chain tokens"
[ "$(grep -c 'remote.sh restore keycloak' "$tmp/ramps-keycloak.out")" = 4 ] \
  && pass "a restore (store, cache drop, restart) before each of the 4 phases" || fail "restores"
grep -q 'shutdown, -h, "+240"' "$tmp/ramps-keycloak.out" && grep -q 'SnapshotId=snap-dry' "$tmp/ramps-keycloak.out" \
  && pass "the ramp server: 240 min lifetime, data volume from the seed's snapshot" || fail "ramp launch"

# Hearth: seed, then the cold read over 1M users.
step seed-hearth bash "$c" seed hearth || fail "seed hearth"
grep -q 'DRY ssh .*remote.sh bind-hearth' "$tmp/seed-hearth.out" && pass "Hearth's seed store is on the data volume" \
  || fail "Hearth seed: no bind"
JOURNEYS=cold1m step ramps-hearth bash "$c" ramps hearth 1 || fail "ramps hearth"
grep -q 'ADMIN_IDS_FILE=/opt/stress/ids-1000000.txt' "$tmp"/repo/loadtest/live/results/dry-hearth-s1-1/cold1m-coarse-1/params.env \
  && pass "the cold read walks the 1M-id working set" || fail "cold1m params"
grep -q "awk -v g=2 -v i=1 'NR % g == i % g'" "$tmp/ramps-hearth.out" && pass "each generator gets its own share of the ids" \
  || fail "ids not split"
grep -q 'dry-not-a-secret' "$tmp/ramps-hearth.out" "$tmp/dry/calls.log" && fail "a secret reached the log" || pass "no secret in the log"

# Cost.
open=$(python3 -I - "$state/ledger.jsonl" << 'PY'
import json, sys
ends = {}
for l in open(sys.argv[1]):
    e = json.loads(l)
    if "id" in e:
        ends[e["id"]] = ends.get(e["id"]) if "kind" in e and e.get("end") is None else e.get("end")
print(sum(1 for k, v in ends.items() if v is None and not k.startswith("snap-")))
PY
)
[ "$open" = 0 ] && pass "every instance in the ledger is closed" || fail "$open ledger entries open"
[ "$(wc -l < "$out/cost.txt")" -ge 6 ] && pass "the running total after each step ($(wc -l < "$out/cost.txt") lines)" \
  || fail "cost.txt"
STOP_USD=0.01 JOURNEYS=refresh try stop bash "$c" ramps zitadel 1
grep -q 'no snapshot for zitadel' "$tmp/stop.out" && pass "a product without a seed snapshot does not ramp" || fail "zitadel ramped unseeded"
STOP_USD=0.01 try stop2 bash "$c" seed ory
rc=$?
grep -q 'reached \$0.01: stopping, every run goes down' "$tmp/stop2.out" && [ "$rc" != 0 ] \
  && pass "the session stops at STOP_USD" || fail "no stop at STOP_USD (rc $rc)"
CAP_USD=0.01 try cap bash "$c" seed zitadel
grep -q 'past the \$0.01 cap' "$tmp/cap.out" && ! grep -q run-instances "$tmp/cap.out" \
  && pass "a part over CAP_USD does not start" || fail "CAP_USD"

# Snapshots.
try snapdel-bad bash "$c" delete-snapshots snap-not-ours && fail "deleted a snapshot not of the session" \
  || pass "a snapshot not of the session is refused"
snap=$(jv "$out/seed-keycloak.json" snapshot)
step snapdel bash "$c" delete-snapshots "$snap" && grep -q "DRY aws .*delete-snapshot --snapshot-id $snap" "$tmp/snapdel.out" \
  && pass "delete-snapshots deletes the one named" || fail "delete-snapshots"
grep -q 'ec2 delete-snapshot ' "$tmp/seed-keycloak.out" "$tmp/ramps-keycloak.out" && fail "a snapshot was deleted unasked" \
  || pass "no snapshot is deleted unasked"

# No real tool ran: every call went through the shims.
grep -q '^DRY ' "$tmp/dry/calls.log" && ! grep -q 'unknown tool' "$tmp/dry/calls.log" && pass "all calls went to the shims" \
  || fail "shim log"

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
