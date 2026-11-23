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
#   - the cost ledger (every instance closed), cost.txt, the $20 stop (STOP_USD)
#   - the AWS login window: no part without a login or past the window; a
#     session that stops at the window, then resumes without redoing work or
#     counting a cost twice; the plan's wall clock and logins
#   - the parallel session: parts at once (two size 1 parts, the drill with
#     size 1, size 2 together), the wait for vCPUs under MAX_VCPU, and the stop
#     at STOP_USD with several parts running
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

# The AWS login window: no part starts without a login, or when it would end
# after the window; the stop is clean (exit 4) and says what to do.
before=$(grep -c 'run-instances' "$tmp/dry/calls.log")
DRY_STS_FAIL=1 JOURNEYS=userinfo try sts bash "$c" ramps hearth 1
rc=$?
grep -q 'the aws CLI is not logged in' "$tmp/sts.out" && [ "$rc" = 4 ] \
  && pass "no part starts when the aws CLI is not logged in" || fail "expired login (rc $rc)"
LOGIN_AT=$(($(date +%s) - 11 * 3600)) JOURNEYS=userinfo try window bash "$c" ramps hearth 1
rc=$?
grep -q 'would end after the AWS login window' "$tmp/window.out" \
  && grep -q 'run aws login, then compare.sh session again' "$tmp/window.out" && [ "$rc" = 4 ] \
  && pass "a part that would end after the login window does not start (exit 4)" || fail "window (rc $rc)"
[ "$(grep -c 'run-instances' "$tmp/dry/calls.log")" = "$before" ] && pass "nothing was launched outside the window" \
  || fail "launched outside the window"

step plan bash "$c" plan || fail "plan"
grep -q '^wall clock: about 13.9 h with MAX_VCPU 32' "$tmp/plan.out" && grep -q '^aws logins: 2 ' "$tmp/plan.out" \
  && grep -q '; 32: 13.9 h, 2 login(s); 48: 10.7 h, 1 login(s); 64: 10.7 h, 1 login(s)' "$tmp/plan.out" \
  && pass "plan: the parallel wall clock at the quota (13.9 h at 32 vCPUs, 2 logins; 10.7 h, 1 login at 64)" \
  || fail "plan: $(grep -E '^(wall|aws)' "$tmp/plan.out")"
MAX_VCPU=64 step plan64 bash "$c" plan || fail "plan64"
grep -q '^wall clock: about 10.7 h with MAX_VCPU 64' "$tmp/plan64.out" && grep -q '^aws logins: 1 ' "$tmp/plan64.out" \
  && pass "plan: MAX_VCPU sets the limit" || fail "plan MAX_VCPU=64: $(grep -E '^(wall|aws)' "$tmp/plan64.out")"

# The parts that ran at once, from a session's timeline.txt (its start and end
# events in order): the largest number, whether two size 1 parts and the drill
# with a size 1 part ever overlapped, and the most vCPUs.
overlap() {
  python3 -I - "$1" << 'PY'
import sys
running, most, s1s, drill_s1, s2s, vcpu = set(), 0, False, False, False, 0
for line in open(sys.argv[1]):
    f = line.split()
    if f[1] == "start":
        running.add(f[2])
        vcpu = max(vcpu, int(f[4].split("=")[1]))
    elif f[1] == "end":
        running.discard(f[2])
    most = max(most, len(running))
    s1 = [p for p in running if p.startswith("s1:")]
    s1s = s1s or len(s1) >= 2
    drill_s1 = drill_s1 or ("drill" in running and bool(s1))
    s2s = s2s or len([p for p in running if p.startswith("s2:")]) == 2
print(most, s1s, drill_s1, s2s, vcpu)
PY
}
ledger_open() {
  python3 -I - "$1" << 'PY'
import json, sys
ends = {}
for l in open(sys.argv[1]):
    e = json.loads(l)
    if "id" in e:
        ends[e["id"]] = ends.get(e["id"]) if "kind" in e and e.get("end") is None else e.get("end")
print(sum(1 for k, v in ends.items() if v is None and not k.startswith("snap-")))
PY
}

# A session that starts with 4.5 h of its login window left (LOGIN_AT 7 h
# ago): the Authentik seed (4.5 h plus 15 min) does not fit; the 4 other
# seeds, the drill and their size 1 ramps (3.4 h each; the dry run takes
# seconds) do, in parallel; size 2 needs Authentik's size 1, so it stops.
s=$tmp/repo/loadtest/compare/.build/aws-drys
so=$tmp/repo/loadtest/live/results/compare-drys
SESSION=drys LOGIN_AT=$(($(date +%s) - 7 * 3600)) try session1 bash "$c" session
rc=$?
grep -q 'left for the next login: seed:authentik s1:authentik s2:hearth s2:other' "$tmp/session1.out" && [ "$rc" = 4 ] \
  && grep -q 'run aws login, then compare.sh session again' "$tmp/session1.out" \
  && pass "session: Authentik's seed waits for the next login; the session stops cleanly (exit 4)" \
  || fail "session 1 (rc $rc): $(grep -v '^DRY' "$tmp/session1.out" | tail -n 5)"
[ ! -s "$s/runs.active" ] && [ ! -e "$so/seed-authentik.json" ] && [ -s "$so/ory-s1/mix.json" ] && [ -s "$so/drill.done" ] \
  && [ "$(ledger_open "$s/ledger.jsonl")" = 0 ] \
  && pass "session: 4 seeds, the drill and 4 size 1 parts done, nothing left up" || fail "session 1 state"
read -r most s1s drill_s1 _ vcpu <<< "$(overlap "$so/timeline.txt")"
[ "$s1s" = True ] && [ "$drill_s1" = True ] && [ "$most" -ge 4 ] && [ "$vcpu" -le 32 ] \
  && pass "session: parts in parallel (at most $most at once, two size 1 parts together, the drill with size 1; $vcpu vCPUs at most)" \
  || fail "session 1 overlap: $most $s1s $drill_s1 $vcpu"
grep -q '^LOGIN_AT=' "$s/login.env" && pass "session: the login time is recorded" || fail "no LOGIN_AT"
# A run the stop could not tear down (its credentials ran out in the middle of
# Authentik's size 1 ramps, say).
python3 -I "$here/cost.py" start "$s/ledger.jsonl" instance drys-authentik-s1-1-server c7i.large 30
echo "drys-authentik-s1-1 0" >> "$s/runs.active"
cp "$so/hearth-s1/login.json" "$tmp/hearth-login-before.json"
: > "$so/timeline.txt"

# After a new login: the session resumes, with a larger quota (64), so the
# size 2 parts run together.
SESSION=drys MAX_VCPU=64 step session2 bash "$c" session || fail "session 2"
grep -q 'runs left up by an earlier session: drys-authentik-s1-1' "$tmp/session2.out" && [ ! -s "$s/runs.active" ] \
  && grep -q 'results/drys-authentik-s1-2/' "$so/driver-s1-authentik.log" \
  && pass "resume: a run left up goes down first, and its id is not reused" || fail "resume: the lost run"
for p in hearth keycloak zitadel ory authentik; do
  n=$(grep -c "seed $p on " "$so/driver-seed-$p.log")
  [ "$n" = 1 ] || fail "seed $p ran $n times"
done
started=$(awk '$2 == "start" {print $3}' "$so/timeline.txt" | sort | tr '\n' ' ')
[ "$started" = "s1:authentik s2:hearth s2:other seed:authentik " ] \
  && cmp -s "$so/hearth-s1/login.json" "$tmp/hearth-login-before.json" \
  && ! grep -qE 'drys-(hearth|keycloak|zitadel|ory)-s1-2' "$so"/driver-*.log \
  && pass "resume: only the parts left start; no finished seed, journey or drill runs again" \
  || fail "resume started: $started"
read -r _ _ _ s2s _ <<< "$(overlap "$so/timeline.txt")"
[ "$s2s" = True ] && pass "size 2: Hearth and the other product at once" || fail "size 2 not in parallel"
[ "$(jv "$so/seed-authentik.json" server)" = c7i.2xlarge ] && [ "$(jv "$so/seed-authentik.json" seed_procs)" = 4 ] \
  && [ "$(jv "$so/seed-keycloak.json" server)" = c7i.large ] \
  && grep -q 'shutdown, -h, "+405"' "$so/driver-seed-authentik.log" \
  && pass "Authentik seeds on c7i.2xlarge (4 processes, lifetime 270 + 50 % = 405 min), the others on c7i.large" \
  || fail "seed servers"
grep -q '^## Seeds on c7i.2xlarge' "$so/summary.md" \
  && grep -q 'not with the seeds on c7i.large' "$so/summary.md" \
  && pass "summary: the seed times by server type, Authentik's apart" || fail "summary seed tables"
[ -s "$so/hearth-s2/mix.json" ] && [ -s "$so/$(jv "$so/fastest.json" product)-s2/mix.json" ] \
  && pass "resume: size 2 ran for Hearth and $(jv "$so/fastest.json" product)" || fail "resume: size 2"
dup=$(python3 -I - "$s/ledger.jsonl" << 'PY'
import collections, json, sys
starts = collections.Counter(e["id"] for e in map(json.loads, open(sys.argv[1])) if "kind" in e and "id" in e)
print(" ".join(k for k, n in starts.items() if n > 1))
PY
)
[ -z "$dup" ] && [ "$(ledger_open "$s/ledger.jsonl")" = 0 ] && pass "resume: no ledger entry counted twice, all closed" \
  || fail "counted twice: $dup"

# The quota, MAX_VCPU 32 (the default): the seeds (16) and the drill (6) start;
# one size 1 part (10) fits, the others wait for vCPUs; the size 2 parts (24
# each) run one after the other.
sv=$tmp/repo/loadtest/live/results/compare-drysv
SESSION=drysv step session-vcpu bash "$c" session || fail "session at MAX_VCPU 32"
read -r _ _ _ s2s vcpu <<< "$(overlap "$sv/timeline.txt")"
grep -q '^[0-9]* wait-vcpu s1:' "$sv/timeline.txt" && grep -q '^[0-9]* wait-vcpu s2:' "$sv/timeline.txt" \
  && [ "$vcpu" -le 32 ] && [ "$s2s" = False ] && [ -s "$sv/summary.md" ] \
  && pass "MAX_VCPU 32: parts wait for vCPUs (at most $vcpu running), size 2 one after the other, session done" \
  || fail "MAX_VCPU 32: max $vcpu, s2 together $s2s"

# The stop at STOP_USD while several parts run: a seed's snapshot ($0.20 a
# month) passes $0.10; every part stops, every run of every part goes down.
st=$tmp/repo/loadtest/compare/.build/aws-drysst
sto=$tmp/repo/loadtest/live/results/compare-drysst
SESSION=drysst STOP_USD=0.1 try session-stop bash "$c" session
rc=$?
running_at_stop=$(python3 -I - "$sto/timeline.txt" << 'PY'
import sys
running = set()
for line in open(sys.argv[1]):
    f = line.split()
    if f[1] == "start":
        running.add(f[2])
    elif f[1] == "end":
        print(len(running))
        break
PY
)
[ "$rc" = 3 ] && grep -q 'reached \$0.1' "$tmp/session-stop.out" && [ "${running_at_stop:-0}" -ge 2 ] \
  && [ ! -s "$st/runs.active" ] && [ "$(ledger_open "$st/ledger.jsonl")" = 0 ] \
  && ! pgrep -f "$tmp/repo/loadtest/compare/aws/compare.sh" > /dev/null \
  && pass "STOP_USD with $running_at_stop parts running: all stop, every run down, every ledger entry closed" \
  || fail "STOP_USD in a session (rc $rc, $running_at_stop running, open $(ledger_open "$st/ledger.jsonl"))"

# No real tool ran: every call went through the shims.
grep -q '^DRY ' "$tmp/dry/calls.log" && ! grep -q 'unknown tool' "$tmp/dry/calls.log" && pass "all calls went to the shims" \
  || fail "shim log"

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
