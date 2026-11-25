#!/usr/bin/env bash
# Runs compare.sh end to end with DRY_RUN=1 (#913): no AWS, no SSH, no
# network. The shims in dryrun/ print every AWS call and remote command and
# make up the k6 output, in which every step at DRY_FAIL_RATE (400/s) or more
# is too slow. Checks:
#   - a product's seed: a server-only run with the seed lifetime, the data
#     volume, a snapshot, the seed record, torn down; the 1M ids from the
#     product's store or its admin API (cursor paging), the usable check; a
#     server that stops answering over SSH ends the listing at once
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
#   - a part that fails: it stops alone (its run goes down), the parts after
#     it are skipped, the others run to their end; the session exits 1 with
#     each part's end, and a rerun runs only the failed and skipped parts;
#     STOP_USD still stops every part after a failure
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
# The 1M ids: offset paging through Keycloak's admin API takes about 45 min
# on 2 vCPUs (in 913a it did not end); its PostgreSQL lists them in the API's
# order in seconds.
grep -q 'DRY ssh .*remote.sh product keycloak ids 1000000 /data/bundle/out/ids.txt' "$tmp/seed-keycloak.out" \
  && ! grep -q 'ids.js IDS_COUNT' "$tmp/seed-keycloak.out" \
  && pass "Keycloak's 1M ids come from its store (keycloak.sh ids), not from offset paging" \
  || fail "Keycloak's ids: $(grep -o 'DRY ssh .*ids.*' "$tmp/seed-keycloak.out" | head -n 2)"
grep -qF "awk 'NR == 1 || NR % 1000 == 0' /data/bundle/out/ids.txt > /data/bundle/out/ids-check.txt" "$tmp/seed-keycloak.out" \
  && grep -q 'DRY ssh .*k6.sh /data/bundle ids.js IDS_CHECK=/out/ids-check.txt' "$tmp/seed-keycloak.out" \
  && grep -q 'DRY ssh .*mv /data/bundle/out/ids.txt /data/bundle/ids-1000000.txt' "$tmp/seed-keycloak.out" \
  && pass "usable: the admin API looks up the first and every 1,000th id, then the ids go to the bundle" \
  || fail "no usable check through the admin API"
grep -q 'the admin API answers the cold read' <<< "$(jv "$out/seed-keycloak.json" usable_rule)" \
  && [ "$(jv "$out/seed-keycloak.json" ids_from)" = "store" ] && [ -n "$(jv "$out/seed-keycloak.json" ids_s)" ] \
  && pass "the seed record has the usable rule, where the ids came from and the listing time" \
  || fail "seed record: $(cat "$out/seed-keycloak.json")"

# A server that stops answering over SSH (gone at its lifetime) during the
# listing ends the seed at once, with one clear error, not 120 retries.
SESSION=dryg DRY_SSH_GONE_AFTER='product zitadel seed 0 1000000' try gone bash "$c" seed zitadel
rc=$?
[ "$rc" != 0 ] && [ "$(grep -c 'does not answer over SSH' "$tmp/gone.out")" = 1 ] \
  && ! grep -q 'yet (2)' "$tmp/gone.out" \
  && pass "an unreachable server ends the listing at once, with one error" \
  || fail "unreachable server (rc $rc): $(grep -v '^DRY' "$tmp/gone.out" | tail -n 3 | tr '\n' ' ')"

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
grep -q 'DRY ssh .*IDS_COUNT=1000000 IDS_OUT=/data/bundle/out/ids.txt .*k6 run -q ids.js' "$tmp/seed-hearth.out" \
  && grep -q 'DRY ssh .*IDS_CHECK=/data/bundle/out/ids-check.txt .*k6 run -q ids.js' "$tmp/seed-hearth.out" \
  && [ "$(jv "$out/seed-hearth.json" ids_from)" = "admin API" ] \
  && pass "Hearth's ids come from its admin API (cursor paging), then the same usable check" \
  || fail "Hearth's ids: $(grep -o 'DRY ssh .*ids.js.*' "$tmp/seed-hearth.out" | head -n 2)"
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
# Where each product's ids come from: Ory's admin API pages by cursor (keyset),
# Zitadel's and Authentik's by offset, so theirs come from their store.
grep -q 'DRY ssh .*k6.sh /data/bundle ids.js IDS_COUNT=1000000 IDS_OUT=/out/ids.txt' "$so/driver-seed-ory.log" \
  && ! grep -q 'remote.sh product ory ids' "$so/driver-seed-ory.log" \
  && grep -q 'DRY ssh .*remote.sh product zitadel ids 1000000 ' "$so/driver-seed-zitadel.log" \
  && grep -q 'DRY ssh .*remote.sh product authentik ids 1000000 ' "$so/driver-seed-authentik.log" \
  && [ "$(grep -l 'IDS_CHECK=' "$so"/driver-seed-*.log | wc -l)" = 5 ] \
  && pass "ids: Ory's from its admin API, Zitadel's and Authentik's from their store; every product's usable check" \
  || fail "ids per product"
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

# A part that fails stops alone (owner decision 2026-11-25; in 913a one failed
# part stopped every part, an Authentik seed 2.5 h into its 4.5 h with them).
# Hearth's seed, the first part started, fails at its store bind (DRY_FAIL):
# its run goes down at once, the parts after it (s1:hearth; size 2, after
# every size 1 part) do not start and say why, every other part runs to its
# end, and the parts that wait still start. The session then exits 1 with how
# each part ended. One journey per ramps part (JOURNEYS) keeps it short.
fs=$tmp/repo/loadtest/compare/.build/aws-drysf
fo=$tmp/repo/loadtest/live/results/compare-drysf
SESSION=drysf JOURNEYS=login DRY_FAIL='remote.sh bind-hearth' try session-fail bash "$c" session
rc=$?
# From the timeline: the parts running when the session saw the failure,
# whether each of them then ended with exit 0, and the parts started after.
read -r at_fail ran_on started_after <<< "$(python3 -I - "$fo/timeline.txt" << 'PY'
import sys
running, at_fail, ends, after = set(), None, {}, 0
for line in open(sys.argv[1]):
    f = line.split()
    if f[1] == "start":
        running.add(f[2])
        after += at_fail is not None
    elif f[1] == "end":
        running.discard(f[2])
        if f[2] == "seed:hearth":
            at_fail = set(running)
        elif at_fail is not None:
            ends[f[2]] = f[3]
at_fail = at_fail or set()
print(len(at_fail), all(ends.get(p) == "rc=0" for p in at_fail), after)
PY
)"
[ "$rc" = 1 ] && grep -q "seed:hearth failed (exit 1): $fo/driver-seed-hearth.log" "$tmp/session-fail.out" \
  && grep -q 'tearing down drysf-seed-hearth-1 (seed:hearth)' "$tmp/session-fail.out" \
  && [ "${at_fail:-0}" -ge 1 ] && [ "$ran_on" = True ] \
  && pass "a failed part stops alone: its run goes down, the $at_fail parts running then run to their end" \
  || fail "a failed part (rc $rc, $at_fail running at the failure, they ran on: $ran_on): $(grep -v '^DRY' "$tmp/session-fail.out" | tail -n 5)"
grep -q 's1:hearth skipped: it needs seed:hearth, which failed' "$tmp/session-fail.out" \
  && grep -q 's2:hearth skipped: it needs s1:hearth, skipped because seed:hearth failed' "$tmp/session-fail.out" \
  && grep -q 's2:other skipped: it needs s1:hearth, skipped because seed:hearth failed' "$tmp/session-fail.out" \
  && ! grep -qE '^[0-9]+ start (s1:hearth|s2:)' "$fo/timeline.txt" \
  && pass "the parts after it do not start, each says why (s1:hearth; size 2, after s1:hearth)" \
  || fail "skipped parts: $(grep 'skipped' "$tmp/session-fail.out" | head -n 3)"
indep=0
for p in keycloak zitadel ory authentik; do
  [ -s "$fo/seed-$p.json" ] && [ -s "$fo/$p-s1/login.json" ] && indep=$((indep + 1))
done
[ "$indep" = 4 ] && [ -s "$fo/drill.done" ] && [ "${started_after:-0}" -ge 1 ] \
  && pass "the parts that do not need it start and finish (4 seeds, their size 1, the drill; $started_after started after the failure)" \
  || fail "independent parts: $indep of 4 products, drill $([ -s "$fo/drill.done" ] && echo done), $started_after started after"
grep -qF "  seed:hearth: failed (exit 1): $fo/driver-seed-hearth.log" "$tmp/session-fail.out" \
  && grep -qF '  s1:hearth: skipped (seed:hearth failed)' "$tmp/session-fail.out" \
  && grep -qF '  s2:other: skipped (seed:hearth failed)' "$tmp/session-fail.out" \
  && grep -qF '  seed:authentik: done' "$tmp/session-fail.out" && grep -qF '  s1:ory: done' "$tmp/session-fail.out" \
  && grep -qF '  drill: done' "$tmp/session-fail.out" \
  && grep -q 'FAILED: seed:hearth; skipped: s1:hearth s2:hearth s2:other' "$tmp/session-fail.out" \
  && [ ! -s "$fs/runs.active" ] && [ "$(ledger_open "$fs/ledger.jsonl")" = 0 ] \
  && ! pgrep -f "$tmp/repo/loadtest/compare/aws/compare.sh" > /dev/null \
  && pass "the session exits 1 with each part's end (done; failed and its log; skipped and why); nothing left up" \
  || fail "the end of a session with a failed part: $(grep -v '^DRY' "$tmp/session-fail.out" | tail -n 4)"

# The rerun (same SESSION) runs the failed part and the parts it skipped, and
# nothing else.
: > "$fo/timeline.txt"
SESSION=drysf JOURNEYS=login step session-fail2 bash "$c" session || fail "the rerun after a failed part"
started=$(awk '$2 == "start" {print $3}' "$fo/timeline.txt" | sort | tr '\n' ' ')
once=0
for p in keycloak zitadel ory authentik; do
  [ "$(grep -c "seed $p on " "$fo/driver-seed-$p.log")" = 1 ] && once=$((once + 1))
done
[ "$started" = "s1:hearth s2:hearth s2:other seed:hearth " ] && [ "$once" = 4 ] \
  && [ -s "$fo/hearth-s2/login.json" ] && [ -s "$fo/summary.md" ] && [ "$(ledger_open "$fs/ledger.jsonl")" = 0 ] \
  && pass "rerun: only the failed part and the parts it skipped run, then the session is done" \
  || fail "rerun after a failed part started: $started (seeds run once: $once of 4)"

# After a part failed, the stop at STOP_USD still stops every part: the third
# seed's snapshot ($0.20 a month each) passes $0.50, after Hearth's seed failed.
sfs=$tmp/repo/loadtest/compare/.build/aws-drysfs
SESSION=drysfs JOURNEYS=login STOP_USD=0.5 DRY_FAIL='remote.sh bind-hearth' try session-fail-stop bash "$c" session
rc=$?
failed_at=$(grep -n 'seed:hearth failed (exit 1)' "$tmp/session-fail-stop.out" | head -n 1 | cut -d: -f1)
stopped_at=$(grep -n 'reached \$0.5' "$tmp/session-fail-stop.out" | head -n 1 | cut -d: -f1)
[ "$rc" = 3 ] && [ -n "$failed_at" ] && [ -n "$stopped_at" ] && [ "$failed_at" -lt "$stopped_at" ] \
  && [ ! -s "$sfs/runs.active" ] && [ "$(ledger_open "$sfs/ledger.jsonl")" = 0 ] \
  && ! pgrep -f "$tmp/repo/loadtest/compare/aws/compare.sh" > /dev/null \
  && pass "after a part failed, STOP_USD still stops every part (exit 3), every run down, every ledger entry closed" \
  || fail "STOP_USD after a failed part (rc $rc, failure at line ${failed_at:-none}, stop at ${stopped_at:-none})"

# No real tool ran: every call went through the shims.
grep -q '^DRY ' "$tmp/dry/calls.log" && ! grep -q 'unknown tool' "$tmp/dry/calls.log" && pass "all calls went to the shims" \
  || fail "shim log"

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
