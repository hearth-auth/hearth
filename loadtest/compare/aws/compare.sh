#!/usr/bin/env bash
# The AWS session of the same-hardware comparison (#913): seeds each product
# once, keeps its store as an EBS snapshot, then runs every journey's step
# ladder on the fixed hardware, with a running cost total that stops the
# session at $20. It drives loadtest/live/cloud.sh (sourced for its functions,
# and run for up, deploy, import and down) with PROVIDER=aws; nothing here
# changes how the #647 rounds run.
#
#   compare.sh plan                 the session plan: hours and cost per part,
#                                   the wall clock and the AWS logins it needs
#                                   (at MAX_VCPU, and for other limits)
#   compare.sh seed <product>       one product's seed run (server only): 1M bulk
#                                   users and 1,000 login users through its own
#                                   seed tool, the 1M-id listing, the seed time,
#                                   idle RSS and store size, then a snapshot
#   compare.sh ramps <product> <size> [journey...]
#                                   a ramp run: size 1 (c7i.large and 2
#                                   generators) or 2 (c7i.2xlarge and 4); each
#                                   journey's ladder from a restored store
#   compare.sh session              all of it, in parallel: the 5 seeds and
#                                   the #647 10M restore drill at once, each
#                                   product's size 1 ramps as soon as its
#                                   snapshot exists, then size 2 for Hearth
#                                   and the fastest other product together.
#                                   Each part is its own compare.sh process
#                                   with its own runs; a part waits while its
#                                   instances would take the running vCPUs
#                                   past MAX_VCPU. Run it right after `aws
#                                   login`: a part that would end after the
#                                   login window does not start, and when
#                                   nothing else can run the session stops
#                                   cleanly (exit 4); a rerun after a new
#                                   login resumes (finished seeds, journeys
#                                   and the drill are kept, and not counted
#                                   twice)
#   compare.sh drill                the #647 10M restore drill (round.sh, a plan
#                                   with one drill line)
#   compare.sh cost                 the running total
#   compare.sh snapshots            the session's snapshots
#   compare.sh delete-snapshots <id>...
#                                   delete those snapshots (each must be one of
#                                   the session's; lists them first)
#   compare.sh down-all             tear down every run of the session still up
#
# Products: hearth keycloak zitadel ory authentik. Journeys: login refresh
# client_credentials userinfo introspect admin_lookup create_user mix cold100k
# cold1m (the cold read, admin_lookup over the first 100,000 or 1M users).
#
# Settings (environment):
#   SESSION        the session id (required; letters, digits, -), e.g. 913a
#   IMAGE          the Hearth image (cloud.sh; needs a revision label)
#   STOP_USD       20  (the running total that stops the session and tears
#                  down every part's runs)
#   CAP_USD        20  (a part whose estimate, plus what the parts running are
#                  still expected to cost, would pass it does not start)
#   MAX_VCPU       56  (the vCPUs of all running instances; set it to the
#                  account's on-demand standard-instance quota, L-1216C47A)
#   SEED_SIZE      every seed server's type (default: session-plan.json's
#                  seed_server: c7i.large, the size 1 server; Authentik
#                  c7i.2xlarge)
#   LOGIN_WINDOW_H 11.5 (an `aws login` lasts 12 h at most)
#   LOGIN_MARGIN_MIN 15 (the teardown's share of the window)
#                  A part (a seed, a product's ramps at one size, the drill)
#                  and each journey start only if `aws sts
#                  get-caller-identity` works and their estimate plus the
#                  margin ends before LOGIN_AT + LOGIN_WINDOW_H. `session`
#                  records LOGIN_AT (its start) in the state; LOGIN_AT=<epoch
#                  seconds> overrides it for one command.
#   DATA_GB        40  (the data volume of a seed, and of each ramp server)
#   JOURNEYS       the journeys of `ramps` and `session` (default: all 10 at
#                  size 1, the 8 without the cold reads at size 2)
#   DRY_RUN=1      no AWS and no SSH: PATH shims (dryrun/bin) print every AWS
#                  call and remote command instead, with canned answers
#                  (test_dryrun.sh)
#
# Results: loadtest/live/results/compare-<session>/ (git-ignored): one JSON per
# seed (seed-<product>.json), per journey (<product>-s<size>/<journey>.json,
# with every step's verdict), the cost after each step (cost.txt), the
# fastest-product rule (fastest.json) and the session summary (summary.md).
# State (run ids, snapshot ids, the cost ledger) is in
# loadtest/compare/.build/aws-<session>/ (git-ignored, mode 0700).
set -euo pipefail

aws_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compare_dir=$(cd "$aws_dir/.." && pwd)
live=$(cd "$aws_dir/../../live" && pwd)
PRODUCTS=(hearth keycloak zitadel ory authentik)
ALL_JOURNEYS=(login refresh client_credentials userinfo introspect admin_lookup create_user mix cold100k cold1m)
SIZE2_JOURNEYS=(login refresh client_credentials userinfo introspect admin_lookup create_user mix)

clog() { printf 'compare %s: %s\n' "$(TZ=America/New_York date +'%H:%M:%S %Z')" "$*" >&2; }
cdie() {
  clog "FAILED: $*"
  exit 1
}

if [ "${DRY_RUN:-}" = 1 ]; then
  export PATH="$aws_dir/dryrun/bin:$PATH"
  export DRY_STATE=${DRY_STATE:-$(mktemp -d)}
fi
export PROVIDER=aws

session=${SESSION:-}
case ${1:-} in plan | "") ;; *)
  [[ $session =~ ^[0-9A-Za-z-]+$ ]] || cdie "set SESSION (letters, digits, -)" ;;
esac
state=$compare_dir/.build/aws-$session
out=$live/results/compare-$session
ledger=$state/ledger.jsonl
stop_usd=${STOP_USD:-20}
cap_usd=${CAP_USD:-20}
data_gb=${DATA_GB:-40}

# cloud.sh's functions (ssh_to, load_run, cmd_ramp, cmd_collect, ...). Its
# settings are read now; `up` runs cloud.sh as a command, with its own.
# shellcheck source=../../live/cloud.sh
. "$live/cloud.sh"
set -euo pipefail

cost() { python3 -I "$aws_dir/cost.py" "$@"; }

# The parts of a session run as parallel compare.sh processes that share the
# state files: each change to one holds the session's lock. $1: file; $2: line to add, or
# -d and a sed address of the lines to delete.
state_edit() {
  local f=$1
  shift
  if [ "$1" = -d ]; then
    flock "$state/lock" sed -i "$2d" "$f"
  else
    flock "$state/lock" bash -c 'printf "%s\n" "$1" >> "$2"' _ "$1" "$f"
  fi
}
lad() { python3 -I "$aws_dir/ladder.py" "$@"; }
jget() { python3 -I -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[k]
print(v if not isinstance(v,(list,dict)) else json.dumps(v))' "$@"; }

init_state() {
  umask 077
  mkdir -p "$state" "$out"
  touch "$state/runs.active" "$state/snapshots.env"
  [ ! -e "$live/.build/HOLD-DOWN" ] || cdie "$live/.build/HOLD-DOWN exists: cloud.sh down would leave runs up"
}

# The running total after a step: printed, appended to cost.txt, and the
# session stops at STOP_USD: every run of it (every part's) goes down, and
# the STOPPED file tells the session and the other parts.
spend() {
  local what=$1 total
  total=$(cost check "$ledger" 1000000)
  printf '%s %s total $%s\n' "$(TZ=America/New_York date +'%Y-%m-%d %H:%M %Z')" "$what" "$total" >> "$out/cost.txt"
  clog "cost after $what: \$$total (stop at \$$stop_usd)"
  if { [ -n "${PART:-}" ] && [ -e "$state/STOPPED" ]; } || ! cost check "$ledger" "$stop_usd" > /dev/null; then
    clog "the running total \$$total reached \$$stop_usd: stopping, every run goes down"
    echo "the running total \$$total reached \$$stop_usd" >> "$state/STOPPED"
    down_all
    exit 3
  fi
}

# Whether a part may start: its estimate (USD), the total so far and what the
# other parts running are still expected to cost stay within CAP_USD.
fits_cap() {
  local what=$1 est=$2 total rest
  total=$(cost check "$ledger" 1000000)
  rest=$(cost remaining "$state/parts.active" "$aws_dir/session-plan.json" "${PART:-}")
  python3 -I -c 'import sys; t, r, e, c = map(float, sys.argv[1:]); sys.exit(t + r + e > c)' "$total" "$rest" "$est" "$cap_usd" \
    && return 0
  clog "$what (about \$$est) would take the total \$$total, plus \$$rest still to come from the parts running, past the \$$cap_usd cap"
  return 1
}

# Refuses a part whose estimate would pass CAP_USD.
afford() { fits_cap "$@" || cdie "$1 does not start"; }

# The estimate (USD) of `hours` on a set of instances: "<type>:<n> ...".
estimate_usd() {
  local hours=$1
  shift
  python3 -I - "$aws_dir/prices.json" "$hours" "$@" << 'PY'
import json, sys
p = json.load(open(sys.argv[1])); h = float(sys.argv[2])
print(round(h * sum(int(n) * (p["instance_hour"][t] + p["public_ipv4_hour"])
                    for t, n in (a.split(":") for a in sys.argv[3:])), 2))
PY
}

# A value of session-plan.json's model: `plan_model seed_hours authentik`.
plan_model() { jget model "$@" < "$aws_dir/session-plan.json"; }

# The first run id <prefix>-<n> (n = 1, 2, ...) the ledger has not seen: a
# resumed session starts new runs and never reopens a finished run's entries.
fresh_id() {
  local n=1
  while grep -q "\"id\": \"$1-$n-server\"" "$ledger" 2> /dev/null; do n=$((n + 1)); done
  echo "$1-$n"
}

# ---------------------------------------------------------------- AWS login

login_window_h=${LOGIN_WINDOW_H:-11.5}
login_margin_min=${LOGIN_MARGIN_MIN:-15}
export LOGIN_WINDOW_H=$login_window_h LOGIN_MARGIN_MIN=$login_margin_min

login_at() {
  if [ -n "${LOGIN_AT:-}" ]; then
    echo "$LOGIN_AT"
  else
    sed -n 's/^LOGIN_AT=//p' "$state/login.env" 2> /dev/null | tail -n 1
  fi
}

et() { TZ=America/New_York date -d "@${1%.*}" +'%Y-%m-%d %H:%M %Z'; }

# Whether $1 (about $2 hours) may start: the aws CLI answers, and the part
# plus the teardown margin ends inside the login window. Says why not.
login_fits() {
  local what=$1 hours=$2 at end
  if ! (aws_check_identity) > /dev/null 2>&1; then
    clog "$what: the aws CLI is not logged in (sts get-caller-identity failed)"
    return 1
  fi
  at=$(login_at)
  [ -n "$at" ] || return 0
  end=$(python3 -I -c 'import sys; print(int(float(sys.argv[1]) + float(sys.argv[2]) * 3600))' "$at" "$login_window_h")
  python3 -I -c 'import sys, time; h, m, end = map(float, sys.argv[1:]); sys.exit(time.time() + h * 3600 + m * 60 > end)' \
    "$hours" "$login_margin_min" "$end" && return 0
  clog "$what (about $hours h, plus $login_margin_min min to tear down) would end after the AWS login window ($(et "$end"))"
  return 1
}

# Stops at the end of the login window (exit 4). A part of a session
# (PART set) has torn its own run down and leaves the rest to the session;
# otherwise every run goes down, and a rerun after a new login resumes.
login_exit() {
  if [ -n "${PART:-}" ]; then
    clog "$PART: stopped before the AWS login window ends"
    exit 4
  fi
  down_all
  trap - EXIT
  clog "stopped before the AWS login window ends: run aws login, then compare.sh session again (it resumes; finished seeds, journeys and the drill are kept)"
  exit 4
}

# login_fits, or login_exit.
login_gate() { login_fits "$@" || login_exit; }

# Starts a run: `cloud.sh up` with its own settings, its instances in the
# ledger from before the launch. $1: run id; $2: server type; $3: generators;
# $4: server lifetime (minutes); $5: the server's root disk (GB); the rest:
# env assignments for cloud.sh.
run_up() {
  local id=$1 server=$2 gens=$3 minutes=$4 disk=$5 i
  shift 5
  cost start "$ledger" instance "$id-server" "$server" "$((disk + data_gb))"
  for i in $(seq 1 "$gens"); do cost start "$ledger" instance "$id-gen$i" c7i.xlarge 30; done
  state_edit "$state/runs.active" "$id $gens"
  env STRESS_RUN="$id" SERVER_SIZE="$server" GENERATOR_SIZE=c7i.xlarge GENERATORS="$gens" \
    SERVER_MAX_MINUTES="$minutes" SERVER_DATA_GB="$data_gb" AWS_DISK_GB="$disk" "$@" "$live/cloud.sh" up \
    || cdie "up $id failed; its instances end at their lifetime, or: STRESS_RUN=$id cloud.sh down"
}

# Tears down run $1 (cloud.sh down: instances, group, key; lists what is left)
# and closes its ledger entries.
run_down() {
  # One process tears a run down (its part, or a stop): the run's lock, and
  # nothing to do once the run has left runs.active.
  (
    flock 8
    local id=$1 gens i bytes
    grep -q "^$id " "$state/runs.active" || exit 0
    gens=$(awk -v r="$id" '$1 == r {print $2}' "$state/runs.active" | tail -n 1)
    STRESS_RUN=$id "$live/cloud.sh" down 2>&1 | tee "$out/down-$id.txt" >&2 || true
    cost end "$ledger" "$id-server"
    for i in $(seq 1 "${gens:-0}"); do cost end "$ledger" "$id-gen$i"; done
    bytes=$(du -sb "$live/results/$id" 2> /dev/null | cut -f1 || echo 0)
    cost data-out "$ledger" "${bytes:-0}"
    state_edit "$state/runs.active" -d "/^$id /"
  ) 8> "$state/down-$1.lock"
}

# Every run of the session goes down: one process at a time (several parts
# may stop at once).
down_all() {
  (
    flock 9
    local id
    while read -r id _; do
      [ -n "$id" ] || continue
      clog "tearing down $id"
      run_down "$id"
    done < <(cat "$state/runs.active")
  ) 9> "$state/down.lock"
}

# In a subshell, with run $1 loaded (cloud.sh's load_run): the rest of the
# arguments run as a command there.
in_run() {
  local id=$1
  shift
  (
    export STRESS_RUN=$id
    load_run
    "$@"
  )
}

srv() { ssh_to "$SERVER_PUBLIC" "$@"; }

# The ports a product listens on besides 8443 (Hearth's, which cloud.sh's
# security group opens to the group's members).
ports_of() {
  case $1 in
    hearth | zitadel) echo "" ;;
    keycloak) echo 9000 ;;
    ory) echo 4433-4455 ;;
    authentik) echo 9443 ;;
  esac
}

# cloud.sh's check before a ramp, for a product: its compose project runs.
server_active() {
  if [ "${COMPARE_PRODUCT:-hearth}" = hearth ]; then
    ssh_to "$SERVER_PUBLIC" "systemctl is-active --quiet hearth"
  else
    ssh_to "$SERVER_PUBLIC" "test -n \"\$(docker ps -q --filter label=com.docker.compose.project=compare-$COMPARE_PRODUCT)\""
  fi
}
rsrv() { ssh_to "$SERVER_PUBLIC" "bash /opt/compare/remote.sh $*"; }

# Copies the comparison's files to the server: the product setups, the k6
# scripts the seed tools run, and remote.sh.
copy_compare() {
  srv "mkdir -p /opt/compare/loadtest/live /opt/hearth/out"
  tar -C "$live/../.." --exclude='.build' --exclude='results' --exclude='__pycache__' \
    -czf - loadtest/compare loadtest/live/k6 \
    | ssh_to "$SERVER_PUBLIC" "tar -C /opt/compare -xzf -"
  scp_to "$SERVER_PUBLIC" /opt/compare/ "$aws_dir/remote.sh"
}

# The product server's observation scripts: observe.sh with the compose
# sampler as sampler.sh (no Hearth /metrics to scrape).
product_observers() {
  local p=$1
  scp_to "$SERVER_PUBLIC" /opt/hearth/ "$live/remote/observe.sh"
  scp_to "$SERVER_PUBLIC" /opt/hearth/sampler.sh "$aws_dir/compose-sampler.sh"
  srv "printf '#!/usr/bin/env bash\nexit 0\n' > /opt/hearth/metrics-scrape.sh
    chmod 0755 /opt/hearth/*.sh
    echo COMPOSE_PROJECT=compare-$p > /opt/compare/product.env"
}

# Makes the server its own (only) generator: the seed tools of the products
# run k6 on the server, and Hearth's deploy and import do the same then.
self_generator() {
  printf 'GEN1_ID=%s\nGEN1_PUBLIC=%s\nGEN1_PRIVATE=%s\nGEN_COUNT=1\n' \
    "$SERVER_ID" "$SERVER_PUBLIC" "$SERVER_PRIVATE" >> "$run/run.env"
}

seed_hours() { plan_model seed_hours "$1"; }

# A product's seed server: SEED_SIZE, else the plan's seed_server.
seed_size_of() {
  if [ -n "${SEED_SIZE:-}" ]; then
    echo "$SEED_SIZE"
  else
    python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1]))["model"]["seed_server"]; print(s.get(sys.argv[2], s["default"]))' \
      "$aws_dir/session-plan.json" "$1"
  fi
}

# ---------------------------------------------------------------- seed

cmd_seed() {
  local p=${1:?usage: compare.sh seed <product>}
  init_state
  [[ " ${PRODUCTS[*]} " == *" $p "* ]] || cdie "unknown product $p"
  [ ! -s "$out/seed-$p.json" ] || cdie "$p is seeded already ($out/seed-$p.json)"
  local id est minutes size
  size=$(seed_size_of "$p")
  est=$(python3 -I -c "print(round($(seed_hours "$p") * 60))")
  minutes=$(lad seed-minutes "$est")
  # In a session (PART set), the session checked the login window first.
  [ -n "${PART:-}" ] || login_gate "seed $p" "$(seed_hours "$p")"
  afford "seed $p" "$(estimate_usd "$(python3 -I -c "print($minutes / 60)")" "$size:1")"
  id=$(fresh_id "$session-seed-$p")
  clog "seed $p on $size, run $id, lifetime $minutes min (estimate $est min plus 50 %, at most 16 h)"
  run_up "$id" "$size" 0 "$minutes" 30
  in_run "$id" seed_on_server "$p" "$id" "$size"
  run_down "$id"
  spend "seed $p"
}

seed_on_server() {
  local p=$1 id=$2 server=$3 vol t0 t1 t_usable f="$out/seed-$p.json" log="$out/seed-$p.log"
  self_generator
  load_run
  vol=$(aws_data_volume_id)
  copy_compare
  rsrv data-new "$vol"
  local idle size settle pull="" procs=None
  if [ "$p" = hearth ]; then
    rsrv bind-hearth
    "$live/cloud.sh" deploy 2>&1 | tee -a "$log" >&2
    load_run
    t0=$(date +%s)
    "$live/cloud.sh" import 0 1000000 > "$out/import-$p.json" 2>> "$log"
    t1=$(date +%s)
    # The seed's bundle goes with its store (keys, passwords); the ramp runs
    # deploy it. The generator's copy of generator.env is the one in use.
    cp -a "$run/bundle" "$state/hearth-bundle"
    scp_from "$GEN_PUBLIC" /opt/stress/generator.env "$state/hearth-bundle/generator.env"
    list_ids "$p"
    t_usable=$(date +%s)
    settle=$(rsrv settle /var/lib/hearth)
  else
    rsrv bind-docker-volumes
    rsrv install-docker | tee -a "$log" >&2
    product_observers "$p"
    pull=$(rsrv pull "$p")
    rsrv product "$p" up 2>&1 | tee -a "$log" >&2
    # Authentik's seed applies its blueprints in SEED_PROCS processes: 4, as
    # measured locally, on a larger seed server; its default 2 on c7i.large.
    procs=2
    [ "$server" = c7i.large ] || procs=4
    t0=$(date +%s)
    srv "SEED_PROCS=$procs bash /opt/compare/remote.sh product $p seed 0 1000000" 2>&1 | tee -a "$log" >&2
    t1=$(date +%s)
    list_ids "$p"
    t_usable=$(date +%s)
    [ "$p" != authentik ] || rsrv product authentik settle 2>&1 | tee -a "$log" >&2
    settle=$(rsrv settle /var/lib/docker/volumes)
  fi
  idle=$(rsrv idle "$p")
  size=$(rsrv store-size "$p")
  rsrv freeze "$p"
  clog "seed $p: snapshot of $vol"
  local snap
  snap=$(aws_snapshot "$vol" "$TAG-$p-seed")
  state_edit "$state/snapshots.env" "SNAP_$p=$snap"
  state_edit "$state/snapshots.env" "TAG_$p=$TAG"
  cost start "$ledger" snapshot "$snap" "$(python3 -I -c "import math; print(max(1, math.ceil($size / 1e9)))")"
  python3 -I - "$f" << PY
import json, sys
json.dump({
    "product": "$p", "server": "$server", "seed_procs": $procs, "users_bulk": 1000000, "users_login": 1000,
    "seed_time_comparable_with": "seeds on a $server server only",
    "seed_call_s": $((t1 - t0)), "seed_until_usable_s": $((t_usable - t0)),
    "usable_rule": "the admin API lists 1M users (ids.js)",
    "idle_rss_kb": int("${idle:-0}" or 0), "store_bytes": int("${size:-0}" or 0),
    "settle": "$settle", "pull": "$pull", "snapshot": "$snap", "run": "$id",
}, open(sys.argv[1], "w"), indent=1)
PY
  clog "seed $p: $(cat "$f" | tr -d '\n')"
}

# Lists the first 1M users' ids through the admin API (ids.js) into the
# bundle on the data volume, retrying until the API lists them all (Zitadel's
# projection applies an import after it answers).
list_ids() {
  local p=$1 i
  for i in $(seq 1 120); do
    if [ "$p" = hearth ]; then
      # The server is its own generator here (self_generator).
      launch_on_generator 1 ids-$i << EOF
K6_SCRIPT=ids.js
K6_NO_CSV=1
IDS_COUNT=1000000
IDS_OUT=/opt/stress/out/ids-$i/ids.txt
EOF
      wait_job "ids-$i" 3600
      srv "test \"\$(cat /opt/stress/out/ids-$i/k6.exit)\" = 0 && mkdir -p /data/bundle \
        && mv /opt/stress/out/ids-$i/ids.txt /data/bundle/ids-1000000.txt" && return 0
    else
      srv "cd /opt/compare/loadtest/compare && bash k6.sh /data/bundle ids.js IDS_COUNT=1000000 IDS_OUT=/out/ids.txt > /dev/null 2>&1 \
        && mv /data/bundle/out/ids.txt /data/bundle/ids-1000000.txt" && return 0
    fi
    clog "seed $p: the admin API does not list 1M users yet ($i)"
    sleep 30
  done
  cdie "seed $p: the admin API never listed 1M users"
}

# ---------------------------------------------------------------- ramps

snapshot_of() {
  local v
  v=$(sed -n "s/^SNAP_$1=//p" "$state/snapshots.env" | tail -n 1)
  [ -n "$v" ] || cdie "no snapshot for $1: compare.sh seed $1"
  echo "$v"
}

cmd_ramps() {
  local p=${1:?usage: compare.sh ramps <product> <size> [journey...]} size=${2:?}
  shift 2
  init_state
  local journeys=("$@")
  if [ "${#journeys[@]}" = 0 ]; then
    if [ -n "${JOURNEYS:-}" ]; then read -r -a journeys <<< "$JOURNEYS"
    elif [ "$size" = 1 ]; then journeys=("${ALL_JOURNEYS[@]}")
    else journeys=("${SIZE2_JOURNEYS[@]}"); fi
  fi
  local server gens
  case $size in
    1) server=c7i.large gens=2 ;;
    2) server=c7i.2xlarge gens=4 ;;
    *) cdie "size $size (1 or 2)" ;;
  esac
  local snap dir=$out/$p-s$size id="" left=0 j todo=()
  export COMPARE_PRODUCT=$p
  snap=$(snapshot_of "$p")
  mkdir -p "$dir"
  for j in "${journeys[@]}"; do
    if [ -s "$dir/$j.json" ]; then clog "$p size $size $j: done already"; else todo+=("$j"); fi
  done
  [ "${#todo[@]}" -gt 0 ] || return 0
  # The part (the journeys left) must end inside the AWS login window, and so
  # must each journey (an overrun part stops between journeys).
  local setup_h journey_h
  setup_h=$(plan_model setup_hours_per_ramp_run)
  journey_h=$(python3 -I -c "print(round($(plan_model minutes_per_journey) / 60, 3))")
  [ -n "${PART:-}" ] || login_gate "$p size $size (${#todo[@]} journeys)" "$(python3 -I -c "print(round($setup_h + ${#todo[@]} * $journey_h, 2))")"
  for j in "${todo[@]}"; do
    # A new set when the current one has less lifetime left than a ladder
    # can take (35 min), so no instance ends in the middle of a ramp.
    if [ -n "$id" ] && [ $((left - $(date +%s))) -lt 2100 ]; then
      clog "$p size $size: run $id is near its lifetime; a new set"
      run_down "$id"
      id=""
    fi
    if ! login_fits "$p size $size $j" "$(python3 -I -c "print($journey_h + (0 if '$id' else $setup_h))")"; then
      [ -z "$id" ] || run_down "$id"
      spend "$p size $size"
      login_exit
    fi
    if [ -z "$id" ]; then
      id=$(fresh_id "$session-$p-s$size")
      afford "$p size $size run $id" "$(estimate_usd 4 "$server:1" "c7i.xlarge:$gens")"
      run_up "$id" "$server" "$gens" 240 40 SERVER_DATA_SNAPSHOT="$snap" AWS_EXTRA_PORTS="$(ports_of "$p")"
      left=$(($(date +%s) + 240 * 60 - 600))
      in_run "$id" ramp_setup "$p" "$size" "$dir"
      spend "$p size $size setup"
    fi
    in_run "$id" ladder "$p" "$j" "$dir"
    spend "$p size $size $j"
  done
  [ -z "$id" ] || run_down "$id"
  spend "$p size $size"
}

# The server and generators of a ramp run: the seeded store from the snapshot
# volume, the product (or Hearth), k6 on the generators, and the working sets
# of the cold read.
ramp_setup() {
  local p=$1 size=$2 dir=$3 vol i
  vol=$(aws_data_volume_id)
  copy_compare
  rsrv data-pristine "$vol" | tee "$dir/prewarm-$RUN_ID.txt" >&2
  local bundle=$run/bundle-$p
  if [ "$p" = hearth ]; then
    # The seed's bundle (its config and keys go with its store), pointed at
    # this server; deploy installs Hearth on a fresh store, then the restore
    # swaps in the seeded one and the generators get its api secrets.
    [ -d "$state/hearth-bundle" ] || cdie "no Hearth seed bundle in $state"
    cp -a "$state/hearth-bundle" "$run/bundle"
    sed -i "s/^STRESS_SERVER_IP=.*/STRESS_SERVER_IP=$SERVER_PRIVATE/" "$run/bundle/generator.env"
    "$live/cloud.sh" deploy >&2
    load_run
    # deploy gave the fresh store's api client a new secret; the seeded store
    # (restored below) knows the seed's.
    local secrets i
    secrets=$(grep '^STRESS_API_SECRET' "$state/hearth-bundle/generator.env")
    [ -n "$secrets" ] || cdie "the Hearth seed bundle has no api secret"
    for i in $(seq 1 "$GEN_COUNT"); do
      ssh_to "$(gen_public "$i")" "sed -i '/^STRESS_API_SECRET\(_[0-9][0-9]*\)\?=/d' /opt/stress/generator.env && \
        cat >> /opt/stress/generator.env" <<< "$secrets"
    done
    restore hearth > /dev/null
  else
    rsrv install-docker >&2
    product_observers "$p"
    [ "$size" = 1 ] || rsrv scale 4 >&2
    rsrv pull "$p" | tee "$dir/pull-$RUN_ID.txt" >&2
    mkdir -p "$bundle"
    chmod 0700 "$bundle"
    scp_from "$SERVER_PUBLIC" /pristine/bundle/generator.env "$bundle/generator.env"
    scp_from "$SERVER_PUBLIC" /pristine/bundle/ca.crt "$bundle/ca.crt"
    sed -i "s/^STRESS_SERVER_IP=.*/STRESS_SERVER_IP=$SERVER_PRIVATE/" "$bundle/generator.env"
    for i in $(seq 1 "$GEN_COUNT"); do install_generator "$(gen_public "$i")" "$bundle"; done
    restore "$p" > /dev/null
  fi
  # Each generator walks its own share of each working set, so no id is read
  # twice by two generators within a step.
  local n
  for n in 100000 1000000; do
    for i in $(seq 1 "$GEN_COUNT"); do
      srv "head -n $n /pristine/bundle/ids-1000000.txt | awk -v g=$GEN_COUNT -v i=$i 'NR % g == i % g'" \
        | ssh_to "$(gen_public "$i")" "cat > /opt/stress/ids-$n.txt"
    done
  done
  # Hearth's deploy wrote cloud.sh's inventory; a product's is written here.
  [ "$p" = hearth ] || product_inventory "$p"
  { echo "product: $p"; echo "size: $size"; echo "snapshot volume: $vol"; } >> "$results/inventory.txt"
}

product_inventory() {
  local i
  {
    echo "run: $RUN_ID"
    echo "server: $(srv "nproc; free -m | awk '/^Mem:/ {print \$2\" MB\"}'; grep -m1 'model name' /proc/cpuinfo" | tr '\n' ' ')"
    for i in $(seq 1 "$GEN_COUNT"); do
      echo "generator $i: $(ssh_to "$(gen_public "$i")" "nproc; grep -m1 'model name' /proc/cpuinfo" | tr '\n' ' ')"
    done
    echo "images (images.env):"
    grep '_IMAGE=' "$compare_dir/images.env"
    echo "docker: $(srv "docker version --format '{{.Server.Version}}'")"
    echo "tooling revision: $(git -C "$compare_dir" rev-parse HEAD 2> /dev/null || echo unknown)"
    echo "k6: $k6_version"
    echo "vus per generator: $vus"
  } >> "$results/inventory.txt"
}

restore() {
  local p=$1
  rsrv restore "$p"
  [ "$p" != hearth ] || wait_hearth
}

wait_hearth() {
  for _ in $(seq 1 300); do
    hearth_ready && return 0
    sleep 2
  done
  die "Hearth did not become ready after the restore"
}

# One journey's ladder: the coarse phase, then the fine phase, each after a
# restore; the result in <dir>/<journey>.json.
ladder() {
  local p=$1 jk=$2 dir=$3 journey=$2 env="PRESENT=chain"
  case $jk in
    cold100k) journey=admin_lookup env+=" ADMIN_IDS_FILE=/opt/stress/ids-100000.txt" ;;
    cold1m) journey=admin_lookup env+=" ADMIN_IDS_FILE=/opt/stress/ids-1000000.txt" ;;
  esac
  local coarse fine phase_rates resumed=0
  coarse=$(lad coarse "$journey")
  phase "$p" "$jk" "$journey" "$env" coarse "$coarse" "$dir/$jk.coarse.json"
  # A coarse run that ended before its first failing step and before its 8th
  # step (a lost generator, say) goes on from the next rate, once.
  phase_rates=$(lad resume "$journey" "$dir/$jk.coarse.json")
  if [ "$phase_rates" != "[]" ] && [ "$resumed" = 0 ]; then
    resumed=1
    clog "$p $jk: the coarse run ended early; resuming at $phase_rates"
    phase "$p" "$jk" "$journey" "$env" coarse2 "$phase_rates" "$dir/$jk.coarse2.json"
    python3 -I - "$dir/$jk.coarse.json" "$dir/$jk.coarse2.json" << 'PY'
import json, sys
a = [v for v in json.load(open(sys.argv[1])) if v["clean"] is not None]
json.dump(a + json.load(open(sys.argv[2])), open(sys.argv[1], "w"))
PY
  fi
  fine=$(lad next "$p" "$dir/$jk.coarse.json" | jget fine)
  local args=("$dir/$jk.coarse.json")
  if [ "$fine" != None ] && [ "$fine" != null ]; then
    phase "$p" "$jk" "$journey" "$env" fine "$fine" "$dir/$jk.fine.json"
    args+=("$dir/$jk.fine.json")
  fi
  lad journey "$p" "$jk" "${args[@]}" > "$dir/$jk.json"
  clog "$p $jk: clean rate $(jget clean_rate < "$dir/$jk.json")/s$(
    [ "$(jget at_least < "$dir/$jk.json")" = True ] && echo " (at least)") $(jget flags < "$dir/$jk.json")"
}

# One phase: restore, then one k6 run of a warm-up minute at the first rate
# and one step per rate; a watcher stops it at the first step that fails for
# sure; the verdicts go to $7. $6: the rates (/s) as a JSON list.
phase() {
  local p=$1 jk=$2 journey=$3 env=$4 kind=$5 rates_json=$6 verdicts=$7
  local rates name pm k
  rates=$(python3 -I -c 'import json,sys; print(" ".join(str(r) for r in json.loads(sys.argv[1])))' "$rates_json")
  # shellcheck disable=SC2086 # one rate per word
  pm=$(lad rates-pm "$GEN_COUNT" ${rates%% *} $rates | python3 -I -c 'import json,sys; print(",".join(map(str, json.load(sys.stdin))))')
  for k in $(seq 1 99); do
    name=$jk-$kind-$k
    [ -e "$results/$name" ] || break
  done
  clog "$p $jk $kind: restore, then $rates /s (warm-up at the first)"
  restore "$p" | tee -a "$results/restore.txt" >&2
  # The warm-up is step 0: never judged; the rates are steps 1 ...
  (RATES_PM=$pm K6_ENV=$env cmd_ramp "$name" "$journey" 0 0 0 60) &
  local ramp=$! stopped=-1
  stopped=$(watch_ramp "$p" "$journey" "$name" "$ramp")
  wait "$ramp" || clog "$p $jk $kind: the ramp ended with an error (judged on what it collected)"
  [ -f "$results/$name/report.json" ] || echo '{"steps": []}' > "$results/$name/report.json"
  python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); r.setdefault("journey", sys.argv[2]); json.dump(r, open(sys.argv[1], "w"))' \
    "$results/$name/report.json" "$journey"
  # shellcheck disable=SC2086
  lad judge "$p" "$results/$name/report.json" "$stopped" $rates > "$verdicts"
  echo "$stopped" > "$results/$name/stopped-at"
}

# While ramp $4 runs: every 15 s, each generator's k6 REST API; at the first
# step that fails for sure, stops k6 everywhere. Prints the step it stopped
# at, or -1.
watch_ramp() {
  local p=$1 journey=$2 name=$3 ramp=$4 i start_at stop
  local dir=$results/$name
  while kill -0 "$ramp" 2> /dev/null; do
    sleep 15
    [ -f "$dir/params.env" ] || continue
    start_at=$(sed -n 's/^START_AT=//p' "$dir/params.env")
    local files=()
    for i in $(seq 1 "$GEN_COUNT"); do
      ssh_to "$(gen_public "$i")" "curl -fsS -m 5 localhost:6565/v1/metrics" > "$dir/live-g$i.json" 2> /dev/null \
        && files+=("$dir/live-g$i.json")
    done
    [ "${#files[@]}" -gt 0 ] || continue
    stop=$(lad live "$p" "$journey" "$(date +%s)" "$start_at" 60 "${files[@]}" | jget stop)
    if [ "$stop" != None ]; then
      clog "$p $journey: step $stop fails for sure; stopping the run"
      for i in $(seq 1 "$GEN_COUNT"); do
        ssh_to "$(gen_public "$i")" "curl -fsS -m 5 -X PATCH -H 'Content-Type: application/json' \
          -d '{\"data\":{\"type\":\"status\",\"id\":\"default\",\"attributes\":{\"stopped\":true}}}' \
          localhost:6565/v1/status" > /dev/null 2>&1 || true
      done
      echo "$stop"
      return 0
    fi
  done
  echo -1
}

# ---------------------------------------------------------------- session

# The journeys of a ramps part at size $1.
journeys_of() {
  if [ -n "${JOURNEYS:-}" ]; then
    echo "$JOURNEYS"
  elif [ "$1" = 1 ]; then
    echo "${ALL_JOURNEYS[*]}"
  else
    echo "${SIZE2_JOURNEYS[*]}"
  fi
}

# The product of part s2:other (after the size 1 results: fastest.json).
other_product() {
  [ -s "$out/fastest.json" ] || return 1
  jget product < "$out/fastest.json"
}

# Whether a part of the plan (seed:<p>, s1:<p>, drill, s2:<p>, s2:other) is
# done: its results exist.
part_done() {
  local kind=${1%%:*} p=${1#*:} j
  case $kind in
    seed) [ -s "$out/seed-$p.json" ] ;;
    drill) [ -s "$out/drill.done" ] ;;
    s1 | s2)
      if [ "$p" = other ]; then p=$(other_product) || return 1; fi
      for j in $(journeys_of "${kind#s}"); do [ -s "$out/$p-$kind/$j.json" ] || return 1; done
      ;;
  esac
}

# The compare.sh command of a part.
part_cmd() {
  case $1 in
    seed:*) echo "seed ${1#seed:}" ;;
    s1:*) echo "ramps ${1#s1:} 1" ;;
    s2:other) echo "ramps $(other_product) 2" ;;
    s2:*) echo "ramps ${1#s2:} 2" ;;
    drill) echo drill ;;
  esac
}

# The size 2 product: #913's rule over the size 1 results.
choose_other() {
  python3 -I - "$out" "${PRODUCTS[@]}" > "$out/size1.json" << 'PY'
import json, os, sys
out, products = sys.argv[1], sys.argv[2:]
journeys = ["login", "refresh", "client_credentials", "userinfo", "introspect", "admin_lookup", "create_user", "mix"]
res = {}
for p in products:
    res[p] = {}
    for j in journeys:
        f = os.path.join(out, f"{p}-s1", f"{j}.json")
        res[p][j] = json.load(open(f))["clean_rate"] if os.path.exists(f) else 0
json.dump(res, sys.stdout, indent=1)
PY
  lad fastest "$out/size1.json" > "$out/fastest.json"
  clog "size 2: hearth and $(other_product) (the highest geometric mean of the 8 clean rates at size 1)"
}

timeline() { printf '%s %s\n' "$(date +%s)" "$*" >> "$out/timeline.txt"; }

kill_tree() {
  local c
  for c in $(pgrep -P "$1" 2> /dev/null); do kill_tree "$c"; done
  kill -TERM "$1" 2> /dev/null || true
}

# The session's running parts, by pid.
declare -A S_PART=() S_VCPU=()
S_USED=0

# Stops every running part and tears down every run.
session_cleanup() {
  local pid
  for pid in "${!S_PART[@]}"; do kill_tree "$pid"; done
  wait 2> /dev/null || true
  : > "$state/parts.active"
  down_all
}

session_stop() {
  local rc=$1
  shift
  clog "$*: stopping every part"
  session_cleanup
  trap - EXIT
  exit "$rc"
}

cmd_session() {
  init_state
  [ -n "${IMAGE:-}" ] || cdie "set IMAGE to the Hearth image (cloud.sh)"
  (aws_check_identity) > /dev/null 2>&1 || cdie "the aws CLI is not logged in: run aws login, then compare.sh session"
  local max_vcpu=${MAX_VCPU:-56}
  [[ $max_vcpu =~ ^[0-9]+$ ]] || cdie "MAX_VCPU $max_vcpu"
  # The login window starts now: run the session right after `aws login`.
  export LOGIN_AT=${LOGIN_AT:-$(date +%s)}
  state_edit "$state/login.env" "LOGIN_AT=$LOGIN_AT"
  clog "AWS login window: until $(et "$(python3 -I -c "print(int($LOGIN_AT + $login_window_h * 3600))")") (LOGIN_WINDOW_H $login_window_h); MAX_VCPU $max_vcpu"
  # Runs an earlier session left up (its credentials ran out during a part,
  # say) go down first, and their ledger entries close.
  if [ -s "$state/runs.active" ]; then
    clog "runs left up by an earlier session: $(cut -d' ' -f1 "$state/runs.active" | tr '\n' ' ')"
    down_all
  fi
  rm -f "$state/STOPPED"
  : > "$state/parts.active"
  MAX_VCPU=$max_vcpu cost estimate "$aws_dir/session-plan.json" > "$out/plan.json"
  ! grep -q '"error"' "$out/plan.json" || cdie "the plan does not fit: $(jget schedule error < "$out/plan.json")"
  clog "plan: $(jget total < "$out/plan.json") USD, $(jget hours < "$out/plan.json") instance-set hours, wall clock $(jget schedule wall_clock_h < "$out/plan.json") h, $(jget schedule logins < "$out/plan.json") login(s)"
  trap session_cleanup EXIT
  local order=() part
  read -r -a order <<< "$(python3 -I -c 'import json,sys; print(" ".join(p["id"] for p in json.load(open(sys.argv[1]))["parts"] if p.get("id")))' "$aws_dir/session-plan.json")"
  local -A status=()
  for part in "${order[@]}"; do
    if part_done "$part"; then status[$part]=done; else status[$part]=pending; fi
  done
  # Starts every part that can start, in plan order, then waits for one to
  # end; until nothing runs and nothing can start.
  local hours vcpu usd fin rc pid args=() q
  while :; do
    for part in "${order[@]}"; do
      [ "${status[$part]}" = pending ] || continue
      case $part in
        s1:*) [ "${status[seed:${part#s1:}]}" = done ] || continue ;;
        s2:*)
          for q in "${order[@]}"; do
            [[ $q != s1:* ]] || [ "${status[$q]}" = done ] || continue 2
          done
          other_product > /dev/null || choose_other
          ;;
      esac
      read -r hours vcpu usd <<< "$(cost part "$aws_dir/session-plan.json" "$part")"
      [ "$vcpu" -le "$max_vcpu" ] || cdie "$part needs $vcpu vCPUs, more than MAX_VCPU $max_vcpu"
      if [ $((S_USED + vcpu)) -gt "$max_vcpu" ]; then
        if [ "${status[$part.vcpu]:-}" != said ]; then
          clog "$part waits: its $vcpu vCPUs would make $((S_USED + vcpu)) running, over MAX_VCPU $max_vcpu"
          timeline "wait-vcpu $part need=$vcpu running=$S_USED"
          status[$part.vcpu]=said
        fi
        continue
      fi
      if ! login_fits "$part" "$hours"; then
        status[$part]=later
        continue
      fi
      if ! fits_cap "$part" "$usd"; then
        status[$part]=refused
        continue
      fi
      read -r -a args <<< "$(part_cmd "$part")"
      PART=$part "$0" "${args[@]}" >> "$out/driver-${part/:/-}.log" 2>&1 &
      pid=$!
      S_PART[$pid]=$part
      S_VCPU[$pid]=$vcpu
      S_USED=$((S_USED + vcpu))
      status[$part]=running
      state_edit "$state/parts.active" "$part $usd $hours $(date +%s)"
      timeline "start $part vcpu=$vcpu running=$S_USED"
      clog "$part started (compare.sh ${args[*]}; about $hours h, \$$usd, $vcpu vCPUs; $S_USED of $max_vcpu running)"
    done
    [ "${#S_PART[@]}" -gt 0 ] || break
    rc=0
    wait -n -p fin || rc=$?
    [ -n "${fin:-}" ] && [ -n "${S_PART[$fin]:-}" ] || continue
    part=${S_PART[$fin]}
    S_USED=$((S_USED - S_VCPU[$fin]))
    unset "S_PART[$fin]" "S_VCPU[$fin]"
    state_edit "$state/parts.active" -d "\\|^$part |"
    timeline "end $part rc=$rc"
    [ ! -e "$state/STOPPED" ] || session_stop 3 "$(tail -n 1 "$state/STOPPED")"
    case $rc in
      0) status[$part]=done ;;
      4) status[$part]=later ;;
      3) session_stop 3 "$part stopped at STOP_USD" ;;
      *) session_stop 1 "$part failed (exit $rc): $out/driver-${part/:/-}.log" ;;
    esac
    clog "$part ended (exit $rc); $S_USED of $max_vcpu vCPUs running"
  done
  trap - EXIT
  down_all
  local later=() refused=()
  for part in "${order[@]}"; do
    case ${status[$part]} in
      later | pending) later+=("$part") ;;
      refused) refused+=("$part") ;;
    esac
  done
  [ "${#refused[@]}" = 0 ] || cdie "not started, over the \$$cap_usd cap: ${refused[*]}"
  if [ "${#later[@]}" -gt 0 ]; then
    clog "left for the next login: ${later[*]}"
    clog "stopped before the AWS login window ends: run aws login, then compare.sh session again (it resumes; finished seeds, journeys and the drill are kept)"
    exit 4
  fi
  summary
  clog "session done: $(cost check "$ledger" 1000000) USD; snapshots kept: compare.sh snapshots"
}

cmd_drill() {
  init_state
  [ ! -s "$out/drill.done" ] || { clog "the drill ran already"; return 0; }
  [ -n "${PART:-}" ] || login_gate "the #647 drill" "$(cost part "$aws_dir/session-plan.json" drill | cut -d' ' -f1)"
  afford "the #647 drill" "$(estimate_usd 2 r7i.large:1 c7i.xlarge:1)"
  local id
  id=$(fresh_id "$session-drill")
  cost start "$ledger" instance "$id-server" r7i.large 150
  # cloud.sh gives every instance of a run the same root disk (AWS_DISK_GB).
  cost start "$ledger" instance "$id-gen1" c7i.xlarge 150
  state_edit "$state/runs.active" "$id 1"
  # The #647 path, unchanged: round.sh with a plan of one drill line. The
  # drill seeds its own 10M users on an empty store, so the setup's import
  # (round.sh SETUP=1) is only the 1,000 login users' worth (USERS=1000).
  STRESS_RUN=$id SETUP=1 USERS=1000 SERVER_SIZE=r7i.large AWS_DISK_GB=150 GENERATORS=1 \
    AWS_MAX_MINUTES=${DRILL_MAX_MINUTES:-300} \
    PLAN_FILE="$live/plans/913-drill-r7i-large-10m.txt" "$live/round.sh" 2>&1 | tee "$out/drill.log" >&2 || true
  # round.sh tore the run down (its EXIT trap); close the ledger.
  cost end "$ledger" "$id-server"
  cost end "$ledger" "$id-gen1"
  cost data-out "$ledger" "$(du -sb "$live/results/$id" 2> /dev/null | cut -f1 || echo 0)"
  state_edit "$state/runs.active" -d "/^$id /"
  echo done > "$out/drill.done"
  spend "the #647 drill"
}

summary() {
  python3 -I - "$out" > "$out/summary.md" << 'PY'
import glob, json, os, sys
out = sys.argv[1]
print("# #913 session results\n")
print("| product | size | journey | clean rate /s | p99 ms | CPU % | RSS MB | write IOPS | flags |")
print("|---|---|---|---|---|---|---|---|---|")
for f in sorted(glob.glob(os.path.join(out, "*-s[12]", "*.json"))):
    if f.endswith((".coarse.json", ".coarse2.json", ".fine.json")):
        continue
    r = json.load(open(f))
    size = os.path.basename(os.path.dirname(f)).rsplit("-s", 1)[1]
    rate = f"{'>= ' if r['at_least'] else ''}{r['clean_rate']}"
    print(f"| {r['product']} | {size} | {r['journey']} | {rate} | {r['p99_ms']} | {r['server_cpu_pct_mean']} "
          f"| {r['server_rss_mb_max']} | {r['disk_write_iops_mean']} | {', '.join(r['flags'])} |")
# The seed times compare only between seeds on the same server type: one
# table per type.
seeds = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(out, "seed-*.json")))]
servers = sorted({s["server"] for s in seeds}, key=lambda t: (t != "c7i.large", t))
for server in servers:
    others = [t for t in servers if t != server]
    print(f"\n## Seeds on {server}\n")
    if others:
        print(f"Seed times here compare only with each other, not with the seeds on {', '.join(others)}.\n")
    print("| product | seed server | seed call s | until usable s | idle RSS MB | store GB |")
    print("|---|---|---|---|---|---|")
    for s in seeds:
        if s["server"] == server:
            print(f"| {s['product']} | {s['server']} | {s['seed_call_s']} | {s['seed_until_usable_s']} "
                  f"| {s['idle_rss_kb'] / 1024:.0f} | {s['store_bytes'] / 1e9:.2f} |")
PY
  cat "$out/cost.txt" >> "$out/summary.md" 2> /dev/null || true
}

cmd_snapshots() {
  init_state
  local p tag
  for p in "${PRODUCTS[@]}"; do
    tag=$(sed -n "s/^TAG_$p=//p" "$state/snapshots.env" | tail -n 1)
    [ -z "$tag" ] || aws_list_snapshots "$tag"
  done
}

cmd_delete_snapshots() {
  init_state
  [ "$#" -gt 0 ] || cdie "usage: compare.sh delete-snapshots <snapshot id>... (see compare.sh snapshots)"
  local s
  for s in "$@"; do
    grep -q "^SNAP_[a-z]*=$s$" "$state/snapshots.env" || cdie "$s is not a snapshot of session $session"
  done
  clog "deleting: $*"
  for s in "$@"; do
    aws_delete_snapshot "$s"
    cost end "$ledger" "$s"
    state_edit "$state/snapshots.env" -d "/=$s$/"
    clog "deleted $s"
  done
  cmd_snapshots
}

case ${1:-} in
  plan)
    cost estimate "$aws_dir/session-plan.json"
    cost brief "$aws_dir/session-plan.json"
    ;;
  seed) shift; cmd_seed "$@" ;;
  ramps) shift; cmd_ramps "$@" ;;
  session) shift; cmd_session "$@" ;;
  drill) shift; cmd_drill "$@" ;;
  cost) init_state; cost total "$ledger" ;;
  snapshots) cmd_snapshots ;;
  delete-snapshots) shift; cmd_delete_snapshots "$@" ;;
  down-all) init_state; down_all ;;
  *)
    sed -n '2,/^set -euo/p' "$0" | sed '$d'
    exit 2
    ;;
esac
