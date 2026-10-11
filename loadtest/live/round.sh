#!/usr/bin/env bash
# Runs one round of the live stress test from a plan, then deletes every resource
# of the run (KEEP=1 leaves them up). See README.md § "Running a round".
#
#   SETUP=1 IMAGE=hearth-stress:<tag> PLAN_FILE=<plan> loadtest/live/round.sh
#
# Plan lines (# starts a comment):
#   ramp <name> <journey> <start> <step> <steps> <hold_s>
#   soak <name> <journey> <rate> <seconds> [malloc_info minutes, e.g. 35,59]
#
# Before each line: the image's binary is installed, the post-import store copy
# is restored, the page cache is dropped, Hearth restarts, and
# POST /admin/bootstrap must answer 404 (a production build). During each line,
# vmstat runs on every generator, so a generator-bound result is visible.
#
# Settings (environment), on top of cloud.sh's:
#   SETUP=1      first: up, deploy, a dsync disk check, import USERS, store copy
#   USERS        1000000 (users imported by SETUP)
#   IMAGE        Docker image the binary comes from (needs a revision label)
#   PLAN_FILE    the plan; default: the PLAN variable
#   KEEP=1       leave the run up at the end
#
# Results: results/<run>/<name>/ as cloud.sh writes them, plus variant.txt,
# vmstat-gen<i>-<name>.txt and, for a soak, m<minute>.malloc_info.xml.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
c=$here/cloud.sh
export PROVIDER=${PROVIDER:-aws} GENERATORS=${GENERATORS:-2} VUS=${VUS:-1000}
: "${IMAGE:?set IMAGE to the Docker image to test}"
export IMAGE
if [ -n "${PLAN_FILE:-}" ]; then plan=$(cat "$PLAN_FILE"); else plan=${PLAN:?set PLAN_FILE or PLAN}; fi

note() { printf '\n=== %s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
cleanup() {
  [ "${KEEP:-}" = 1 ] && { note "KEEP=1: resources left up"; return; }
  note "down"
  "$c" down
}
trap cleanup EXIT

if [ "${SETUP:-}" = 1 ]; then
  export AWS_DISK_GB=${AWS_DISK_GB:-40}
  note "up"
  "$c" up || exit 1
fi
run=$(command ls -1d "$here"/.build/run-* | sort | tail -n 1)
# shellcheck disable=SC1091
. "$run/run.env"
results=$here/results/$RUN_ID
mkdir -p "$results"
ssh_opts=(-i "$run/id_ed25519" -o UserKnownHostsFile="$run/known_hosts" -o BatchMode=yes
  -o ConnectTimeout=10 -o ServerAliveInterval=30)
s() { ssh "${ssh_opts[@]}" "root@$SERVER_PUBLIC" "$@"; }
sg() { local h=$1; shift; ssh "${ssh_opts[@]}" "root@$h" "$@"; }
sp() { scp -q "${ssh_opts[@]}" "$@"; }

if [ "${SETUP:-}" = 1 ]; then
  note "deploy ($IMAGE)"
  "$c" deploy || exit 1
  s 'dd if=/dev/zero of=/var/lib/hearth/dd.test bs=4k count=2000 oflag=dsync 2>&1 | tail -n 1; rm -f /var/lib/hearth/dd.test' \
    | tee "$results/disk-dsync.txt"
  note "import 0..${USERS:-1000000}"
  "$c" import 0 "${USERS:-1000000}" | tee "$results/import.json" || exit 1
  note "store copy"
  s 'systemctl stop hearth && cp -a /var/lib/hearth /var/lib/hearth.base && du -sh /var/lib/hearth.base && df -h /' \
    | tee "$results/store-copy.txt" || exit 1
fi

# Installs the binary, restores the store copy, drops the page cache, starts
# Hearth and writes $run/variant-$1.txt. Returns 1 on failure.
prepare() {
  local name=$1 rev cid code
  "$c" allow-ssh-here || note "allow-ssh-here FAILED"
  rev=$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
  [ -n "$rev" ] || { note "image $IMAGE has no revision label"; return 1; }
  note "$name: $IMAGE ($rev); restore store, drop caches, restart"
  if [ ! -f "$run/hearth-$rev" ]; then
    cid=$(docker create "$IMAGE")
    docker cp "$cid:/usr/local/bin/hearth" "$run/hearth-$rev" > /dev/null
    docker rm "$cid" > /dev/null
  fi
  sp "$run/hearth-$rev" "root@$SERVER_PUBLIC:/opt/hearth/hearth.new" || return 1
  # No `pkill -f` here: a pattern for the store copy also matches this shell's
  # own command line, which contains the `cp -a` below.
  s "set -e
    systemctl stop hearth || true
    install -m 0755 /opt/hearth/hearth.new /opt/hearth/hearth && rm /opt/hearth/hearth.new
    rm -rf /var/lib/hearth && cp -a /var/lib/hearth.base /var/lib/hearth
    [ ! -f /opt/hearth/out/hearth.log ] || mv /opt/hearth/out/hearth.log /opt/hearth/out/hearth-before-$name.log
    sync; echo 3 > /proc/sys/vm/drop_caches" || { note "$name: remote restore failed"; return 1; }
  "$c" restart || return 1
  code=$(s "curl -sk -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:8443/admin/bootstrap")
  {
    echo "name: $name"
    echo "image: $IMAGE"
    echo "revision: $rev"
    echo "restart: $(date -u +%FT%TZ) (store restored from the post-import copy, page cache dropped)"
    echo "POST /admin/bootstrap: $code"
    s 'echo "thp: $(cat /sys/kernel/mm/transparent_hugepage/enabled)"; /opt/hearth/hearth --version
      grep -E "glibc malloc|argon2id|kdf admission|hot tier" /opt/hearth/out/hearth.log | head -n 8'
  } > "$run/variant-$name.txt" 2>&1
  [ "$code" = 404 ] || { note "$name: bootstrap answered $code: not a production build"; return 1; }
}

# Runs "$@" (a cloud.sh ramp) with vmstat on every generator, then files the notes.
observed() {
  local name=$1 i host pids=()
  shift
  for i in $(seq 1 "$GEN_COUNT"); do
    host=GEN${i}_PUBLIC
    sg "${!host}" 'vmstat -n -t 5' < /dev/null > "$run/vmstat-gen$i-$name.txt" 2>&1 &
    pids+=($!)
  done
  "$@" || note "$name: FAILED (rc=$?)"
  kill "${pids[@]}" 2> /dev/null
  wait "${pids[@]}" 2> /dev/null
  mkdir -p "$results/$name"
  cp "$run/variant-$name.txt" "$results/$name/variant.txt" 2> /dev/null || true
  for i in $(seq 1 "$GEN_COUNT"); do
    cp "$run/vmstat-gen$i-$name.txt" "$results/$name/" 2> /dev/null || true
  done
}

ramp() {
  local name=$1 journey=$2 start=$3 step=$4 steps=$5 hold=$6
  prepare "$name" || { note "$name: prepare FAILED"; return; }
  note "$name: ramp $journey $start/s by $step/s, $steps steps of $hold s"
  observed "$name" "$c" ramp "$name" "$journey" "$start" "$step" "$steps" "$hold"
}

soak() {
  local name=$1 journey=$2 rate=$3 secs=$4 minutes=${5:-} out=$results/$1 start_at m f
  prepare "$name" || { note "$name: prepare FAILED"; return; }
  note "$name: soak $journey $rate/s for $secs s"
  observed "$name" "$c" ramp "$name" "$journey" "$rate" 0 1 "$secs" &
  local rp=$!
  if [ -n "$minutes" ]; then
    for _ in $(seq 1 120); do grep -q '^START_AT=' "$out/params.env" 2> /dev/null && break; sleep 2; done
    start_at=$(sed -n 's/^START_AT=//p' "$out/params.env" 2> /dev/null)
    for m in ${minutes//,/ }; do
      [ -n "$start_at" ] || { note "$name: no START_AT; malloc_info not scheduled"; break; }
      s "systemd-run --unit=mi-$name-$m --collect --quiet \
        --on-active=\$(( $start_at + $m * 60 - \$(date +%s) ))s /opt/hearth/malloc-info.sh $name-m$m" \
        || note "$name: scheduling malloc_info at minute $m FAILED"
    done
  fi
  wait "$rp"
  for m in ${minutes//,/ }; do
    for f in malloc_info.xml malloc-state.txt; do
      sp "root@$SERVER_PUBLIC:/opt/hearth/out/$name-m$m.$f" "$out/m$m.$f" 2> /dev/null \
        || note "$name: no minute-$m $f"
    done
  done
}

# The plan is read on fd 3: ssh inside the loop would read stdin and eat it.
while read -r -u 3 kind name rest; do
  case $kind in
    '' | '#'*) continue ;;
    ramp) read -r journey start step steps hold <<< "$rest"
      ramp "$name" "$journey" "$start" "$step" "$steps" "$hold" < /dev/null ;;
    soak) read -r journey rate secs minutes <<< "$rest"
      soak "$name" "$journey" "$rate" "$secs" "${minutes:-}" < /dev/null ;;
    *) note "unknown plan line: $kind $name $rest" ;;
  esac
done 3<<< "$plan"
note "round done: $results"
