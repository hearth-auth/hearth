#!/usr/bin/env bash
# Runs one round of the live stress test from a plan, then deletes every resource
# of the run (KEEP=1 leaves them up). See README.md § "Running a round".
#
#   SETUP=1 IMAGE=hearth-stress:<tag> PLAN_FILE=<plan> loadtest/live/round.sh
#
# Plan lines (# starts a comment):
#   ramp <name> <journey> <start> <step> <steps> <hold_s>
#   soak <name> <journey> <rate> <seconds> [malloc_info minutes, e.g. 35,59]
#   restart <name>
#       a clean stop, the page cache dropped, then a start timed to the first
#       200 from /readyz (the "start" file: seconds and outcome)
#   crash <name> <journey> <rate> <seconds> <kill_at_s> [k6 settings]
#       a load at <rate>; kill -9 at <kill_at_s>, a start at once, timed as
#       above; then cloud.sh verify (acknowledged users that are missing). For
#       the mix, add create_user so that there are writes to check, e.g.
#       MIX=refresh:60,login:15,userinfo:15,admin_lookup:5,create_user:5
#   backup <name> <journey> <rate> <hold_s>
#       3 equal steps of <hold_s> at <rate>; POST /admin/backup on the server
#       when step 2's hold starts. Step 1 is the latency without a backup,
#       step 2 the latency during it (the "backup" file: seconds, exit status,
#       archive bytes). Make <hold_s> longer than the backup.
#   drill <name> <users>
#       restore-drill.sh on the server with <users> users: backup, restore and
#       compare times (drill/). It replaces the server's config and data, so
#       it must be the last line of a plan.
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
#   HEAPTRACK=1  run each plan line's Hearth under heaptrack, and end each soak
#                with kill -9, so the trace's "leaked" memory is the live heap
#                (needs an image with symbols: README, "Heap accounting")
#   JEPROF=1     turn on jemalloc's heap profiler in each plan line's Hearth: a
#                heap profile every 15 minutes (needs an image built with
#                --features heap-profile: README, "Heap accounting")
#
# Results: results/<run>/<name>/ as cloud.sh writes them, plus variant.txt,
# vmstat-gen<i>-<name>.txt and, for a soak, m<minute>.malloc_info.xml and, with
# HEAPTRACK=1, heaptrack.zst, and with JEPROF=1, jeprof.tar.gz.
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
  if [ "${HEAPTRACK:-}" = 1 ]; then
    heaptrack_setup || { note "$name: heaptrack setup FAILED"; return 1; }
  fi
  if [ "${JEPROF:-}" = 1 ]; then
    jeprof_setup || { note "$name: jeprof setup FAILED"; return 1; }
  fi
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

# Runs Hearth under heaptrack from its next start: one trace per start, in
# /opt/hearth/out/heaptrack (prepare deletes /var/lib/hearth). Setup and the
# import run without it, at full speed.
heaptrack_setup() {
  s "set -e
    if ! command -v heaptrack > /dev/null; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get -qq update > /dev/null
      apt-get -qq install -y heaptrack > /dev/null
    fi
    install -d -o hearth -g hearth /opt/hearth/out/heaptrack
    cat > /opt/hearth/heaptrack-hearth.sh << 'EOF'
#!/bin/sh
# Hearth under heaptrack (round.sh HEAPTRACK=1), one trace per start.
exec /usr/bin/heaptrack -o /opt/hearth/out/heaptrack/hearth-\$(date -u +%Y%m%dT%H%M%SZ) \\
  /opt/hearth/hearth serve -c /opt/hearth/hearth.yaml
EOF
    chmod 0755 /opt/hearth/heaptrack-hearth.sh
    mkdir -p /etc/systemd/system/hearth.service.d
    printf '[Service]\nExecStart=\nExecStart=/opt/hearth/heaptrack-hearth.sh\n' \
      > /etc/systemd/system/hearth.service.d/heaptrack.conf
    systemctl daemon-reload"
}

# Ends a heaptrack soak. kill -9 leaves Hearth's live heap as the trace's
# "leaked" memory; heaptrack's interpreter writes the file when its pipe closes.
heaptrack_collect() {
  local name=$1 out=$2 f
  f=$(s "pkill -9 -x hearth || true
    for _ in \$(seq 1 360); do systemctl is-active -q hearth || break; sleep 5; done
    ls -t /opt/hearth/out/heaptrack/hearth-* 2> /dev/null | head -n 1")
  [ -n "$f" ] || { note "$name: no heaptrack trace"; return; }
  sp "root@$SERVER_PUBLIC:$f" "$out/heaptrack.${f##*.}" || { note "$name: fetching $f FAILED"; return; }
  note "$name: heaptrack trace $(du -h "$out/heaptrack.${f##*.}" | cut -f1)"
}

# A clean stop, the page cache dropped, and a start timed to ready (#647).
restart() {
  local name=$1 out=$results/$1
  prepare "$name" || { note "$name: prepare FAILED"; return; }
  mkdir -p "$out"
  cp "$run/variant-$name.txt" "$out/variant.txt" 2> /dev/null || true
  note "$name: clean stop, drop caches, timed start"
  s "systemctl stop hearth && sync && echo 3 > /proc/sys/vm/drop_caches && /opt/hearth/timed-start.sh $name" \
    || note "$name: Hearth did not become ready"
  sp "root@$SERVER_PUBLIC:/opt/hearth/out/$name.start" "$out/start" || note "$name: no start file"
  note "$name: start to ready: $(cat "$out/start" 2> /dev/null)"
}

# A load with kill -9 and a start at once, timed to ready; then a check that
# every acknowledged user is still there (#647).
crash() {
  local name=$1 journey=$2 rate=$3 secs=$4 kill_at=$5 k6env=${6:-}
  prepare "$name" || { note "$name: prepare FAILED"; return; }
  note "$name: $journey at $rate/s for $secs s, kill -9 at $kill_at s, timed start"
  observed "$name" env KILL_RESTART=1 K6_ENV="$k6env" "$c" ramp "$name" "$journey" "$rate" 0 1 "$secs" "$kill_at"
  # The start can outlast the load: wait for timed-start.sh (at most 1,800 s).
  s "for _ in \$(seq 1 1810); do [ -f /opt/hearth/out/$name.start ] && break; sleep 1; done" \
    && sp "root@$SERVER_PUBLIC:/opt/hearth/out/$name.start" "$results/$name/start" \
    || note "$name: no start file"
  note "$name: start to ready: $(cat "$results/$name/start" 2> /dev/null)"
  "$c" verify "$name" > "$results/$name/verify.json" || note "$name: verify FAILED"
  note "$name: verify: $(tr -d ' \n' < "$results/$name/verify.json")"
}

# POST /admin/backup on the server during step 2 of a 3-step load (#647).
backup() {
  local name=$1 journey=$2 rate=$3 hold=$4 out=$results/$1 start_at at
  prepare "$name" || { note "$name: prepare FAILED"; return; }
  s "rm -rf /opt/hearth/drill /var/lib/hearth-backup && install -d -m 0700 /opt/hearth/drill /var/lib/hearth-backup" \
    && sp "$here/restore_drill.py" "$run/bundle/generator.env" "root@$SERVER_PUBLIC:/opt/hearth/drill/" \
    || { note "$name: copying the backup client FAILED"; return; }
  note "$name: $journey at $rate/s, 3 steps of $hold s, POST /admin/backup at the start of step 2"
  observed "$name" "$c" ramp "$name" "$journey" "$rate" 0 3 "$hold" &
  local rp=$!
  for _ in $(seq 1 600); do grep -q '^START_AT=' "$out/params.env" 2> /dev/null && break; sleep 2; done
  start_at=$(sed -n 's/^START_AT=//p' "$out/params.env" 2> /dev/null)
  if [ -n "$start_at" ]; then
    # Step 2's hold starts after two ramp-ups (RAMP_S, 5 s) and step 1's hold.
    at=$((start_at + hold + 10))
    sleep $((at - $(date +%s) > 0 ? at - $(date +%s) : 0))
    s "cd /opt/hearth/drill && t0=\$(date +%s.%N)
      python3 restore_drill.py backup --target generator.env --ca /opt/hearth/ca.crt \
        --output /var/lib/hearth-backup/archive > /opt/hearth/out/$name.backup.log 2>&1
      rc=\$?
      awk -v a=\$t0 -v b=\$(date +%s.%N) -v rc=\$rc -v n=\$(stat -c %s /var/lib/hearth-backup/archive 2> /dev/null || echo 0) \
        'BEGIN { printf \"%.1f %s %s\\n\", b - a, rc, n }' > /opt/hearth/out/$name.backup"
  else
    note "$name: no START_AT; no backup"
  fi
  wait "$rp"
  sp "root@$SERVER_PUBLIC:/opt/hearth/out/$name.backup" "root@$SERVER_PUBLIC:/opt/hearth/out/$name.backup.log" "$out/" \
    || note "$name: no backup file"
  note "$name: backup seconds, exit status, bytes: $(cat "$out/$name.backup" 2> /dev/null)"
  s "rm -rf /var/lib/hearth-backup /opt/hearth/drill"
}

# restore-drill.sh on the server (#647). It replaces /opt/hearth's config and
# the data directory: the last line of a plan.
drill() {
  local name=$1 users=$2 out=$results/$1 rev rc
  prepare "$name" || { note "$name: prepare FAILED"; return; }
  rev=$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
  s "set -e
    systemctl stop hearth
    rm -rf /var/lib/hearth /var/lib/hearth.base /opt/stress-drill
    install -d -m 0700 /opt/stress-drill
    cp /opt/hearth/hearth /opt/stress-drill/hearth" || { note "$name: drill setup FAILED"; return; }
  sp "$here/restore-drill.sh" "$here/restore_drill.py" "$here/gen-config.sh" "root@$SERVER_PUBLIC:/opt/stress-drill/" \
    || { note "$name: copying the drill FAILED"; return; }
  note "$name: restore drill with $users users"
  s "cd /opt/stress-drill && GITHUB_SHA=$rev USERS=$users bash restore-drill.sh /opt/stress-drill/hearth /opt/stress-drill/out \
    > /opt/stress-drill/drill.log 2>&1"
  rc=$?
  mkdir -p "$out/drill"
  sp -r "root@$SERVER_PUBLIC:/opt/stress-drill/out/." "root@$SERVER_PUBLIC:/opt/stress-drill/drill.log" "$out/drill/" \
    || note "$name: fetching the drill results FAILED"
  echo "$rc" > "$out/drill/exit"
  note "$name: restore drill exit $rc (0 = the restored server gives back the same data)"
}

# Turns on jemalloc's heap profiler from Hearth's next start: a profile every
# 15 minutes in /opt/hearth/out/jeprof, emptied for each plan line. The image
# must be a `--features heap-profile` build, or Hearth logs that the profiler
# is off and writes nothing.
jeprof_setup() {
  s "set -e
    rm -rf /opt/hearth/out/jeprof
    install -d -o hearth -g hearth /opt/hearth/out/jeprof
    mkdir -p /etc/systemd/system/hearth.service.d
    cat > /etc/systemd/system/hearth.service.d/jeprof.conf << 'EOF'
[Service]
Environment=_RJEM_MALLOC_CONF=prof:true,lg_prof_sample:19,prof_prefix:/opt/hearth/out/jeprof/hearth
Environment=HEARTH_HEAP_PROFILE_INTERVAL_SECS=900
EOF
    systemctl daemon-reload"
}

# Fetches the soak's heap profiles as jeprof.tar.gz.
jeprof_collect() {
  local name=$1 out=$2 n
  n=$(s "ls /opt/hearth/out/jeprof/*.heap 2> /dev/null | wc -l")
  [ "${n:-0}" -gt 0 ] || { note "$name: no heap profiles"; return; }
  s "tar -C /opt/hearth/out -czf /opt/hearth/out/jeprof-$name.tar.gz jeprof" \
    && sp "root@$SERVER_PUBLIC:/opt/hearth/out/jeprof-$name.tar.gz" "$out/jeprof.tar.gz" \
    || { note "$name: fetching the heap profiles FAILED"; return; }
  note "$name: $n heap profiles, $(du -h "$out/jeprof.tar.gz" | cut -f1)"
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
  if [ "${HEAPTRACK:-}" = 1 ]; then heaptrack_collect "$name" "$out"; fi
  if [ "${JEPROF:-}" = 1 ]; then jeprof_collect "$name" "$out"; fi
}

# The plan is read on fd 3: ssh inside the loop would read stdin and eat it.
while read -r -u 3 kind name rest; do
  case $kind in
    '' | '#'*) continue ;;
    ramp) read -r journey start step steps hold <<< "$rest"
      ramp "$name" "$journey" "$start" "$step" "$steps" "$hold" < /dev/null ;;
    soak) read -r journey rate secs minutes <<< "$rest"
      soak "$name" "$journey" "$rate" "$secs" "${minutes:-}" < /dev/null ;;
    restart) restart "$name" < /dev/null ;;
    crash) read -r journey rate secs kill_at k6env <<< "$rest"
      crash "$name" "$journey" "$rate" "$secs" "$kill_at" "${k6env:-}" < /dev/null ;;
    backup) read -r journey rate hold <<< "$rest"
      backup "$name" "$journey" "$rate" "$hold" < /dev/null ;;
    drill) read -r users <<< "$rest"
      drill "$name" "$users" < /dev/null ;;
    *) note "unknown plan line: $kind $name $rest" ;;
  esac
done 3<<< "$plan"
note "round done: $results"
