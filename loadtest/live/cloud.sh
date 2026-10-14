#!/usr/bin/env bash
# Runs the live stress test on DigitalOcean (default) or AWS EC2 (PROVIDER=aws,
# see provider-aws.sh): one Hearth server, one or more
# load generators, all throwaway. Uses the doctl (or aws CLI) you are logged in with.
#
#   cloud.sh up        create an SSH key, a firewall, the server and the generators
#   cloud.sh up-resume finish an `up` that stopped part-way
#   cloud.sh deploy    install Hearth (production mode) and k6, prepare clients
#   cloud.sh fill <from> <to>
#                      grow the store with password-less users fill<from..to>
#                      through POST /admin/users, split across the generators
#   cloud.sh import <from> <to>
#                      the same through the bulk import endpoint (slower)
#   cloud.sh ramp <name> <journey> <start> <step> <steps> [hold_s] [kill_at_s]
#                      one open-loop ramp, its rate split across the generators;
#                      kill_at_s: kill -9 Hearth that many seconds into the ramp.
#                      Waits for the end, then runs `collect`.
#   cloud.sh collect <name>
#                      wait for ramp <name> to end, fetch its results, analyse them
#                      (again after a lost session: the ramp runs on the Droplets)
#   cloud.sh restart   start Hearth again (after a crash or a kill)
#   cloud.sh verify <name>
#                      check every user acknowledged by create_user ramp <name>
#   cloud.sh add-server <size>
#                      create a second server Droplet (e.g. s-2vcpu-4gb)
#   cloud.sh move-store
#                      stop Hearth on the first server, copy its store and
#                      settings to the second server, start it there and point
#                      the generators at it
#   cloud.sh allow-ssh-here
#                      replace the firewall's SSH address with this machine's
#   cloud.sh status    show the run's resources and Hearth's state
#   cloud.sh down      delete every resource of the run, then list what is left
#
# Settings (environment):
#   STRESS_RUN       run id; default: the newest .build/run-* (or a new one for `up`)
#   DO_REGION        nyc1  (c-2 and c-4 exist in blr1 lon1 nyc1 sfo2 sgp1 tor1)
#   SERVER_SIZE      c-2   (2 dedicated vCPU, 4 GB)
#   GENERATOR_SIZE   c-4   (4 dedicated vCPU, 8 GB)
#   GENERATORS       2     (load generators; ramp rates are split evenly)
#   IMAGE            hearth-stress:local (Docker image the binary comes from)
#   LOGIN_USERS      1000  (users with a password; seeded at first start)
#   VUS              1000  (k6 VUs per generator: the most journeys in flight)
#   SETUP_GRACE      seconds between launch and the ramps' common start
#                    (default: 30, plus time to sign in the token pools)
#   K6_ENV           extra k6 settings for a ramp, e.g. "MIX=refresh:70,login:30"
#   PROFILE_AT, PROFILE_S
#                    profile Hearth for PROFILE_S seconds, PROFILE_AT seconds
#                    into a ramp (perf + offcputime; needs an unstripped binary)
#
# Security: SSH (22) is open only to this machine's public address and to
# this run's Droplets (for move-store); Hearth's port (8443) only to this
# run's Droplets. Secrets stay in .build/<run>/ (mode 0700, git-ignored) and
# on the Droplets, which `down` destroys.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
build=$here/.build
region=${DO_REGION:-nyc1}
server_size=${SERVER_SIZE:-c-2}
generator_size=${GENERATOR_SIZE:-c-4}
generators=${GENERATORS:-2}
docker_image=${IMAGE:-hearth-stress:local}
login_users=${LOGIN_USERS:-1000}
vus=${VUS:-1000}
image=ubuntu-24-04-x64
k6_version=2.0.0

log() { printf 'cloud: %s\n' "$*" >&2; }
die() {
  log "FAILED: $*"
  exit 1
}

run_dir() {
  if [ -n "${STRESS_RUN:-}" ]; then
    echo "$build/run-$STRESS_RUN"
  else
    local newest
    newest=$(ls -1d "$build"/run-* 2> /dev/null | sort | tail -n 1 || true)
    [ -n "$newest" ] || die "no run yet; start with: cloud.sh up"
    echo "$newest"
  fi
}

load_run() {
  run=$(run_dir)
  [ -f "$run/run.env" ] || die "$run/run.env is missing"
  # shellcheck disable=SC1091
  . "$run/run.env"
  # The server under test: the first one, or the second after move-store.
  if [ "${TARGET:-1}" = 2 ]; then
    SERVER_PUBLIC=$SERVER2_PUBLIC
    SERVER_PRIVATE=$SERVER2_PRIVATE
  fi
  GEN_COUNT=${GEN_COUNT:-1}
  # Empty when `up` failed before a generator started; `down` must still run.
  GEN_PUBLIC=${GEN1_PUBLIC:-}
  results=$here/results/$RUN_ID
  mkdir -p "$results"
}

# The public address of generator $1 (1-based).
gen_public() {
  local var=GEN${1}_PUBLIC
  echo "${!var}"
}

ssh_to() {
  local ip=$1
  shift
  ssh -i "$run/id_ed25519" -o UserKnownHostsFile="$run/known_hosts" \
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=30 \
    -o BatchMode=yes "root@$ip" "$@"
}

scp_to() {
  local ip=$1 dest=$2
  shift 2
  scp -q -i "$run/id_ed25519" -o UserKnownHostsFile="$run/known_hosts" \
    -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$@" "root@$ip:$dest"
}

scp_from() {
  local ip=$1 src=$2 dest=$3
  scp -q -i "$run/id_ed25519" -o UserKnownHostsFile="$run/known_hosts" \
    -o StrictHostKeyChecking=accept-new -o BatchMode=yes "root@$ip:$src" "$dest"
}

# k6 in the foreground on generator 1, with the run's environment.
# $1: extra env assignments.
k6_on_generator() {
  local envs=$1
  shift
  ssh_to "$GEN_PUBLIC" "cd /opt/stress/k6 && set -a && . /opt/stress/generator.env && set +a && \
    export SSL_CERT_FILE=/opt/stress/trust.pem $envs && ulimit -n 1048576 && /usr/local/bin/k6 $*"
}

my_public_ip() {
  local ip
  ip=$(curl -fsS https://api.ipify.org) || die "cannot learn this machine's public IP"
  [[ $ip =~ ^[0-9.]+$ ]] || die "unexpected public IP '$ip'"
  echo "$ip"
}

wait_ssh() {
  local ip=$1
  for _ in $(seq 1 60); do
    ssh_to "$ip" true 2> /dev/null && return 0
    sleep 5
  done
  ssh_to "$ip" true || die "no SSH to $ip"
}

# Creates one Droplet and prints "ID PUBLIC PRIVATE" once it is active.
# Polls instead of `doctl --wait`, which hung for 10 minutes on a flaky
# connection after the Droplet was long active; every call has a timeout.
create_droplet() {
  local name=$1 size=$2 id line status public private
  id=$(timeout 120 doctl compute droplet create "$name" --region "$region" --size "$size" \
    --image "$image" --ssh-keys "$KEY_ID" --tag-names "$TAG" --format ID --no-header) \
    || die "creating $name failed; check: doctl compute droplet list --tag-name $TAG"
  for _ in $(seq 1 60); do
    line=$(timeout 60 doctl compute droplet get "$id" --format Status,PublicIPv4,PrivateIPv4 --no-header || true)
    read -r status public private <<< "$line"
    if [ "$status" = active ] && [ -n "$private" ]; then
      echo "$id $public $private"
      return 0
    fi
    sleep 5
  done
  die "$name ($id) did not become active"
}

cmd_up() {
  command -v doctl > /dev/null || die "doctl is not installed"
  local id
  id=$(date -u +%Y%m%d-%H%M%S)
  run=$build/run-$id
  umask 077
  mkdir -p "$run"
  TAG=hearth-stress-$id
  local my_ip
  my_ip=$(my_public_ip)

  log "run $id: SSH key"
  ssh-keygen -q -t ed25519 -N '' -C "$TAG" -f "$run/id_ed25519"
  # Each resource id goes into run.env as soon as it exists, so `down`
  # can clean up after a failure part-way through.
  printf 'RUN_ID=%s\nTAG=%s\n' "$id" "$TAG" > "$run/run.env"
  doctl compute tag create "$TAG" > /dev/null
  KEY_ID=$(doctl compute ssh-key import "$TAG" --public-key-file "$run/id_ed25519.pub" \
    --format ID --no-header)
  echo "KEY_ID=$KEY_ID" >> "$run/run.env"

  log "run $id: firewall (SSH from $my_ip and this run's Droplets; 8443 from this run's Droplets)"
  local fw_id
  fw_id=$(doctl compute firewall create --name "$TAG" --tag-names "$TAG" \
    --inbound-rules "protocol:tcp,ports:22,address:$my_ip/32 protocol:tcp,ports:22,tag:$TAG protocol:tcp,ports:8443,tag:$TAG" \
    --outbound-rules "protocol:tcp,ports:all,address:0.0.0.0/0,address:::/0 protocol:udp,ports:all,address:0.0.0.0/0,address:::/0 protocol:icmp,address:0.0.0.0/0,address:::/0" \
    --format ID --no-header)
  printf 'FW_ID=%s\nSSH_FROM=%s\n' "$fw_id" "$my_ip" >> "$run/run.env"

  log "run $id: server $server_size and $generators x $generator_size generator in $region"
  local line
  line=$(create_droplet "$TAG-server" "$server_size")
  read -r server_id server_public server_private <<< "$line"
  printf 'SERVER_ID=%s\nSERVER_PUBLIC=%s\nSERVER_PRIVATE=%s\nSERVER_SIZE_SLUG=%s\n' \
    "$server_id" "$server_public" "$server_private" "$server_size" >> "$run/run.env"
  local i
  for i in $(seq 1 "$generators"); do
    line=$(create_droplet "$TAG-gen$i" "$generator_size")
    read -r gen_id gen_public gen_private <<< "$line"
    printf 'GEN%s_ID=%s\nGEN%s_PUBLIC=%s\nGEN%s_PRIVATE=%s\n' \
      "$i" "$gen_id" "$i" "$gen_public" "$i" "$gen_private" >> "$run/run.env"
  done
  echo "GEN_COUNT=$generators" >> "$run/run.env"
  load_run
  log "waiting for SSH"
  wait_ssh "$SERVER_PUBLIC"
  for i in $(seq 1 "$GEN_COUNT"); do wait_ssh "$(gen_public "$i")"; done
  log "up: server $SERVER_PUBLIC (private $SERVER_PRIVATE), $GEN_COUNT generators. Next: cloud.sh deploy"
}

# Finishes an `up` that stopped part-way: records the run's Droplets that
# run.env does not list yet, creates the generators still missing, and waits
# for SSH on all of them.
cmd_up_resume() {
  run=$(run_dir)
  # shellcheck disable=SC1091
  . "$run/run.env"
  local i var name line id public private status
  for i in $(seq 1 "$generators"); do
    var=GEN${i}_ID
    [ -z "${!var:-}" ] || continue
    name=$TAG-gen$i
    line=$(timeout 60 doctl compute droplet list --tag-name "$TAG" \
      --format Name,ID,Status,PublicIPv4,PrivateIPv4 --no-header | awk -v n="$name" '$1 == n')
    if [ -n "$line" ]; then
      read -r _ id status public private <<< "$line"
      [ "$status" = active ] || die "$name exists but is $status"
      log "recording $name ($id)"
    else
      log "creating $name"
      read -r id public private <<< "$(create_droplet "$name" "$generator_size")"
    fi
    printf 'GEN%s_ID=%s\nGEN%s_PUBLIC=%s\nGEN%s_PRIVATE=%s\n' \
      "$i" "$id" "$i" "$public" "$i" "$private" >> "$run/run.env"
  done
  grep -q '^GEN_COUNT=' "$run/run.env" || echo "GEN_COUNT=$generators" >> "$run/run.env"
  load_run
  wait_ssh "$SERVER_PUBLIC"
  for i in $(seq 1 "$GEN_COUNT"); do wait_ssh "$(gen_public "$i")"; done
  log "up: server $SERVER_PUBLIC (private $SERVER_PRIVATE), $GEN_COUNT generators. Next: cloud.sh deploy"
}

# Installs the packages the server-side observation and profiling need.
install_server_tools() {
  ssh_to "$1" "export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update > /dev/null
    apt-get -qq install -y sysstat gdb linux-tools-common linux-tools-\$(uname -r) bpfcc-tools > /dev/null
    sysctl -q -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535 kernel.perf_event_paranoid=-1"
}

# Copies the server scripts to $1.
copy_server_scripts() {
  scp_to "$1" /opt/hearth/ "$here/sampler.sh" "$here/metrics-scrape.sh" \
    "$here/remote/observe.sh" "$here/remote/kill.sh" "$here/remote/profile.sh" \
    "$here/remote/malloc-info.sh"
  ssh_to "$1" "chmod 0755 /opt/hearth/*.sh"
}

install_generator() {
  local ip=$1 bundle=$2
  scp_to "$ip" /tmp/ "$bundle/ca.crt" "$bundle/generator.env"
  ssh_to "$ip" "set -e
    mkdir -p /opt/stress/k6 /opt/stress/out
    cd /tmp
    base=https://github.com/grafana/k6/releases/download/v$k6_version
    curl -fsSLO \$base/k6-v$k6_version-linux-amd64.tar.gz
    curl -fsSLO \$base/k6-v$k6_version-checksums.txt
    grep ' k6-v$k6_version-linux-amd64.tar.gz\$' k6-v$k6_version-checksums.txt | sha256sum -c - > /dev/null
    tar -xzf k6-v$k6_version-linux-amd64.tar.gz
    install -m 0755 k6-v$k6_version-linux-amd64/k6 /usr/local/bin/k6
    cat /tmp/ca.crt /etc/ssl/certs/ca-certificates.crt > /opt/stress/trust.pem
    install -m 0600 /tmp/generator.env /opt/stress/generator.env
    rm -f /tmp/ca.crt /tmp/generator.env
    sysctl -q -w net.ipv4.ip_local_port_range='10240 65535' net.ipv4.tcp_tw_reuse=1"
  scp_to "$ip" /opt/stress/ "$here/sampler.sh" "$here/remote/launch.sh"
  ssh_to "$ip" "chmod 0755 /opt/stress/launch.sh"
  scp_to "$ip" /opt/stress/k6/ "$here/k6/lib.js" "$here/k6/stress.js" \
    "$here/k6/prepare.js" "$here/k6/verify.js" "$here/k6/fill.js"
}

hearth_ready() {
  ssh_to "$GEN_PUBLIC" "curl -fsS -o /dev/null --cacert /opt/stress/trust.pem \
    --resolve hearth.stress.test:8443:$SERVER_PRIVATE https://hearth.stress.test:8443/readyz" 2> /dev/null
}

cmd_deploy() {
  load_run
  local bundle=$run/bundle
  if [ ! -d "$bundle" ]; then
    "$here/gen-config.sh" "$bundle" "$SERVER_PRIVATE" "$login_users"
  fi

  local rev
  rev=$(image_commit)
  echo "$rev" > "$run/revision"
  log "extracting the production binary from $docker_image ($rev)"
  local cid
  cid=$(docker create "$docker_image")
  docker cp "$cid:/usr/local/bin/hearth" "$run/hearth" > /dev/null
  docker rm "$cid" > /dev/null

  log "server: install Hearth and the observation tools"
  ssh_to "$SERVER_PUBLIC" "set -e
    id hearth > /dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hearth
    mkdir -p /opt/hearth/tls /opt/hearth/out /var/lib/hearth
    chown hearth:hearth /var/lib/hearth"
  install_server_tools "$SERVER_PUBLIC"
  scp_to "$SERVER_PUBLIC" /opt/hearth/ "$run/hearth" "$bundle/ca.crt" \
    "$bundle/server/hearth.yaml" "$bundle/server/hearth.env"
  copy_server_scripts "$SERVER_PUBLIC"
  scp_to "$SERVER_PUBLIC" /opt/hearth/tls/ "$bundle/server/tls/https.crt" "$bundle/server/tls/https.key"
  ssh_to "$SERVER_PUBLIC" "set -e
    chmod 0755 /opt/hearth/hearth
    chown -R root:hearth /opt/hearth/tls /opt/hearth/hearth.yaml /opt/hearth/hearth.env
    chmod 0750 /opt/hearth/tls
    chmod 0644 /opt/hearth/tls/https.crt /opt/hearth/ca.crt
    chmod 0640 /opt/hearth/tls/https.key /opt/hearth/hearth.env /opt/hearth/hearth.yaml
    cat > /etc/systemd/system/hearth.service << 'EOF'
[Unit]
Description=Hearth (live stress run)
After=network-online.target
[Service]
User=hearth
Group=hearth
EnvironmentFile=/opt/hearth/hearth.env
ExecStart=/opt/hearth/hearth serve -c /opt/hearth/hearth.yaml
WorkingDirectory=/var/lib/hearth
LimitNOFILE=1048576
# A crash or an out-of-memory kill is a result: do not hide it by restarting.
Restart=no
StandardOutput=append:/opt/hearth/out/hearth.log
StandardError=append:/opt/hearth/out/hearth.log
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl start hearth"

  local i
  for i in $(seq 1 "$GEN_COUNT"); do
    log "generator $i: install k6 $k6_version"
    install_generator "$(gen_public "$i")" "$bundle"
  done

  log "waiting for Hearth (first start seeds $login_users password users)"
  local ready=0
  for _ in $(seq 1 360); do
    if hearth_ready; then
      ready=1
      break
    fi
    # Restart=no: a failed start will not come back by waiting.
    if ! ssh_to "$SERVER_PUBLIC" "systemctl is-active --quiet hearth" 2> /dev/null; then
      ssh_to "$SERVER_PUBLIC" "tail -n 5 /opt/hearth/out/hearth.log" >&2 || true
      die "Hearth stopped during start-up"
    fi
    sleep 5
  done
  [ "$ready" = 1 ] || die "Hearth did not become ready; see: cloud.sh status"
  wait_seeded

  log "checking the binary is a production build (POST /admin/bootstrap must be 404)"
  local code
  code=$(ssh_to "$GEN_PUBLIC" "curl -s -o /dev/null -w '%{http_code}' -X POST --cacert /opt/stress/trust.pem \
    --resolve hearth.stress.test:8443:$SERVER_PRIVATE https://hearth.stress.test:8443/admin/bootstrap")
  [ "$code" = 404 ] || die "POST /admin/bootstrap answered $code: not a production build"

  log "preparing the api client (regenerated secret)"
  k6_on_generator "PREPARE_CLIENTS=1 PREPARE_OUT=/opt/stress/prepare.json" run -q prepare.js > /dev/null
  local secret
  secret=$(ssh_to "$GEN_PUBLIC" "python3 -c 'import json; print(json.load(open(\"/opt/stress/prepare.json\"))[\"api_secret\"])'")
  for i in $(seq 1 "$GEN_COUNT"); do
    ssh_to "$(gen_public "$i")" "sed -i '/^STRESS_API_SECRET=/d' /opt/stress/generator.env && \
      cat >> /opt/stress/generator.env" <<< "STRESS_API_SECRET=$secret"
  done
  record_inventory
  log "deployed. Next: cloud.sh fill <from> <to>, or cloud.sh ramp <name> <journey> <start> <step> <steps>"
}

# Waits until the declared seed users exist: the first start creates them one
# by one after the listener is up.
wait_seeded() {
  for _ in $(seq 1 720); do
    if ssh_to "$SERVER_PUBLIC" "grep -c 'created seed user' /opt/hearth/out/hearth.log" 2> /dev/null \
      | awk -v n="$login_users" '{exit !($1 >= n + 1)}'; then
      return 0
    fi
    sleep 5
  done
  die "seeding $login_users users did not finish"
}

# The commit the image was built from: its OCI revision label, else IMAGE_COMMIT.
image_commit() {
  docker image inspect "$docker_image" > /dev/null 2>&1 \
    || die "image $docker_image is missing; see loadtest/live/README.md"
  local rev
  rev=$(docker image inspect "$docker_image" \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')
  if [ -z "$rev" ] || [ "$rev" = unknown ]; then
    rev=${IMAGE_COMMIT:?the image has no revision label; set IMAGE_COMMIT to the commit it was built from}
  fi
  [[ $rev =~ ^[0-9a-f]{40}$ ]] || die "image revision '$rev' is not a full commit id"
  echo "$rev"
}

record_inventory() {
  local i
  {
    echo "run: $RUN_ID"
    echo "region: $region"
    echo "target server: ${TARGET:-1}"
    echo "server: $(ssh_to "$SERVER_PUBLIC" "nproc; free -m | awk '/^Mem:/ {print \$2\" MB\"}'; lsblk -dno NAME,SIZE,ROTA | head -n 3; grep -m1 'model name' /proc/cpuinfo" | tr '\n' ' ')"
    for i in $(seq 1 "$GEN_COUNT"); do
      echo "generator $i: $generator_size $(ssh_to "$(gen_public "$i")" "nproc; free -m | awk '/^Mem:/ {print \$2\" MB\"}'; grep -m1 'model name' /proc/cpuinfo" | tr '\n' ' ')"
    done
    echo "hearth: $(ssh_to "$SERVER_PUBLIC" '/opt/hearth/hearth --version')"
    echo "hearth revision (image label): $(cat "$run/revision")"
    echo "binary: $(ssh_to "$SERVER_PUBLIC" 'file -b /opt/hearth/hearth | cut -d, -f1-2,8-')"
    echo "tooling revision: $(git -C "$repo" rev-parse HEAD)"
    echo "k6: $k6_version"
    echo "login_users: $login_users"
    echo "vus per generator: $vus"
  } >> "$results/inventory.txt"
  log "inventory: $results/inventory.txt"
}

cmd_import() {
  load_run
  local from=${1:?usage: cloud.sh import <from> <to>} to=${2:?usage: cloud.sh import <from> <to>}
  run_split_job "import-$from-$to" "$from" "$to" prepare.js IMPORT 14400
}

# Runs <script> over the user range [from, to), split evenly across the
# generators as detached jobs, waits, and adds up the result JSONs.
# $5: the script's range variable prefix (FILL or IMPORT).
run_split_job() {
  local name=$1 from=$2 to=$3 script=$4 prefix=$5 limit=$6 i lo hi
  local per=$((((to - from) + GEN_COUNT - 1) / GEN_COUNT))
  log "$name: users $from..$to through $script on $GEN_COUNT generators"
  # A job re-run under the same name must not find the last run's files:
  # wait_job ends as soon as k6.exit exists, and then result.json is fetched.
  for i in $(seq 1 "$GEN_COUNT"); do
    ssh_to "$(gen_public "$i")" "rm -f /opt/stress/out/$name/k6.exit /opt/stress/out/$name/result.json"
  done
  rm -f "$results/$name"/result-g*.json
  for i in $(seq 1 "$GEN_COUNT"); do
    lo=$((from + (i - 1) * per))
    hi=$((lo + per < to ? lo + per : to))
    [ "$lo" -lt "$hi" ] || continue
    launch_on_generator "$i" "$name" << EOF
K6_SCRIPT=$script
K6_NO_CSV=1
${prefix}_FROM=$lo
${prefix}_TO=$hi
FILL_VUS=${FILL_VUS:-64}
IMPORT_BATCH=${IMPORT_BATCH:-2000}
IMPORT_VUS=${IMPORT_VUS:-8}
FILL_OUT=/opt/stress/out/$name/result.json
PREPARE_OUT=/opt/stress/out/$name/result.json
EOF
  done
  wait_job "$name" "$limit"
  mkdir -p "$results/$name"
  for i in $(seq 1 "$GEN_COUNT"); do
    scp_from "$(gen_public "$i")" "/opt/stress/out/$name/result.json" "$results/$name/result-g$i.json" 2> /dev/null || true
  done
  python3 - "$results/$name" << 'PY'
import glob, json, sys
rows = [json.load(open(p)) for p in sorted(glob.glob(f"{sys.argv[1]}/result-g*.json"))]
ok = sum(r.get("created", r.get("users_imported", 0)) for r in rows)
bad = sum(r.get("failed", r.get("users_import_failed", 0)) for r in rows)
secs = max(r["duration_s"] for r in rows)
print(json.dumps({"generators": len(rows), "users": ok, "failed": bad,
                  "duration_s": round(secs, 1), "users_per_s": round(ok / secs, 1)}, indent=2))
PY
}

# Starts a k6 job on generator $1 under systemd: writes its params.env, then
# runs launch.sh. $2: job name; stdin: the params.env content.
launch_on_generator() {
  local i=$1 name=$2 ip
  ip=$(gen_public "$i")
  ssh_to "$ip" "mkdir -p /opt/stress/out/$name && cat > /opt/stress/out/$name/params.env"
  ssh_to "$ip" "systemctl reset-failed stress-$name 2> /dev/null || true
    systemd-run --unit=stress-$name --collect --quiet /opt/stress/launch.sh $name"
}

# Waits until job $1 has ended on every generator; $2: most seconds to wait.
wait_job() {
  local name=$1 limit=$2 waited=0 i finished
  while [ "$waited" -lt "$limit" ]; do
    finished=0
    for i in $(seq 1 "$GEN_COUNT"); do
      if ssh_to "$(gen_public "$i")" "test -f /opt/stress/out/$name/k6.exit" 2> /dev/null; then
        finished=$((finished + 1))
      fi
    done
    [ "$finished" -lt "$GEN_COUNT" ] || return 0
    sleep 15
    waited=$((waited + 15))
  done
  die "job $name did not end within ${limit}s; resume with: cloud.sh collect $name"
}

cmd_fill() {
  load_run
  local from=${1:?usage: cloud.sh fill <from> <to>} to=${2:?usage: cloud.sh fill <from> <to>}
  run_split_job "fill-$from-$to" "$from" "$to" fill.js FILL 14400
}

cmd_ramp() {
  load_run
  local name=${1:?usage: cloud.sh ramp <name> <journey> <start> <step> <steps> [hold_s] [kill_at_s]}
  local journey=${2:?} start=${3:?} step=${4:?} steps=${5:?} hold=${6:-60} kill_at=${7:-}
  local out=$results/$name
  [ ! -e "$out" ] || die "$out exists; pick another name"
  [ $((start % GEN_COUNT)) = 0 ] && [ $((step % GEN_COUNT)) = 0 ] \
    || die "start ($start) and step ($step) must divide evenly across $GEN_COUNT generators"
  ssh_to "$SERVER_PUBLIC" "systemctl is-active --quiet hearth" || die "Hearth is not running; cloud.sh restart"
  mkdir -p "$out"

  local grace=${SETUP_GRACE:-}
  if [ -z "$grace" ]; then
    case $journey in
      # Each generator signs in a token pool (about VUS sessions) first.
      refresh | mix | introspect | userinfo) grace=$((30 + vus * GEN_COUNT / 25)) ;;
      *) grace=30 ;;
    esac
  fi
  local now start_at run_s
  now=$(ssh_to "$GEN_PUBLIC" 'date +%s')
  start_at=$((now + grace))
  run_s=$((steps * (hold + 5)))
  cat > "$out/params.env" << EOF
JOURNEY=$journey
START_RATE=$start
STEP_RATE=$step
STEPS=$steps
HOLD_S=$hold
KILL_AT=$kill_at
START_AT=$start_at
RUN_S=$run_s
GENERATORS=$GEN_COUNT
K6_ENV=${K6_ENV:-}
EOF

  log "ramp $name: $journey from $start/s by $step/s, $steps steps of ${hold}s, on $GEN_COUNT generators; starts in ${grace}s"
  ssh_to "$SERVER_PUBLIC" "systemctl reset-failed observe-$name 2> /dev/null || true
    systemd-run --unit=observe-$name --collect --quiet /opt/hearth/observe.sh $name $((grace + run_s + 300))"
  if [ -n "$kill_at" ]; then
    ssh_to "$SERVER_PUBLIC" "systemd-run --unit=kill-$name --collect --quiet \
      --on-active=\$(( $start_at + $kill_at - \$(date +%s) ))s /opt/hearth/kill.sh $name"
    log "kill -9 scheduled ${kill_at}s into the ramp"
  fi
  if [ -n "${PROFILE_AT:-}" ]; then
    ssh_to "$SERVER_PUBLIC" "systemd-run --unit=profile-$name --collect --quiet \
      --on-active=\$(( $start_at + $PROFILE_AT - \$(date +%s) ))s /opt/hearth/profile.sh $name ${PROFILE_S:-30}"
    log "profile scheduled ${PROFILE_AT}s into the ramp, for ${PROFILE_S:-30}s"
  fi
  local i extra=""
  [ -z "${K6_ENV:-}" ] || extra=$(tr ' ' '\n' <<< "$K6_ENV")
  for i in $(seq 1 "$GEN_COUNT"); do
    launch_on_generator "$i" "$name" << EOF
JOURNEY=$journey
START_RATE=$((start / GEN_COUNT))
STEP_RATE=$((step / GEN_COUNT))
STEPS=$steps
HOLD_S=$hold
VUS=$vus
RUN_ID=$name-g$i
START_AT=$start_at
SUMMARY_OUT=/opt/stress/out/$name/summary.json
$extra
EOF
  done
  cmd_collect "$name"
}

cmd_collect() {
  load_run
  local name=${1:?usage: cloud.sh collect <name>}
  local out=$results/$name
  [ -f "$out/params.env" ] || die "$out/params.env is missing: no ramp $name"
  local JOURNEY START_RATE STEP_RATE STEPS HOLD_S RUN_S START_AT
  # shellcheck disable=SC1091
  . "$out/params.env"
  local now limit
  now=$(date +%s)
  limit=$((START_AT + RUN_S + 900 - now))
  [ "$limit" -gt 60 ] || limit=60
  wait_job "$name" "$limit"
  ssh_to "$SERVER_PUBLIC" "systemctl stop observe-$name 2> /dev/null || true"

  local i ip remote=/opt/stress/out/$name status
  local raws=() summaries=() gsamplers=()
  for i in $(seq 1 "$GEN_COUNT"); do
    ip=$(gen_public "$i")
    status=$(ssh_to "$ip" "cat $remote/k6.exit" 2> /dev/null || echo '?')
    log "generator $i: k6 exited $status (99: thresholds; 108: aborted by the failure-ratio guard)"
    echo "$status" > "$out/k6-g$i.exit"
    scp_from "$ip" "$remote/k6.txt" "$out/k6-g$i.txt" 2> /dev/null || true
    scp_from "$ip" "$remote/console.log" "$out/console-g$i.log" 2> /dev/null || true
    scp_from "$ip" "$remote/gen-sampler.csv" "$out/gen-sampler-g$i.csv" 2> /dev/null \
      && gsamplers+=("$out/gen-sampler-g$i.csv")
    if scp_from "$ip" "$remote/summary.json" "$out/summary-g$i.json" 2> /dev/null \
      && scp_from "$ip" "$remote/raw.csv.gz" "$out/raw-g$i.csv.gz"; then
      raws+=("$out/raw-g$i.csv.gz")
      summaries+=("$out/summary-g$i.json")
    else
      log "generator $i: no summary or raw data"
    fi
  done
  local f
  for f in sampler.csv metrics.txt iostat.txt killed_at perf.txt offcpu.folded perf.err offcpu.err; do
    scp_from "$SERVER_PUBLIC" "/opt/hearth/out/$name.$f" "$out/$f" 2> /dev/null || true
  done
  ssh_to "$SERVER_PUBLIC" "systemctl is-active hearth; journalctl -u hearth -n 5 --no-pager; \
    dmesg 2> /dev/null | grep -i -E 'out of memory|killed process' | tail -n 3" > "$out/server-state.txt" 2>&1 || true
  ssh_to "$SERVER_PUBLIC" "tail -n 200 /opt/hearth/out/hearth.log" > "$out/hearth-tail.log" 2>&1 || true

  local budget
  case $JOURNEY in
    introspect | userinfo | admin_lookup) budget=50 ;;
    refresh | create_user) budget=100 ;;
    login | mix) budget=1000 ;;
  esac
  if [ "${#raws[@]}" -gt 0 ]; then
    python3 "$here/analyze.py" --raw "${raws[@]}" --summary "${summaries[@]}" \
      --sampler "$out/sampler.csv" --gen-sampler "${gsamplers[@]}" --journey "$JOURNEY" \
      --start-rate "$START_RATE" --step-rate "$STEP_RATE" --steps "$STEPS" --hold-s "$HOLD_S" \
      --budget-ms "$budget" --out "$out/report.json" | tee "$out/report.md"
  fi
  log "ramp $name collected: $out"
}

cmd_restart() {
  load_run
  ssh_to "$SERVER_PUBLIC" "systemctl reset-failed hearth 2> /dev/null || true; systemctl start hearth"
  for _ in $(seq 1 300); do
    if hearth_ready; then
      log "Hearth is ready again"
      return 0
    fi
    sleep 2
  done
  die "Hearth did not become ready"
}

cmd_verify() {
  load_run
  local name=${1:?usage: cloud.sh verify <name>} i ip
  for i in $(seq 1 "$GEN_COUNT"); do
    ip=$(gen_public "$i")
    ssh_to "$ip" "cd /opt/stress/k6 && set -a && . /opt/stress/generator.env && set +a && \
      SSL_CERT_FILE=/opt/stress/trust.pem ACK_FILE=/opt/stress/out/$name/console.log \
      VERIFY_OUT=/opt/stress/out/$name/verify.json /usr/local/bin/k6 run -q verify.js" > /dev/null 2>&1 || true
    scp_from "$ip" "/opt/stress/out/$name/verify.json" "$results/$name/verify-g$i.json"
  done
  python3 - "$results/$name" << 'PY'
import glob, json, sys
rows = [json.load(open(p)) for p in sorted(glob.glob(f"{sys.argv[1]}/verify-g*.json"))]
total = {k: sum(r[k] for r in rows) for k in ("acknowledged", "found", "missing", "errors")}
print(json.dumps(total, indent=2))
PY
}

cmd_add_server() {
  load_run
  local size=${1:?usage: cloud.sh add-server <size>}
  [ -z "${SERVER2_ID:-}" ] || die "a second server exists already ($SERVER2_ID)"
  log "creating a second server: $size"
  local line
  line=$(create_droplet "$TAG-server2" "$size")
  read -r id public private <<< "$line"
  printf 'SERVER2_ID=%s\nSERVER2_PUBLIC=%s\nSERVER2_PRIVATE=%s\nSERVER2_SIZE_SLUG=%s\n' \
    "$id" "$public" "$private" "$size" >> "$run/run.env"
  wait_ssh "$public"
  install_server_tools "$public"
  log "second server $public (private $private). Next: cloud.sh move-store"
}

cmd_move_store() {
  load_run
  [ -n "${SERVER2_ID:-}" ] || die "no second server; cloud.sh add-server <size>"
  [ "${TARGET:-1}" = 1 ] || die "the store has moved already"
  local from=$SERVER_PUBLIC to_public=$SERVER2_PUBLIC to_private=$SERVER2_PRIVATE

  log "stopping Hearth on the first server"
  ssh_to "$from" "systemctl stop hearth"
  # A key made on the first server for this copy only: the run's own key
  # never leaves this machine.
  local pub
  pub=$(ssh_to "$from" "test -f /root/.ssh/move_ed25519 || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/move_ed25519
    cat /root/.ssh/move_ed25519.pub")
  ssh_to "$to_public" "cat >> /root/.ssh/authorized_keys" <<< "$pub"
  ssh_to "$to_public" "id hearth > /dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hearth"
  log "copying the store and settings over the private network"
  ssh_to "$from" "tar -C / -cf - opt/hearth var/lib/hearth etc/systemd/system/hearth.service \
    | ssh -i /root/.ssh/move_ed25519 -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
      root@$to_private 'tar -C / -xpf -'"
  ssh_to "$to_public" "set -e
    chown -R hearth:hearth /var/lib/hearth
    chown -R root:hearth /opt/hearth/tls /opt/hearth/hearth.yaml /opt/hearth/hearth.env
    : > /opt/hearth/out/hearth.log
    sed -i '/move_ed25519/d' /root/.ssh/authorized_keys
    systemctl daemon-reload
    systemctl start hearth"
  ssh_to "$from" "rm -f /root/.ssh/move_ed25519 /root/.ssh/move_ed25519.pub"
  echo "TARGET=2" >> "$run/run.env"
  load_run
  local i
  for i in $(seq 1 "$GEN_COUNT"); do
    ssh_to "$(gen_public "$i")" "sed -i 's/^STRESS_SERVER_IP=.*/STRESS_SERVER_IP=$SERVER_PRIVATE/' /opt/stress/generator.env"
  done
  for _ in $(seq 1 300); do
    if hearth_ready; then
      server_size=$SERVER2_SIZE_SLUG
      record_inventory
      log "Hearth runs on the second server ($SERVER2_SIZE_SLUG); ramps now target it"
      return 0
    fi
    sleep 2
  done
  die "Hearth did not become ready on the second server"
}

cmd_allow_ssh_here() {
  load_run
  local ip
  ip=$(my_public_ip)
  [ "$ip" != "${SSH_FROM:-}" ] || { log "SSH already allowed from $ip"; return 0; }
  doctl compute firewall add-rules "$FW_ID" --inbound-rules "protocol:tcp,ports:22,address:$ip/32"
  [ -z "${SSH_FROM:-}" ] \
    || doctl compute firewall remove-rules "$FW_ID" --inbound-rules "protocol:tcp,ports:22,address:$SSH_FROM/32"
  echo "SSH_FROM=$ip" >> "$run/run.env"
  log "SSH now allowed from $ip only"
}

cmd_status() {
  load_run
  doctl compute droplet list --tag-name "$TAG" --format Name,Status,PublicIPv4,PrivateIPv4,SizeSlug
  ssh_to "$SERVER_PUBLIC" "systemctl is-active hearth; systemctl list-units --no-legend 'observe-*' 'kill-*' 'profile-*'; tail -n 5 /opt/hearth/out/hearth.log" || true
}

cmd_down() {
  load_run
  log "deleting Droplets tagged $TAG"
  doctl compute droplet delete --tag-name "$TAG" --force || true
  [ -z "${FW_ID:-}" ] || doctl compute firewall delete "$FW_ID" --force || true
  [ -z "${KEY_ID:-}" ] || doctl compute ssh-key delete "$KEY_ID" --force || true
  sleep 5
  doctl compute tag delete "$TAG" --force || true
  log "left over (must be empty):"
  doctl compute droplet list --tag-name "$TAG" --format ID,Name --no-header
  doctl compute firewall list --format ID,Name --no-header | grep "$TAG" || true
  doctl compute ssh-key list --format ID,Name --no-header | grep "$TAG" || true
}

# PROVIDER=aws swaps in the EC2 versions of the provider commands. A run
# records its provider in run.env, so later commands need no setting.
provider=${PROVIDER:-}
if [ -z "$provider" ] && [ "${1:-}" != up ] && [ -n "${1:-}" ]; then
  provider_run=$( (run_dir) 2> /dev/null || true)
  if [ -n "$provider_run" ] && [ -f "$provider_run/run.env" ]; then
    provider=$(sed -n 's/^PROVIDER=//p' "$provider_run/run.env" | tail -n 1)
  fi
fi
# shellcheck source=provider-aws.sh
case ${provider:-do} in
  do) ;;
  aws) . "$here/provider-aws.sh" ;;
  *) die "unknown PROVIDER '$provider' (do or aws)" ;;
esac

case ${1:-} in
  up) shift; cmd_up "$@" ;;
  up-resume) shift; cmd_up_resume "$@" ;;
  deploy) shift; cmd_deploy "$@" ;;
  fill) shift; cmd_fill "$@" ;;
  import) shift; cmd_import "$@" ;;
  ramp) shift; cmd_ramp "$@" ;;
  collect) shift; cmd_collect "$@" ;;
  restart) shift; cmd_restart "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  add-server) shift; cmd_add_server "$@" ;;
  move-store) shift; cmd_move_store "$@" ;;
  allow-ssh-here) shift; cmd_allow_ssh_here "$@" ;;
  status) shift; cmd_status "$@" ;;
  down)
    shift
    # A later driver owns the teardown while this file exists.
    if [ -e "$here/.build/HOLD-DOWN" ]; then
      echo "down: held by $here/.build/HOLD-DOWN; resources left up"
      exit 0
    fi
    cmd_down "$@"
    ;;
  *)
    sed -n '2,52p' "$0"
    exit 2
    ;;
esac
