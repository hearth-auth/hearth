#!/usr/bin/env bash
# The dry run of compare.sh (DRY_RUN=1, #913): stands in for aws, ssh, scp,
# docker, curl, ssh-keygen and sleep (dryrun/bin/<name> links here). Each call
# is printed ("DRY <tool> ...") to stderr and appended to $DRY_STATE/calls.log,
# and gets a canned answer; nothing leaves this machine.
#
# A ramp's k6 output is made up when cloud.sh collect fetches it: every
# journey takes 5 ms, except at an offered rate of DRY_FAIL_RATE (/s, default
# 400) or more, where it takes 5 s, so the ladder fails there.
#
# DRY_STS_FAIL=1 makes `aws sts get-caller-identity` fail, as after the login
# has expired.
#
# DRY_FAIL=<text> makes an ssh or scp call whose command line contains <text>
# fail (exit 1), as a remote step that breaks.
#
# DRY_SSH_GONE_AFTER=<text>: the host of the ssh call whose command line
# contains <text> stops answering after that call, as a server that reached
# its lifetime: every later ssh call to it fails as ssh does (exit 255,
# "Connection timed out").
#
# The addresses handed out are documentation ranges, built at run time.
set -uo pipefail

tool=$(basename "$0")
state=${DRY_STATE:?DRY_STATE is not set}
mkdir -p "$state"
log() {
  printf 'DRY %s\n' "$*" >> "$state/calls.log"
  printf 'DRY %s\n' "$*" >&2
}
# A number unique to this call: the parts of a session call the shims at once.
counter() {
  (
    flock 9
    local n
    n=$(($(cat "$state/n" 2> /dev/null || echo 0) + 1))
    echo "$n" > "$state/n"
    echo "$n"
  ) 9> "$state/n.lock"
}
fails() { [ -n "${DRY_FAIL:-}" ] && [[ $1 == *"$DRY_FAIL"* ]]; }
public_ip() { printf '%d.%d.%d.%d' 198 51 100 "$1"; }
private_ip() { printf '%d.%d.%d.%d' 10 0 0 "$1"; }

# The made-up raw.csv.gz of a ramp: $1 the local file, from its run's
# params.env (next to it) and the generator number in its name.
fake_raw() {
  local dest=$1 dir
  dir=$(dirname "$dest")
  python3 -I - "$dir/params.env" "$dest" "${DRY_FAIL_RATE:-400}" << 'PY'
import gzip, sys
p = dict(l.rstrip("\n").split("=", 1) for l in open(sys.argv[1]) if "=" in l)
gens = int(p["GENERATORS"])
start, hold, fail = int(p["START_AT"]), int(p["HOLD_S"]), float(sys.argv[3])
rates = [int(r) / 60 for r in p["RATES_PM"].split(",")] if p.get("RATES_PM") else \
    [int(p["START_RATE"]) + i * int(p["STEP_RATE"]) for i in range(int(p["STEPS"]))]
with gzip.open(sys.argv[2], "wt") as f:
    f.write("metric_name,timestamp,metric_value,extra_tags\n")
    for step, rate in enumerate(rates):
        t0 = start + step * (hold + 5) + 5
        n = max(1, round(rate * hold / gens))
        ms = 5000 if rate >= fail else 5
        for i in range(min(n, 400)):
            ts = t0 + (i * hold) // max(1, min(n, 400))
            tags = f"step={step}&phase=hold"
            f.write(f"journey_ms,{ts},{ms},{tags}\njourney_ok,{ts},1,{tags}\n")
PY
}

fake_sampler() {
  local dest=$1 dir start
  dir=$(dirname "$dest")
  start=$(sed -n 's/^START_AT=//p' "$dir/params.env")
  {
    echo "ts,alive,pid,cpu_ticks,clk_tck,rss_kb,threads,fds,mem_available_kb,disk_writes,disk_write_sectors,load1,rss_anon_kb,rss_file_kb"
    for i in $(seq 0 5 3000); do
      echo "$((start + i)),1,1,$((i * 100)),100,204800,40,100,3000000,$((i * 50)),$((i * 4000)),1.0,200000,4800"
    done
  } > "$dest"
}

case $tool in
  aws)
    log "aws $*"
    n=$(counter)
    case " $* " in
      *" sts get-caller-identity "*)
        # DRY_STS_FAIL=1: the login has expired.
        [ "${DRY_STS_FAIL:-}" != 1 ] || exit 255
        echo "arn:aws:iam::ACCOUNT:user/hearth-stress-runner"
        ;;
      *" ssm get-parameter "*) echo ami-dry ;;
      *" describe-vpcs "*) echo vpc-dry ;;
      *" describe-subnets "*) echo subnet-dry ;;
      *" create-security-group "*) echo sg-dry ;;
      *" run-instances "*) echo "i-dry$n" ;;
      *" create-snapshot "*) echo "snap-dry$n" ;;
      *" describe-snapshots "*"--snapshot-ids"*) echo completed ;;
      *" describe-snapshots "*) echo "snap-dry1 40 hearth-stress-dry-seed" ;;
      *"BlockDeviceMappings"*) echo vol-0dry0000000000001 ;;
      *"--query Reservations[].Instances[].InstanceId "*) echo i-dry-of-the-run ;;
      *" describe-instances "*"State.Name,PublicIpAddress,PrivateIpAddress"*)
        printf 'running %s %s\n' "$(public_ip $((n % 250)))" "$(private_ip $((n % 250)))" ;;
    esac
    ;;
  ssh)
    # The options, then root@host, then the remote command.
    while [ $# -gt 0 ]; do
      case $1 in
        -i | -o) shift 2 ;;
        root@*) host=${1#root@}; shift; break ;;
        *) shift ;;
      esac
    done
    cmd="$*"
    log "ssh ${host:-?}: $(tr '\n' ' ' <<< "$cmd" | tr -s ' ' | cut -c1-400)"
    # Every remote command that reads stdin (cat > file, tar -x) gets it.
    [ -t 0 ] || cat > /dev/null
    if [ -n "${DRY_SSH_GONE_AFTER:-}" ]; then
      if [ -e "$state/gone-${host:-?}" ]; then
        echo "ssh: connect to host ${host:-?} port 22: Connection timed out" >&2
        exit 255
      fi
      [[ $cmd != *"$DRY_SSH_GONE_AFTER"* ]] || touch "$state/gone-${host:-?}"
    fi
    ! fails "$cmd" || exit 1
    case $cmd in
      *"date +%s"*) date +%s ;;
      *"/v1/metrics"*) exit 7 ;;
      *"/admin/bootstrap"*) echo 404 ;;
      *"prepare.json"*"api_secrets"*) echo STRESS_API_SECRET=dry-not-a-secret ;;
      *"cat /opt/stress/out/"*"/k6.exit"*) echo 0 ;;
      *"remote.sh idle"*) echo 204800 ;;
      *"remote.sh store-size"*) echo 4000000000 ;;
      *"remote.sh data-pristine"*) echo "read 42949672960 bytes in 300 s" ;;
      *"remote.sh pull"*) echo "pulled 3 images in 40 s" ;;
      *"remote.sh settle"*) echo "settled after 30 s" ;;
      *"remote.sh restore"*) echo "restored in 60 s" ;;
      *"head -n"*"ids-1000000.txt"*) printf 'id-%d\n' 1 2 3 ;;
      *"grep -E \"^(MemTotal"*) printf 'MemTotal: 16000000 kB\nSwapTotal: 0 kB\n2\n' ;;
    esac
    exit 0
    ;;
  scp)
    args=()
    for a in "$@"; do args+=("$a"); done
    log "scp ${args[*]}"
    ! fails "${args[*]}" || exit 1
    last=${args[-1]}
    src=${args[-2]}
    case $src in
      root@*:*)
        # A fetch: make up what cloud.sh collect and compare.sh read.
        case $src in
          *raw.csv.gz) fake_raw "$last" ;;
          *summary.json)
            start=$(sed -n 's/^START_AT=//p' "$(dirname "$last")/params.env")
            echo "{\"started_at\": $((start * 1000))}" > "$last" ;;
          *.sampler.csv) fake_sampler "$last" ;;
          *result.json) echo '{"users_imported": 1000000, "users_import_failed": 0, "duration_s": 600}' > "$last" ;;
          *generator.env) printf 'PRODUCT=dry\nSTRESS_SERVER_IP=%s\nSTRESS_API_SECRET=dry-not-a-secret\n' "$(private_ip 1)" > "$last" ;;
          *ca.crt | *k6.txt | *console.log | *gen-sampler.csv) : > "$last" ;;
          *) exit 1 ;;
        esac
        ;;
    esac
    exit 0
    ;;
  docker)
    log "docker $*"
    case " $* " in
      *" image inspect "*) echo 0123456789abcdef0123456789abcdef01234567 ;;
      *" create "*) echo cid-dry ;;
      *" cp "*) eval "dest=\${$#}"; touch "$dest" ;;
    esac
    ;;
  curl)
    log "curl $*"
    public_ip 7
    echo
    ;;
  ssh-keygen)
    log "ssh-keygen $*"
    while [ $# -gt 0 ]; do [ "$1" = -f ] && touch "$2" "$2.pub"; shift; done
    ;;
  sleep) ;;
  *) log "unknown tool $tool $*"; exit 1 ;;
esac
exit 0
