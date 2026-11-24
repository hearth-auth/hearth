#!/usr/bin/env bash
# Tests the hard lifetime of every AWS instance cloud.sh starts (#913): each
# run-instances call terminates the instance on shutdown, and its user data
# schedules that shutdown at first boot.
#
#   case 1  default: 240 minutes, for the server and the generators of `up`
#   case 2  AWS_MAX_MINUTES=90, and SERVER_MAX_MINUTES / GENERATOR_MAX_MINUTES
#           per instance (a seed server: its estimate plus 50 %)
#   case 3  AWS_MAX_HOURS=6 (the #647 rounds' setting) gives 360 minutes
#   case 4  a bad lifetime is refused, and nothing is launched
#   case 5  a server data volume: a second gp3 mapping, from a snapshot if given
#
# A fake `aws` (written below) records each call's arguments and answers just
# enough for `up`; nothing reaches AWS. The addresses it hands out are made at
# run time.
#
# Usage: bash loadtest/live/test_lifetime.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "ok: $*"; }

mkdir -p "$tmp/bin"
# Each call: one line "CALL", then one argument per line.
cat > "$tmp/bin/aws" << 'EOF'
#!/usr/bin/env bash
{ echo CALL; printf '%s\n' "$@"; } >> "$FAKE_AWS_LOG"
n=$(($(grep -c '^CALL$' "$FAKE_AWS_LOG")))
case " $* " in
  *" sts get-caller-identity "*) echo "arn:aws:iam::ACCOUNT:user/hearth-stress-runner" ;;
  *" ssm get-parameter "*) echo ami-fake ;;
  *" describe-vpcs "*) echo vpc-fake ;;
  *" describe-subnets "*) echo subnet-fake ;;
  *" create-security-group "*) echo sg-fake ;;
  *" run-instances "*) echo "i-fake$n" ;;
  *" describe-instances "*) printf 'running %s %s\n' "$(printf '%d.%d.%d.%d' 198 51 100 $((n % 250)))" \
    "$(printf '%d.%d.%d.%d' 172 31 0 $((n % 250)))" ;;
esac
exit 0
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/sleep"
cat > "$tmp/bin/ssh-keygen" << 'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do [ "$1" = -f ] && { touch "$2" "$2.pub"; }; shift; done
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/ssh"
printf '#!/usr/bin/env bash\nprintf "%%d.%%d.%%d.%%d\\n" 203 0 113 7\n' > "$tmp/bin/curl"
chmod +x "$tmp/bin"/*

# Runs cloud.sh with the fake aws in a copy of loadtest/live (its .build/ is
# the copy's). $1: case name; the rest: env assignments; then "--" and the
# cloud.sh arguments.
run_case() {
  local name=$1
  shift
  local envs=()
  while [ "$1" != -- ]; do envs+=("$1"); shift; done
  shift
  mkdir -p "$tmp/$name"
  cp "$here/cloud.sh" "$here/provider-aws.sh" "$tmp/$name/"
  : > "$tmp/$name.log"
  env -u AWS_MAX_HOURS -u AWS_MAX_MINUTES -u SERVER_MAX_MINUTES -u GENERATOR_MAX_MINUTES \
    -u STRESS_RUN -u SERVER_DATA_GB -u SERVER_DATA_SNAPSHOT \
    PATH="$tmp/bin:$PATH" FAKE_AWS_LOG="$tmp/$name.log" PROVIDER=aws AWS_PROFILE=hearth-stress \
    "${envs[@]}" bash "$tmp/$name/cloud.sh" "$@" > "$tmp/$name.out" 2>&1
}

# The arguments of the run-instances calls of a log, one call per paragraph.
launches() {
  awk '/^CALL$/ {if (keep) print ""; keep = 0; next} $0 == "run-instances" {keep = 1} keep' "$1"
}

# Checks every launch of log $1 carries terminate-on-shutdown and the lifetime
# of the name pattern: $2 = "<name regex>=<minutes> ...".
check_lifetimes() {
  local log=$1 want=$2 count
  count=$(launches "$log" | grep -c '^run-instances$')
  [ "$count" -gt 0 ] || { fail "$log: no run-instances call"; return; }
  local para name minutes rule ok_all=1
  while IFS= read -r -d '' para; do
    name=$(grep -o 'Key=Name,Value=[^}]*' <<< "$para" | head -n 1 | cut -d= -f3)
    grep -qx -- '--instance-initiated-shutdown-behavior' <<< "$para" \
      && grep -A1 -x -- '--instance-initiated-shutdown-behavior' <<< "$para" | tail -n 1 | grep -qx terminate \
      || { fail "$name: launched without --instance-initiated-shutdown-behavior terminate"; ok_all=0; }
    minutes=$(grep -o 'shutdown, -h, "+[0-9]*"' <<< "$para" | grep -o '[0-9]*')
    for rule in $want; do
      if [[ $name =~ ${rule%%=*} ]]; then
        [ "$minutes" = "${rule#*=}" ] \
          || { fail "$name: shutdown in ${minutes:-none} minutes, want ${rule#*=}"; ok_all=0; }
        break
      fi
    done
  done < <(launches "$log" | awk 'BEGIN {RS = ""; ORS = "\0"} {print}')
  [ "$ok_all" = 0 ] || pass "$3 ($count launches)"
}

# case 1
run_case default GENERATORS=2 -- up
check_lifetimes "$tmp/default.log" "server=240 gen=240" "default lifetime 240 minutes, terminate on shutdown"
grep -q 'disable_root: false' "$tmp/default.log" || fail "the user data lost disable_root"

# case 2
run_case minutes GENERATORS=2 AWS_MAX_MINUTES=90 SERVER_MAX_MINUTES=1440 -- up
check_lifetimes "$tmp/minutes.log" "server=1440 gen=90" "AWS_MAX_MINUTES and SERVER_MAX_MINUTES"
run_case seed GENERATORS=0 SERVER_MAX_MINUTES=960 -- up
check_lifetimes "$tmp/seed.log" "server=960" "a server-only run with its own lifetime"
[ "$(launches "$tmp/seed.log" | grep -c '^run-instances$')" = 1 ] || fail "GENERATORS=0 launched generators"
run_case gens GENERATORS=1 GENERATOR_MAX_MINUTES=30 -- up
check_lifetimes "$tmp/gens.log" "server=240 gen=30" "GENERATOR_MAX_MINUTES"

# case 3
run_case hours GENERATORS=1 AWS_MAX_HOURS=6 -- up
check_lifetimes "$tmp/hours.log" "server=360 gen=360" "AWS_MAX_HOURS=6 is 360 minutes"

# case 4
for bad in "AWS_MAX_MINUTES=0" "AWS_MAX_MINUTES=4h" "SERVER_MAX_MINUTES=-5"; do
  run_case bad GENERATORS=1 "$bad" -- up
  if grep -q '^run-instances$' "$tmp/bad.log"; then
    fail "$bad: an instance was launched"
  else
    pass "$bad: refused before any launch"
  fi
done

# case 5
run_case data GENERATORS=1 STRESS_RUN=t913-data SERVER_DATA_GB=40 SERVER_DATA_SNAPSHOT=snap-fake -- up
server=$(launches "$tmp/data.log" | awk 'BEGIN {RS = ""} /Value=hearth-stress-t913-data-server/')
gen=$(launches "$tmp/data.log" | awk 'BEGIN {RS = ""} /Value=hearth-stress-t913-data-gen1/')
grep -q 'DeviceName=/dev/sdf,Ebs={VolumeSize=40,VolumeType=gp3,Iops=3000,Throughput=125,Encrypted=true,DeleteOnTermination=true,SnapshotId=snap-fake}' <<< "$server" \
  && pass "server data volume from a snapshot, deleted with the instance" \
  || fail "server launch has no data volume mapping: $server"
grep -q '/dev/sdf' <<< "$gen" && fail "a generator got the data volume" || pass "generators get no data volume"
[ -f "$tmp/data/.build/run-t913-data/run.env" ] && pass "STRESS_RUN names the new run" \
  || fail "STRESS_RUN did not name the run"
run_case data GENERATORS=1 STRESS_RUN=t913-data -- up
grep -q 'exists already' "$tmp/data.out" && pass "an existing run id is refused" || fail "an existing run id was reused"

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
