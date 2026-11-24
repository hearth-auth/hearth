# shellcheck shell=bash
# Sourced by cloud.sh, which defines build, generators, log, die and the rest.
# shellcheck disable=SC2154
# AWS EC2 versions of cloud.sh's provider commands. cloud.sh sources this file
# when PROVIDER=aws; every other command (deploy, ramp, collect, ...) works over
# SSH and is shared. Uses the aws CLI profile you are logged in with
# (AWS_PROFILE, default hearth-stress; only hearth-stress* profiles are accepted,
# and never the account root).
#
# Settings (environment), on top of cloud.sh's:
#   AWS_REGION       us-east-1
#   AWS_AZ           us-east-1a (all instances share one availability zone)
#   SERVER_SIZE      c7i.large   (2 vCPU, 4 GiB)
#   GENERATOR_SIZE   c7i.xlarge  (4 vCPU, 8 GiB)
#                    The policy also allows r7i.large (2 vCPU, 16 GiB; the
#                    10M-user round of #647), c7i.2xlarge and t3.medium (2 vCPU,
#                    4 GiB, about half the price of c7i.large; for long memory
#                    soaks, not for latency). A t3 instance starts in unlimited
#                    mode, so a run never loses CPU when its credits run out.
#   AWS_DISK_GB      30          (gp3 root volume, 3,000 IOPS, 125 MB/s, encrypted)
#   AWS_MAX_MINUTES  240         (each instance's hard lifetime: it shuts
#                                 itself down, and so terminates, this long
#                                 after boot, a cost guard if this session
#                                 dies before `down`. AWS_MAX_HOURS, if set,
#                                 gives it in hours instead. A round that runs
#                                 longer MUST raise it: #647 round C ran 5.3 h)
#   SERVER_MAX_MINUTES, GENERATOR_MAX_MINUTES
#                                 the same for the server or the generators
#                                 only (default AWS_MAX_MINUTES)
#   SERVER_DATA_GB, SERVER_DATA_SNAPSHOT
#                    a second volume for the server only (below)
#   AWS_EXTRA_PORTS  ports the group's members may reach besides 22 and 8443,
#                    e.g. "4433-4455 9443" (the #913 products; compare/aws)
#
# Security: the security group admits SSH (22) only from this machine's public
# address and from members of the group, and Hearth's port (8443) only from
# members. Instances get no IAM role, so no AWS credentials, and require
# IMDSv2. The key pair, security group and instances carry the run's tag, and
# `down` deletes them.

aws_region=${AWS_REGION:-us-east-1}
aws_az=${AWS_AZ:-${aws_region}a}
server_size=${SERVER_SIZE:-c7i.large}
generator_size=${GENERATOR_SIZE:-c7i.xlarge}
aws_disk_gb=${AWS_DISK_GB:-30}
if [ -n "${AWS_MAX_HOURS:-}" ]; then
  aws_max_minutes=$((AWS_MAX_HOURS * 60))
else
  aws_max_minutes=${AWS_MAX_MINUTES:-240}
fi
[[ $aws_max_minutes =~ ^[1-9][0-9]*$ ]] || die "AWS_MAX_MINUTES must be a positive number of minutes"
# shellcheck disable=SC2034 # cloud.sh records it in the inventory
region=$aws_region

aws_profile=${AWS_PROFILE:-hearth-stress}
export AWS_PROFILE=$aws_profile
aws_() { timeout 120 aws --region "$aws_region" "$@"; }

# Accepts only a hearth-stress* profile and refuses a root session: a load test
# runs only as the scoped IAM user (EC2 on tagged resources in one region,
# nothing else; see aws-iam.sh).
aws_check_identity() {
  case $aws_profile in
    hearth-stress*) ;;
    *) die "AWS_PROFILE=$aws_profile is not a load-test profile (want hearth-stress*)" ;;
  esac
  local arn
  arn=$(aws_ sts get-caller-identity --query Arn --output text) \
    || die "the aws CLI is not logged in for profile $aws_profile"
  case $arn in
    *:root) die "profile $aws_profile is the account root; use the scoped hearth-stress profile" ;;
  esac
  echo "$arn"
}

# Ubuntu 24.04 LTS (amd64, gp3) — Canonical's public SSM parameter.
aws_ami() {
  aws_ ssm get-parameter \
    --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
    --query Parameter.Value --output text
}

aws_tags() {
  local kind=$1 name=$2
  echo "ResourceType=$kind,Tags=[{Key=Name,Value=$name},{Key=hearth-stress,Value=$TAG},{Key=Project,Value=hearth},{Key=Purpose,Value=${AWS_PURPOSE:-stress}}]"
}

# The cloud-init user data of an instance with a lifetime of $1 minutes: root
# takes the key pair (cloud.sh connects as root), and the instance schedules
# its own shutdown at first boot, which terminates it
# (--instance-initiated-shutdown-behavior terminate). cloud.sh never reboots
# an instance, which would clear the timer.
aws_user_data() {
  printf '#cloud-config\ndisable_root: false\nruncmd:\n  - [shutdown, -h, "+%s"]\n' "$1"
}

# Creates one instance and prints "ID PUBLIC PRIVATE" once it is running.
# $3: its lifetime in minutes (default AWS_MAX_MINUTES). $4: the GB of a second
# gp3 volume (/dev/sdf, the root volume's IOPS and throughput, deleted with the
# instance), made from snapshot $5 if given.
create_droplet() {
  local name=$1 size=$2 minutes=${3:-$aws_max_minutes} data_gb=${4:-} snap=${5:-}
  local id line state public private ud
  [[ $minutes =~ ^[1-9][0-9]*$ ]] || die "lifetime '$minutes' of $name is not a number of minutes"
  ud=$(aws_user_data "$minutes")
  local disks=("DeviceName=/dev/sda1,Ebs={VolumeSize=$aws_disk_gb,VolumeType=gp3,Iops=3000,Throughput=125,Encrypted=true,DeleteOnTermination=true}")
  if [ -n "$data_gb" ]; then
    [[ $data_gb =~ ^[1-9][0-9]*$ ]] || die "data volume size '$data_gb' is not a number of GB"
    disks+=("DeviceName=/dev/sdf,Ebs={VolumeSize=$data_gb,VolumeType=gp3,Iops=3000,Throughput=125,Encrypted=true,DeleteOnTermination=true${snap:+,SnapshotId=$snap}}")
  fi
  local credits=()
  case $size in t3.* | t3a.*) credits=(--credit-specification CpuCredits=unlimited) ;; esac
  id=$(aws_ ec2 run-instances \
    --image-id "$AWS_AMI" --instance-type "$size" --key-name "$KEY_ID" "${credits[@]}" \
    --security-group-ids "$FW_ID" --subnet-id "$AWS_SUBNET" --associate-public-ip-address \
    --instance-initiated-shutdown-behavior terminate \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --block-device-mappings "${disks[@]}" \
    --tag-specifications "$(aws_tags instance "$name")" "$(aws_tags volume "$name")" \
    --user-data "$ud" --query 'Instances[0].InstanceId' --output text) \
    || die "creating $name failed; check: aws ec2 describe-instances --filters Name=tag:hearth-stress,Values=$TAG"
  for _ in $(seq 1 60); do
    line=$(aws_ ec2 describe-instances --instance-ids "$id" \
      --query 'Reservations[0].Instances[0].[State.Name,PublicIpAddress,PrivateIpAddress]' \
      --output text || true)
    read -r state public private <<< "$line"
    if [ "$state" = running ] && [ "$public" != None ] && [ -n "$public" ]; then
      echo "$id $public $private"
      return 0
    fi
    sleep 5
  done
  die "$name ($id) did not start"
}

cmd_up() {
  command -v aws > /dev/null || die "the aws CLI is not installed"
  local account
  account=$(aws_check_identity)
  local id
  # STRESS_RUN names the new run (a driver that starts several runs at once
  # must not let two of them share a second's id).
  id=${STRESS_RUN:-$(date -u +%Y%m%d-%H%M%S)}
  [[ $id =~ ^[0-9A-Za-z-]+$ ]] || die "run id '$id' may hold only letters, digits and -"
  run=$build/run-$id
  [ ! -e "$run" ] || die "$run exists already"
  umask 077
  mkdir -p "$run"
  TAG=hearth-stress-$id
  local my_ip vpc
  my_ip=$(my_public_ip)

  vpc=$(aws_ ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
  [ "$vpc" != None ] || die "no default VPC in $aws_region"
  AWS_SUBNET=$(aws_ ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc" \
    Name=default-for-az,Values=true "Name=availability-zone,Values=$aws_az" \
    --query 'Subnets[0].SubnetId' --output text)
  [ "$AWS_SUBNET" != None ] || die "no default subnet in $aws_az"
  AWS_AMI=$(aws_ami)

  log "run $id: $account, $aws_az; SSH key pair"
  ssh-keygen -q -t ed25519 -N '' -C "$TAG" -f "$run/id_ed25519"
  # Each resource id goes into run.env as soon as it exists, so `down`
  # can clean up after a failure part-way through.
  printf 'RUN_ID=%s\nTAG=%s\nPROVIDER=aws\nAWS_PROFILE=%s\nAWS_REGION=%s\nAWS_SUBNET=%s\nAWS_AMI=%s\n' \
    "$id" "$TAG" "$aws_profile" "$aws_region" "$AWS_SUBNET" "$AWS_AMI" > "$run/run.env"
  aws_ ec2 import-key-pair --key-name "$TAG" \
    --public-key-material "fileb://$run/id_ed25519.pub" \
    --tag-specifications "$(aws_tags key-pair "$TAG")" > /dev/null
  KEY_ID=$TAG
  echo "KEY_ID=$KEY_ID" >> "$run/run.env"

  log "run $id: security group (SSH from $my_ip and the group; 8443 from the group)"
  FW_ID=$(aws_ ec2 create-security-group --group-name "$TAG" --vpc-id "$vpc" \
    --description "Hearth stress run $id" \
    --tag-specifications "$(aws_tags security-group "$TAG")" --query GroupId --output text)
  printf 'FW_ID=%s\nSSH_FROM=%s\n' "$FW_ID" "$my_ip" >> "$run/run.env"
  aws_ ec2 authorize-security-group-ingress --group-id "$FW_ID" --ip-permissions \
    "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$my_ip/32}]" \
    "IpProtocol=tcp,FromPort=22,ToPort=22,UserIdGroupPairs=[{GroupId=$FW_ID}]" \
    "IpProtocol=tcp,FromPort=8443,ToPort=8443,UserIdGroupPairs=[{GroupId=$FW_ID}]" > /dev/null
  local ports from to
  for ports in ${AWS_EXTRA_PORTS:-}; do
    from=${ports%-*} to=${ports#*-}
    [[ $from =~ ^[0-9]+$ && $to =~ ^[0-9]+$ ]] || die "AWS_EXTRA_PORTS: '$ports' is not a port or a range"
    aws_ ec2 authorize-security-group-ingress --group-id "$FW_ID" --ip-permissions \
      "IpProtocol=tcp,FromPort=$from,ToPort=$to,UserIdGroupPairs=[{GroupId=$FW_ID}]" > /dev/null
  done

  log "run $id: server $server_size and $generators x $generator_size generator in $aws_az"
  local line
  line=$(create_droplet "$TAG-server" "$server_size" "${SERVER_MAX_MINUTES:-$aws_max_minutes}" \
    "${SERVER_DATA_GB:-}" "${SERVER_DATA_SNAPSHOT:-}")
  read -r server_id server_public server_private <<< "$line"
  printf 'SERVER_ID=%s\nSERVER_PUBLIC=%s\nSERVER_PRIVATE=%s\nSERVER_SIZE_SLUG=%s\n' \
    "$server_id" "$server_public" "$server_private" "$server_size" >> "$run/run.env"
  local i
  for i in $(seq 1 "$generators"); do
    line=$(create_droplet "$TAG-gen$i" "$generator_size" "${GENERATOR_MAX_MINUTES:-$aws_max_minutes}")
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

# Finishes an `up` that stopped part-way: records the run's instances that
# run.env does not list yet, creates the generators still missing, and waits
# for SSH on all of them.
cmd_up_resume() {
  run=$(run_dir)
  # shellcheck disable=SC1091
  . "$run/run.env"
  local i var name line id public private state
  for i in $(seq 1 "$generators"); do
    var=GEN${i}_ID
    [ -z "${!var:-}" ] || continue
    name=$TAG-gen$i
    line=$(aws_ ec2 describe-instances --filters "Name=tag:Name,Values=$name" \
      Name=instance-state-name,Values=pending,running \
      --query 'Reservations[0].Instances[0].[InstanceId,State.Name,PublicIpAddress,PrivateIpAddress]' \
      --output text || true)
    if [ -n "$line" ] && [ "${line%%[[:space:]]*}" != None ]; then
      read -r id state public private <<< "$line"
      [ "$state" = running ] || die "$name exists but is $state"
      log "recording $name ($id)"
    else
      log "creating $name"
      read -r id public private <<< "$(create_droplet "$name" "$generator_size" "${GENERATOR_MAX_MINUTES:-$aws_max_minutes}")"
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

cmd_allow_ssh_here() {
  load_run
  local ip
  ip=$(my_public_ip)
  [ "$ip" != "${SSH_FROM:-}" ] || { log "SSH already allowed from $ip"; return 0; }
  aws_ ec2 authorize-security-group-ingress --group-id "$FW_ID" \
    --protocol tcp --port 22 --cidr "$ip/32" > /dev/null
  [ -z "${SSH_FROM:-}" ] \
    || aws_ ec2 revoke-security-group-ingress --group-id "$FW_ID" \
      --protocol tcp --port 22 --cidr "$SSH_FROM/32" > /dev/null
  echo "SSH_FROM=$ip" >> "$run/run.env"
  log "SSH now allowed from $ip only"
}

aws_list_instances() {
  aws_ ec2 describe-instances --filters "Name=tag:hearth-stress,Values=$TAG" \
    Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down \
    --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`]|[0].Value,State.Name,InstanceType,PublicIpAddress,PrivateIpAddress]' \
    --output text
}

cmd_status() {
  load_run
  aws_list_instances
  ssh_to "$SERVER_PUBLIC" "systemctl is-active hearth; systemctl list-units --no-legend 'observe-*' 'kill-*' 'profile-*'; tail -n 5 /opt/hearth/out/hearth.log" || true
}

cmd_down() {
  load_run
  aws_check_identity > /dev/null
  local ids
  ids=$(aws_ ec2 describe-instances --filters "Name=tag:hearth-stress,Values=$TAG" \
    Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down \
    --query 'Reservations[].Instances[].InstanceId' --output text || true)
  if [ -n "$ids" ]; then
    log "terminating instances tagged $TAG: $ids"
    # shellcheck disable=SC2086 # one id per word
    aws_ ec2 terminate-instances --instance-ids $ids > /dev/null || true
    # shellcheck disable=SC2086
    timeout 600 aws --region "$aws_region" ec2 wait instance-terminated --instance-ids $ids || true
  fi
  [ -z "${FW_ID:-}" ] || aws_ ec2 delete-security-group --group-id "$FW_ID" || true
  [ -z "${KEY_ID:-}" ] || aws_ ec2 delete-key-pair --key-name "$KEY_ID" || true
  log "left over (must be empty):"
  aws_list_instances
  aws_ ec2 describe-security-groups --filters "Name=tag:hearth-stress,Values=$TAG" \
    --query 'SecurityGroups[].GroupId' --output text
  aws_ ec2 describe-key-pairs --filters "Name=tag:hearth-stress,Values=$TAG" \
    --query 'KeyPairs[].KeyName' --output text
  aws_ ec2 describe-volumes --filters "Name=tag:hearth-stress,Values=$TAG" \
    --query 'Volumes[].VolumeId' --output text
  # Snapshots are kept on purpose (the #913 seeds); listed, never deleted here.
  log "snapshots kept (delete only with compare.sh delete-snapshots):"
  aws_list_snapshots
}

# Data volumes and snapshots (the #913 comparison, loadtest/compare/aws): a
# product's seeded store lives on the server's second volume (SERVER_DATA_GB,
# /dev/sdf, made at launch with the instance and deleted with it), which is
# kept as an EBS snapshot tagged with the seed run's tag; a ramp run's server
# launches with a volume made from it (SERVER_DATA_SNAPSHOT). Volumes and
# snapshots carry the run's tag, so `down` and the left-over check list them.
# A snapshot outlives its run: it is deleted only by
# `compare.sh delete-snapshots`, which lists what it deletes.

# Snapshots volume $1 as $2, waits until it is complete, and prints its id.
aws_snapshot() {
  local vol=$1 name=$2 snap state
  snap=$(aws_ ec2 create-snapshot --volume-id "$vol" --description "$name" \
    --tag-specifications "$(aws_tags snapshot "$name")" --query SnapshotId --output text) \
    || die "snapshotting $vol failed"
  # A first snapshot copies every written block to S3: minutes per 10 GB.
  for _ in $(seq 1 360); do
    state=$(aws_ ec2 describe-snapshots --snapshot-ids "$snap" --query 'Snapshots[0].State' --output text || true)
    case $state in
      completed) echo "$snap"; return 0 ;;
      error) die "snapshot $snap failed" ;;
    esac
    sleep 10
  done
  die "snapshot $snap is not complete after an hour"
}

# Snapshots tagged hearth-stress=<tag $1> (default: this run's): "ID SIZE NAME".
aws_list_snapshots() {
  aws_ ec2 describe-snapshots --owner-ids self --filters "Name=tag:hearth-stress,Values=${1:-$TAG}" \
    --query 'Snapshots[].[SnapshotId,VolumeSize,Tags[?Key==`Name`]|[0].Value]' --output text
}

# Deletes snapshot $1, which must carry a hearth-stress tag.
aws_delete_snapshot() {
  aws_ ec2 delete-snapshot --snapshot-id "$1"
}

# The id of the server's data volume (/dev/sdf).
aws_data_volume_id() {
  aws_ ec2 describe-instances --instance-ids "$SERVER_ID" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==`/dev/sdf`].Ebs.VolumeId' \
    --output text
}
