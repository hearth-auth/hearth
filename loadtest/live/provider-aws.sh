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
#   AWS_DISK_GB      30          (gp3 root volume, 3,000 IOPS, 125 MB/s, encrypted)
#   AWS_MAX_HOURS    10          (each instance shuts itself down, and so
#                                 terminates, after this long: a cost guard if
#                                 this session dies before `down`)
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
aws_max_hours=${AWS_MAX_HOURS:-10}
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

# Creates one instance and prints "ID PUBLIC PRIVATE" once it is running.
create_droplet() {
  local name=$1 size=$2 id line state public private ud
  # cloud-init: root takes the key pair (cloud.sh connects as root), and the
  # instance schedules its own shutdown, which terminates it.
  ud=$(printf '#cloud-config\ndisable_root: false\nruncmd:\n  - [shutdown, -h, "+%s"]\n' \
    "$((aws_max_hours * 60))")
  id=$(aws_ ec2 run-instances \
    --image-id "$AWS_AMI" --instance-type "$size" --key-name "$KEY_ID" \
    --security-group-ids "$FW_ID" --subnet-id "$AWS_SUBNET" --associate-public-ip-address \
    --instance-initiated-shutdown-behavior terminate \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$aws_disk_gb,VolumeType=gp3,Iops=3000,Throughput=125,Encrypted=true,DeleteOnTermination=true}" \
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
  id=$(date -u +%Y%m%d-%H%M%S)
  run=$build/run-$id
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

  log "run $id: server $server_size and $generators x $generator_size generator in $aws_az"
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
}
