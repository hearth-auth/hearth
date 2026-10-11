#!/usr/bin/env bash
# Creates or deletes the scoped AWS identity that a live stress run uses: the
# managed policy hearth-stress-ec2 (aws-policy.json: EC2 in us-east-1 only, on
# c7i instances and on resources tagged hearth-stress-* only), the IAM user
# hearth-stress-runner with that policy, one access key, and the local CLI
# profile hearth-stress.
#
#   aws-iam.sh up     run with an admin session (for example right after `aws login`)
#   aws-iam.sh down   delete the key, the user, the policy and the local profile
#
# An admin session from `aws login` can expire after a few minutes, so run `up`
# right after the login. Run `down` after every round, once `cloud.sh down`
# reports that nothing is left.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
user=hearth-stress-runner
policy=hearth-stress-ec2
profile=hearth-stress
die() { echo "aws-iam: $*" >&2; exit 1; }

case ${AWS_PROFILE:-} in
  "$profile"*) die "run this with an admin profile, not AWS_PROFILE=$AWS_PROFILE" ;;
esac

# Removes section [$2] from the INI file $1.
drop_section() {
  [ -f "$1" ] || return 0
  python3 -I - "$1" "$2" << 'EOF'
import re, sys
path, name = sys.argv[1], sys.argv[2]
out, skip = [], False
for line in open(path).read().splitlines(keepends=True):
    m = re.match(r"\s*\[(.+)\]\s*$", line)
    if m:
        skip = m.group(1).strip() == name
    if not skip:
        out.append(line)
open(path, "w").write("".join(out).rstrip("\n") + "\n")
EOF
}

account=$(aws sts get-caller-identity --query Account --output text) || die "not logged in"
arn=arn:aws:iam::$account:policy/$policy

case ${1:-} in
  up)
    grep -q "^\[$profile\]" ~/.aws/credentials 2> /dev/null && die "profile $profile exists; run down first"
    doc=$(mktemp)
    trap 'rm -f "$doc"' EXIT
    sed "s/ACCOUNT_ID/$account/g" "$here/aws-policy.json" > "$doc"
    aws iam create-policy --policy-name "$policy" --policy-document "file://$doc" > /dev/null
    aws iam create-user --user-name "$user" --tags Key=purpose,Value=hearth-stress > /dev/null
    aws iam attach-user-policy --user-name "$user" --policy-arn "$arn"
    read -r kid secret < <(aws iam create-access-key --user-name "$user" \
      --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
    umask 077
    mkdir -p ~/.aws
    printf '\n[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n' \
      "$profile" "$kid" "$secret" >> ~/.aws/credentials
    printf '\n[profile %s]\nregion = us-east-1\noutput = json\n' "$profile" >> ~/.aws/config
    echo "aws-iam: user $user with policy $policy; local profile $profile"
    ;;
  down)
    for kid in $(aws iam list-access-keys --user-name "$user" \
      --query 'AccessKeyMetadata[].AccessKeyId' --output text 2> /dev/null); do
      aws iam delete-access-key --user-name "$user" --access-key-id "$kid"
    done
    aws iam detach-user-policy --user-name "$user" --policy-arn "$arn" 2> /dev/null || true
    aws iam delete-user --user-name "$user" 2> /dev/null || true
    for v in $(aws iam list-policy-versions --policy-arn "$arn" \
      --query 'Versions[?!IsDefaultVersion].VersionId' --output text 2> /dev/null); do
      aws iam delete-policy-version --policy-arn "$arn" --version-id "$v"
    done
    aws iam delete-policy --policy-arn "$arn" 2> /dev/null || true
    drop_section ~/.aws/credentials "$profile"
    drop_section ~/.aws/config "profile $profile"
    aws iam get-user --user-name "$user" > /dev/null 2>&1 && die "user $user still exists"
    aws iam get-policy --policy-arn "$arn" > /dev/null 2>&1 && die "policy $policy still exists"
    echo "aws-iam: user, key, policy and local profile deleted"
    ;;
  *)
    sed -n '2,13p' "$0"
    exit 2
    ;;
esac
