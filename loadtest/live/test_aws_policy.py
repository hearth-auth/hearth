"""Static tests for aws-policy.json, the policy of the hearth-stress-runner user.

The #913 session stopped at its first snapshot: tag-on-create for CreateSnapshot
was denied, because a snapshot ARN has no account field and the statement only
named account-ful ARNs. These tests check, without AWS, that every resource
type the scripts create with --tag-specifications can be tagged on create, and
that aws-iam.sh can still upload the policy.

Usage: python3 -I loadtest/live/test_aws_policy.py
"""
import glob
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LOADTEST = os.path.dirname(HERE)
REGION = "us-east-1"
ACCOUNT = "123456789012"  # aws-iam.sh puts the 12-digit account here

# Each type the scripts tag on create: the action that creates it, and its ARN.
# EC2 snapshots (like images) have an EMPTY account field in their ARN.
TAGGED = {
    "instance": ("RunInstances", f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-1"),
    "volume": ("RunInstances", f"arn:aws:ec2:{REGION}:{ACCOUNT}:volume/vol-1"),
    "security-group": ("CreateSecurityGroup", f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-1"),
    "key-pair": ("ImportKeyPair", f"arn:aws:ec2:{REGION}:{ACCOUNT}:key-pair/key-1"),
    "snapshot": ("CreateSnapshot", f"arn:aws:ec2:{REGION}::snapshot/snap-1"),
}


def load_policy():
    with open(os.path.join(HERE, "aws-policy.json")) as f:
        text = f.read()
    return text, json.loads(text.replace("ACCOUNT_ID", ACCOUNT))


def as_list(v):
    return v if isinstance(v, list) else [v]


def arn_matches(pattern, arn):
    """IAM resource matching: `*` is any run of characters, `?` one character."""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, arn) is not None


def create_actions(stmt):
    cond = stmt.get("Condition", {})
    vals = []
    for op in ("StringEquals", "StringLike"):
        vals += as_list(cond.get(op, {}).get("ec2:CreateAction", []))
    return vals


def tag_on_create_allows(policy, action, arn):
    for s in policy["Statement"]:
        if s["Effect"] != "Allow" or "ec2:CreateTags" not in as_list(s["Action"]):
            continue
        if action not in create_actions(s):
            continue
        if any(arn_matches(r, arn) for r in as_list(s["Resource"])):
            return True
    return False


def tagged_types_in_scripts():
    found = set()
    for path in glob.glob(os.path.join(LOADTEST, "**", "*.sh"), recursive=True):
        with open(path) as f:
            found |= set(re.findall(r"\baws_tags ([a-z-]+)", f.read()))
    return found


class TagOnCreate(unittest.TestCase):
    def test_the_scripts_tag_only_types_this_test_knows(self):
        found = tagged_types_in_scripts()
        self.assertTrue(found, "no `aws_tags <type>` call found; did provider-aws.sh move?")
        self.assertLessEqual(found, set(TAGGED), "add the new type to TAGGED with its ARN shape")

    def test_every_tagged_type_can_be_tagged_on_create(self):
        _, policy = load_policy()
        for kind, (action, arn) in TAGGED.items():
            with self.subTest(kind=kind):
                self.assertTrue(tag_on_create_allows(policy, action, arn),
                                f"ec2:CreateTags for {action} denied on {arn}")

    def test_tag_on_create_is_not_allowed_outside_a_create_action(self):
        _, policy = load_policy()
        for s in policy["Statement"]:
            if "ec2:CreateTags" in as_list(s["Action"]):
                self.assertTrue(create_actions(s), f"statement {s.get('Sid')} tags without ec2:CreateAction")


class Upload(unittest.TestCase):
    def test_aws_iam_can_upload_the_policy(self):
        text, policy = load_policy()
        self.assertEqual(policy["Version"], "2012-10-17")
        self.assertNotRegex(text, r"\d{12}", "an account ID belongs in aws-iam.sh, not the repo")
        # An IAM managed policy is at most 6,144 characters, whitespace not counted,
        # after aws-iam.sh puts the account in.
        size = len(re.sub(r"\s", "", text.replace("ACCOUNT_ID", ACCOUNT)))
        self.assertLessEqual(size, 6144)


if __name__ == "__main__":
    unittest.main()
