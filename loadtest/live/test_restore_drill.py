#!/usr/bin/env python3
"""Tests for restore_drill.py: the comparison must fail on every kind of lost data.

Run: python3 loadtest/live/test_restore_drill.py

The tests sign real EdDSA tokens with Ed25519 keys that openssl makes, because the drill
checks the pre-backup token with openssl too.
"""
import base64
import contextlib
import copy
import io
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import restore_drill  # noqa: E402

T0 = 1_800_000_000
REALM = "0b7c6a52-6f1e-4c55-9a43-2d1f8e0c7a11"
CLIENT = "5d1c3a2b-7e6f-4a1b-8c9d-0e1f2a3b4c5d"
ROLE = "role_3f2e1d0c-9b8a-4765-8432-10fedcba9876"
ADMIN = "admin@hearth.stress.test"
USER1 = "user000001@hearth.stress.test"
CHECKS = {
    "restore exit status", "realm id", "user count", "sampled users", "email index",
    "known users sign in", "realm JWKS", "pre-backup token signature",
    "pre-backup token introspection", "client record", "client credentials", "role",
    "role assignments", "webhook subscriptions",
}


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def openssl(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


class Keys:
    """Two Ed25519 key pairs from openssl ("realm" and "other"), and a JWT signer."""

    def __init__(self, d):
        self.d = d
        self.pem = {}
        self.raw = {}
        for name in ("realm", "other"):
            pem = os.path.join(d, f"{name}.pem")
            openssl("genpkey", "-algorithm", "ed25519", "-out", pem)
            self.pem[name] = pem
            # The SubjectPublicKeyInfo ends with the 32-byte key.
            self.raw[name] = openssl("pkey", "-in", pem, "-pubout", "-outform", "DER")[-32:]

    def jwk(self, name, kid):
        return {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid,
                "x": b64url(self.raw[name])}

    def token(self, name, kid, claims):
        header = b64url(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": kid}).encode())
        payload = b64url(json.dumps(claims).encode())
        data = os.path.join(self.d, "signing-input")
        sig = os.path.join(self.d, "signature")
        with open(data, "wb") as f:
            f.write(f"{header}.{payload}".encode())
        openssl("pkeyutl", "-sign", "-inkey", self.pem[name], "-rawin", "-in", data, "-out", sig)
        with open(sig, "rb") as f:
            return f"{header}.{payload}.{b64url(f.read())}"


def ok(value):
    return {"ok": True, "value": value}


def user(i):
    uid = f"00000000-0000-4000-8000-{i:012d}"
    return uid, {
        "id": uid, "email": f"bulk{i:07d}@hearth.stress.test", "display_name": f"Bulk {i}",
        "first_name": f"Given{i}", "last_name": f"Family{i}", "status": "USER_STATUS_ACTIVE",
        "created_at": T0 * 10**6 + i, "updated_at": T0 * 10**6 + i,
    }


def snapshot(keys, phase="before", n_users=5):
    """A snapshot of a seeded server, as restore_drill.py snapshot writes it."""
    records = dict(user(i) for i in range(n_users))
    return {
        "phase": phase,
        "taken_at": T0 if phase == "before" else T0 + 600,
        "sections": {
            "admin": ok({"realm_id": REALM, "sub": "sub-admin"}),
            "user_count": ok(1_000_008),
            "users": ok({uid: {"status": 200, "record": rec} for uid, rec in records.items()}),
            "email_index": ok({rec["email"]: uid for uid, rec in records.items()}),
            "known_users": ok({ADMIN: {"ok": True, "sub": "sub-admin"},
                               USER1: {"ok": True, "sub": "sub-user1"}}),
            "jwks": ok({"keys": [keys.jwk("realm", "k1")]}),
            "client": ok({"client_id": CLIENT, "client_name": "Restore drill service",
                          "is_confidential": True, "grant_types": ["client_credentials"],
                          "created_at": T0}),
            "client_token": ok({"with_secret": 200, "without_secret": 401}),
            "old_token": ok({"active": True,
                             "checked_at": T0 + 5 if phase == "before" else T0 + 600}),
            "role": ok({"id": ROLE, "name": "drill.reader", "permissions": ["drill.read"]}),
            "assignments": ok([{"id": "asg-1", "role_id": ROLE, "scope": "realm"}]),
            "webhooks": ok([{"id": "wh-1", "url": "https://example.com/hearth-restore-drill",
                             "secret_sha256": "ab" * 32, "event_filters": ["realm_deleted"]}]),
        },
    }


def results(findings):
    """{check: (result, detail)}"""
    return {f["check"]: (f["result"], f["detail"]) for f in findings}


class CompareTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.keys = Keys(cls.tmp.name)
        cls.token = cls.keys.token("realm", "k1", {
            "iss": "https://hearth.stress.test:8443", "sub": CLIENT, "tid": f"realm_{REALM}",
            "iat": T0, "exp": T0 + 3600})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.before = snapshot(self.keys, "before")
        self.after = snapshot(self.keys, "after")

    def compare(self, **kw):
        kw.setdefault("token", self.token)
        kw.setdefault("restore_exit", 0)
        return results(restore_drill.compare(self.before, self.after, **kw))

    def assertFails(self, check, *words, **kw):
        r = self.compare(**kw)
        self.assertIn(check, r)
        result, detail = r[check]
        self.assertEqual(result, "FAIL", f"{check}: {detail}")
        for w in words:
            self.assertIn(w, detail)
        self.assertEqual(restore_drill.verdict(list(self.findings_of(**kw))), "FAIL")
        return detail

    def findings_of(self, **kw):
        kw.setdefault("token", self.token)
        kw.setdefault("restore_exit", 0)
        return restore_drill.compare(self.before, self.after, **kw)

    def after_section(self, name):
        return self.after["sections"][name]["value"]

    def test_an_identical_restore_passes(self):
        findings = self.findings_of()
        r = results(findings)
        self.assertEqual(set(r), CHECKS)
        for check, (result, detail) in r.items():
            self.assertEqual(result, "PASS", f"{check}: {detail}")
        self.assertEqual(restore_drill.verdict(findings), "PASS")

    def test_a_restore_that_exits_non_zero_fails(self):
        self.assertFails("restore exit status", "1", restore_exit=1)

    def test_a_new_realm_id_fails(self):
        self.after_section("admin")["realm_id"] = "11111111-2222-4333-8444-555555555555"
        self.assertFails("realm id", REALM)

    def test_a_lower_user_count_fails(self):
        self.after["sections"]["user_count"] = ok(1_000_007)
        self.assertFails("user count", "1000008", "1000007")

    def test_a_missing_user_fails(self):
        uid = next(iter(self.after_section("users")))
        self.after_section("users")[uid] = {"status": 404}
        detail = self.assertFails("sampled users", "1 missing", uid)
        self.assertIn("5", detail)

    def test_a_changed_field_fails(self):
        uid, rec = next(iter(self.after_section("users").items()))
        rec["record"]["display_name"] = "Someone else"
        self.assertFails("sampled users", "display_name", "1 of 5", uid)

    def test_a_dropped_field_fails(self):
        # The API leaves out an empty field (required_actions, for one): a field that only
        # one side has is a difference too.
        _, rec = next(iter(self.after_section("users").items()))
        del rec["record"]["last_name"]
        self.assertFails("sampled users", "last_name")

    def test_reset_timestamps_fail(self):
        for rec in self.after_section("users").values():
            rec["record"]["created_at"] += 3600 * 10**6
        self.assertFails("sampled users", "created_at", "5 of 5")

    def test_an_unreadable_user_fails(self):
        uid = next(iter(self.after_section("users")))
        self.after_section("users")[uid] = {"status": 500, "error": "internal"}
        self.assertFails("sampled users", "1 unreadable")

    def test_an_empty_sample_fails(self):
        self.before["sections"]["users"] = ok({})
        self.after["sections"]["users"] = ok({})
        self.assertFails("sampled users", "no user")

    def test_an_email_that_no_longer_finds_its_user_fails(self):
        email = next(iter(self.after_section("email_index")))
        self.after_section("email_index")[email] = None
        self.assertFails("email index", email)

    def test_a_known_user_who_cannot_sign_in_fails(self):
        self.after_section("known_users")[USER1] = {"ok": False, "error": "login_submit: 200"}
        self.assertFails("known users sign in", USER1, "login_submit")

    def test_a_recreated_known_user_fails(self):
        # A seed user that the restore lost comes back from hearth.yaml with a new id.
        self.after_section("known_users")[USER1] = {"ok": True, "sub": "sub-new"}
        self.assertFails("known users sign in", USER1, "sub-new")

    def test_a_different_jwks_fails(self):
        self.after["sections"]["jwks"] = ok({"keys": [self.keys.jwk("other", "k2")]})
        self.assertFails("realm JWKS")

    def test_a_token_signed_by_a_lost_key_fails(self):
        # Same kid, other key: only the signature check can tell.
        self.after["sections"]["jwks"] = ok({"keys": [self.keys.jwk("other", "k1")]})
        self.assertFails("pre-backup token signature", "does not verify")
        self.assertFails("realm JWKS")

    def test_a_token_whose_kid_is_gone_fails(self):
        self.after["sections"]["jwks"] = ok({"keys": [self.keys.jwk("realm", "k2")]})
        self.assertFails("pre-backup token signature", "k1")

    def test_a_tampered_token_fails(self):
        header, payload, sig = self.token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["sub"] = "someone-else"
        forged = ".".join([header, b64url(json.dumps(claims).encode()), sig])
        self.assertFails("pre-backup token signature", token=forged)

    def test_no_token_fails(self):
        self.assertFails("pre-backup token signature", token=None)

    def test_a_token_the_restored_server_refuses_before_it_expires_fails(self):
        self.after["sections"]["old_token"] = ok({"active": False, "checked_at": T0 + 600})
        self.assertFails("pre-backup token introspection", "inactive")

    def test_an_expired_token_is_skipped_not_passed(self):
        # A restore that takes longer than the token lifetime cannot show it active.
        self.after["sections"]["old_token"] = ok({"active": False, "checked_at": T0 + 7200})
        findings = self.findings_of()
        result, detail = results(findings)["pre-backup token introspection"]
        self.assertEqual(result, "SKIPPED", detail)
        self.assertIn("expired", detail)
        self.assertEqual(restore_drill.verdict(findings), "PASS")

    def test_a_changed_client_fails(self):
        self.after_section("client")["grant_types"] = ["authorization_code"]
        self.assertFails("client record", "grant_types")

    def test_a_lost_client_fails(self):
        self.after["sections"]["client"] = {"ok": False, "error": "GET client: 404"}
        self.assertFails("client record", "404")

    def test_a_client_secret_that_no_longer_works_fails(self):
        self.after_section("client_token")["with_secret"] = 401
        self.assertFails("client credentials", "401")

    def test_a_client_that_needs_no_secret_any_more_fails(self):
        # A restore that dropped the secret hash would make the client public.
        self.after_section("client_token")["without_secret"] = 200
        self.assertFails("client credentials", "200")

    def test_a_lost_role_fails(self):
        self.after["sections"]["role"] = {"ok": False, "error": "GET role: 404"}
        self.assertFails("role", "404")

    def test_a_changed_role_fails(self):
        self.after_section("role")["permissions"] = []
        self.assertFails("role", "permissions")

    def test_a_lost_assignment_fails(self):
        self.after["sections"]["assignments"] = ok([])
        self.assertFails("role assignments")

    def test_a_lost_webhook_is_advisory_by_default(self):
        self.after["sections"]["webhooks"] = ok([])
        findings = self.findings_of()
        result, _ = results(findings)["webhook subscriptions"]
        self.assertEqual(result, "ADVISORY")
        self.assertEqual(restore_drill.verdict(findings), "PASS")

    def test_a_lost_webhook_fails_when_required(self):
        self.after["sections"]["webhooks"] = ok([])
        self.assertFails("webhook subscriptions", require_webhooks=True)

    def test_a_section_the_restored_server_could_not_answer_fails(self):
        self.after["sections"]["user_count"] = {"ok": False, "error": "GET users: timed out"}
        self.assertFails("user count", "timed out")

    def test_a_missing_section_fails(self):
        del self.after["sections"]["jwks"]
        self.assertFails("realm JWKS", "missing")

    def test_a_broken_baseline_fails(self):
        # The drill cannot vouch for a restore when the original server failed the check.
        self.before["sections"]["client_token"] = ok({"with_secret": 401,
                                                      "without_secret": 401})
        self.assertFails("client credentials", "before")

    def test_a_baseline_token_that_does_not_verify_fails(self):
        self.before["sections"]["jwks"] = ok({"keys": [self.keys.jwk("other", "k1")]})
        self.after["sections"]["jwks"] = ok({"keys": [self.keys.jwk("other", "k1")]})
        self.assertFails("pre-backup token signature", "before")


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.keys = Keys(self.d)
        token = self.keys.token("realm", "k1", {"sub": CLIENT, "iat": T0, "exp": T0 + 3600})
        self.token_file = os.path.join(self.d, "token.json")
        with open(self.token_file, "w") as f:
            json.dump({"access_token": token}, f)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, obj):
        path = os.path.join(self.d, name)
        with open(path, "w") as f:
            json.dump(obj, f)
        return path

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = restore_drill.main(list(argv))
        return code, out.getvalue()

    def test_compare_exits_0_on_a_match_and_1_on_a_difference(self):
        before = self.write("before.json", snapshot(self.keys, "before"))
        after_snap = snapshot(self.keys, "after")
        after = self.write("after.json", after_snap)
        findings = os.path.join(self.d, "findings.json")
        code, out = self.run_main("compare", "--token-file", self.token_file,
                                  "--restore-exit", "0", "--findings", findings, before, after)
        self.assertEqual(code, 0, out)
        self.assertIn("VERDICT: PASS", out)
        with open(findings) as f:
            self.assertEqual({x["check"] for x in json.load(f)}, CHECKS)

        after_snap["sections"]["user_count"] = ok(3)
        after = self.write("after.json", after_snap)
        code, out = self.run_main("compare", "--token-file", self.token_file,
                                  "--restore-exit", "0", "--findings", findings, before, after)
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: FAIL", out)
        self.assertIn("user count", out)

    def test_report_writes_times_and_the_recovery_time(self):
        steps = os.path.join(self.d, "steps.txt")
        with open(steps, "w") as f:
            f.write("seed 95.5\nbackup_create 61.25\nbackup_verify 4\nbackup_sign 3.5\n"
                    "server_stop 2\nrestore 3725\nrestored_start_to_ready 42.5\n")
        facts = os.path.join(self.d, "facts.txt")
        with open(facts, "w") as f:
            f.write("users 1000008\narchive_bytes 314572800\nhearth_version hearth 4.6.6\n"
                    "cpus 4\nmemory_bytes 16777216000\n")
        findings = self.write("findings.json", [
            {"check": "user count", "result": "PASS", "detail": "1000008 before and after"},
            {"check": "sampled users", "result": "FAIL", "detail": "created_at differs"}])
        out_json = os.path.join(self.d, "timings.json")
        out_md = os.path.join(self.d, "summary.md")
        code, _ = self.run_main("report", "--steps", steps, "--facts", facts,
                                "--findings", findings, "--json", out_json,
                                "--markdown", out_md)
        self.assertEqual(code, 0)
        with open(out_json) as f:
            t = json.load(f)
        self.assertEqual(t["status"], "FAIL")
        self.assertEqual(t["users"], 1_000_008)
        self.assertEqual(t["archive_bytes"], 314_572_800)
        self.assertEqual(t["seconds"]["restore"], 3725.0)
        self.assertAlmostEqual(t["recovery_seconds"], 3767.5)
        with open(out_md) as f:
            md = f.read()
        self.assertIn("Restore drill: FAIL", md)
        self.assertIn("1,000,008 users", md)
        self.assertIn("| Restore: `hearth backup restore` | 1 h 02 min |", md)
        self.assertIn("| **Recovery: restore and start** | **1 h 02 min** |", md)
        self.assertIn("300.0 MiB", md)
        self.assertIn("| sampled users | FAIL | created_at differs |", md)

    def test_report_of_a_drill_that_did_not_finish(self):
        steps = os.path.join(self.d, "steps.txt")
        with open(steps, "w") as f:
            f.write("seed 95.5\n")
        out_json = os.path.join(self.d, "timings.json")
        out_md = os.path.join(self.d, "summary.md")
        code, _ = self.run_main("report", "--steps", steps, "--facts", "/nonexistent",
                                "--status", "DID NOT FINISH: the restored server is not ready",
                                "--json", out_json, "--markdown", out_md)
        self.assertEqual(code, 0)
        with open(out_md) as f:
            md = f.read()
        self.assertIn("DID NOT FINISH: the restored server is not ready", md)
        self.assertIn("| Seed: import and known data | 1 min 36 s |", md)
        with open(out_json) as f:
            self.assertIsNone(json.load(f)["recovery_seconds"])


class HelpersTest(unittest.TestCase):
    def test_count_by_probe_finds_the_exact_count_in_few_probes(self):
        for n in (0, 1, 2, 3, 7, 8, 9, 1000, 1_000_008):
            probes = []

            def has_at(offset, n=n, probes=probes):
                probes.append(offset)
                return offset < n

            self.assertEqual(restore_drill.count_by_probe(has_at), n)
            self.assertLessEqual(len(probes), 2 * math.log2(n + 1) + 3, n)

    def test_the_sample_is_deterministic_and_covers_both_ends(self):
        s = restore_drill.sample_indexes(1_000_000, 1000)
        self.assertEqual(s, restore_drill.sample_indexes(1_000_000, 1000))
        self.assertEqual(s[0], 0)
        self.assertEqual(s[-1], 999_999)
        self.assertEqual(len(s), 1001)
        self.assertEqual(restore_drill.sample_indexes(5, 1000), [0, 4])

    def test_bulk_users_are_deterministic_and_varied(self):
        a = restore_drill.bulk_user(12_345, "hearth.stress.test")
        self.assertEqual(a, restore_drill.bulk_user(12_345, "hearth.stress.test"))
        self.assertEqual(a["email"], "bulk0012345@hearth.stress.test")
        statuses = {restore_drill.bulk_user(i, "h.test").get("status", "active")
                    for i in range(1000)}
        self.assertEqual(statuses, {"active", "disabled", "pending_verification"})

    def test_a_signature_needs_the_right_key(self):
        with tempfile.TemporaryDirectory() as d:
            keys = Keys(d)
            token = keys.token("realm", "k1", {"sub": "x"})
            ok_jwks = {"keys": [keys.jwk("realm", "k1")]}
            bad_jwks = {"keys": [keys.jwk("other", "k1")]}
            self.assertEqual(restore_drill.verify_jwt_signature(token, ok_jwks)[0], True)
            good, why = restore_drill.verify_jwt_signature(token, bad_jwks)
            self.assertFalse(good)
            self.assertIn("does not verify", why)
            good, why = restore_drill.verify_jwt_signature("not.a-token", ok_jwks)
            self.assertFalse(good)


if __name__ == "__main__":
    unittest.main()
