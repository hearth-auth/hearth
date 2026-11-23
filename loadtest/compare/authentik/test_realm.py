"""Tests for realm.py: the Authentik realm of the comparison must match the Hearth run's realm.

Usage: python3 -I loadtest/compare/authentik/test_realm.py
"""
import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import realm  # noqa: E402

G = {
    "STRESS_BASE": "https://authentik.stress.test:9443",
    "STRESS_HOST": "authentik.stress.test",
    "STRESS_SERVER_IP": "127.0.0.1",
    "STRESS_REDIRECT_URI": "https://app.stress.test/callback",
    "STRESS_LOGIN_USERS": "3",
    "STRESS_USER_PASSWORD": "user-pw",
    "STRESS_REALM": "stress",
}
FLOWS = {"authorization": "f-authz", "invalidation": "f-inval"}


class RealmTest(unittest.TestCase):
    def test_a_hash_is_djangos_default_pbkdf2_sha256(self):
        h = realm.pbkdf2_hash("pw", "abcdefghijklmnopqrstuv")
        algorithm, iterations, salt, digest = h.split("$")
        self.assertEqual(algorithm, "pbkdf2_sha256")
        # Django 5.2's default, which Authentik keeps.
        self.assertEqual(iterations, "1000000")
        self.assertEqual(salt, "abcdefghijklmnopqrstuv")
        expected = hashlib.pbkdf2_hmac("sha256", b"pw", salt.encode(), 1_000_000)
        self.assertEqual(base64.b64decode(digest), expected)

    def test_a_salt_is_as_long_as_djangos(self):
        # Another salt length would make Django re-hash at the next login.
        s = realm.salt()
        self.assertEqual(len(s), 22)
        self.assertTrue(all(ch in realm.SALT_CHARS for ch in s))
        self.assertNotEqual(realm.salt(), s)

    def test_login_users_are_numbered_and_share_one_hash(self):
        bp = json.loads(realm.login_blueprint(G, "pbkdf2_sha256$1000000$s$d"))
        self.assertEqual(bp["version"], 1)
        emails = [e["identifiers"]["username"] for e in bp["entries"]]
        self.assertEqual(
            emails,
            ["user000001@authentik.stress.test", "user000002@authentik.stress.test", "user000003@authentik.stress.test"],
        )
        first = bp["entries"][0]
        self.assertEqual(first["model"], "authentik_core.user")
        # An existing user makes the file invalid: it is applied in full or not at all.
        self.assertEqual(first["state"], "must_created")
        self.assertEqual(
            first["attrs"],
            {
                "name": "User 1",
                "email": "user000001@authentik.stress.test",
                "is_active": True,
                "password_hash": "pbkdf2_sha256$1000000$s$d",
            },
        )
        # Never a plaintext password.
        self.assertNotIn("password", first["attrs"])
        self.assertNotIn("user-pw", realm.login_blueprint(G, "h"))

    def test_bulk_files_have_the_seed_names_and_no_password(self):
        files = list(realm.bulk_files("h.test", 5, 12, 3))
        self.assertEqual(
            [name for name, _ in files],
            ["bulk-00000005-00000008.yaml", "bulk-00000008-00000011.yaml", "bulk-00000011-00000012.yaml"],
        )
        entries = [e for _, content in files for e in json.loads(content)["entries"]]
        self.assertEqual(
            [e["identifiers"]["username"] for e in entries], [f"bulk{i:08d}@h.test" for i in range(5, 12)]
        )
        self.assertEqual(entries[0]["attrs"], {"name": "Bulk 5", "email": "bulk00000005@h.test", "is_active": True})
        # No password_hash: a hash would queue worker tasks for each user.
        for e in entries:
            self.assertNotIn("password_hash", e["attrs"])
            self.assertNotIn("password", e["attrs"])
            self.assertEqual(e["state"], "must_created")
        # Each file names a distinct blueprint.
        names = {json.loads(content)["metadata"]["name"] for _, content in files}
        self.assertEqual(len(names), 3)

    def test_the_app_provider_is_a_public_code_client_with_rotating_refresh_tokens(self):
        app = realm.provider_rep(
            "app", FLOWS, ["m1"], "key", False, ["authorization_code", "refresh_token"], G["STRESS_REDIRECT_URI"]
        )
        self.assertEqual(app["client_type"], "public")
        self.assertEqual(app["grant_types"], ["authorization_code", "refresh_token"])
        self.assertEqual(
            app["redirect_uris"],
            [{"matching_mode": "strict", "url": "https://app.stress.test/callback", "redirect_uri_type": "authorization"}],
        )
        self.assertEqual(app["authorization_flow"], "f-authz")
        self.assertEqual(app["invalidation_flow"], "f-inval")
        self.assertEqual(app["signing_key"], "key")
        self.assertEqual(app["property_mappings"], ["m1"])
        # The method: access tokens live 1 h; a new refresh token at every refresh.
        self.assertEqual(app["access_token_validity"], "hours=1")
        self.assertEqual(app["refresh_token_threshold"], "seconds=0")

    def test_the_api_provider_is_confidential_for_client_credentials(self):
        api = realm.provider_rep("api", FLOWS, [], "key", True, ["client_credentials"])
        self.assertEqual(api["client_type"], "confidential")
        self.assertEqual(api["grant_types"], ["client_credentials"])
        self.assertEqual(api["redirect_uris"], [])
        self.assertEqual(api["access_token_validity"], "hours=1")
        # Authentik generates the client id and secret.
        self.assertNotIn("client_id", api)
        self.assertNotIn("client_secret", api)

    def test_the_scopes_are_the_vendors_managed_mappings(self):
        self.assertEqual(realm.APP_SCOPES, ["openid", "email", "profile", "offline_access", "authentik_api"])
        self.assertEqual(realm.SCOPE + "offline_access", "goauthentik.io/providers/oauth2/scope-offline_access")
        self.assertEqual(realm.AUTHORIZATION_FLOW, "default-provider-authorization-implicit-consent")

    def test_the_client_credentials_secret_is_base64_of_username_and_app_password(self):
        secret = realm.cc_secret("ak-cc", "tok:en")
        self.assertEqual(base64.b64decode(secret).decode(), "ak-cc:tok:en")

    def test_env_files_are_read_and_updated_privately(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "generator.env")
            with open(p, "w") as f:
                f.write("A=1\nB=2\n# c\nH='pbkdf2_sha256$1$s$d'\n")
            self.assertEqual(realm.read_env(p), {"A": "1", "B": "2", "H": "pbkdf2_sha256$1$s$d"})
            realm.update_env(p, {"B": "3", "C": "4"})
            self.assertEqual(realm.read_env(p)["B"], "3")
            self.assertEqual(realm.read_env(p)["C"], "4")
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_blueprint_files_are_readable_by_the_workers_user(self):
        with tempfile.TemporaryDirectory() as d:
            realm.main_bulk(os.path.join(d, "seed"), "h.test", 0, 5, 2)
            names = sorted(os.listdir(os.path.join(d, "seed")))
            self.assertEqual(len(names), 3)
            for n in names:
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "seed", n)).st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
