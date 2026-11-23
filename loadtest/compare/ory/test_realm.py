"""Tests for realm.py: the Ory realm of the comparison must match the Hearth run's realm.

Usage: python3 -I loadtest/compare/ory/test_realm.py
"""
import base64
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import realm  # noqa: E402

G = {
    "STRESS_BASE": "https://ory.stress.test:4444",
    "STRESS_HOST": "ory.stress.test",
    "STRESS_SERVER_IP": "127.0.0.1",
    "STRESS_REDIRECT_URI": "https://app.stress.test/callback",
    "STRESS_LOGIN_USERS": "250",
    "STRESS_USER_PASSWORD": "user-pw",
    "STRESS_REALM": "stress",
}


def b64decode(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


class RealmTest(unittest.TestCase):
    def test_app_is_a_public_code_client_with_refresh_tokens_and_no_consent_page(self):
        app = realm.app_rep(G)
        self.assertEqual(app["redirect_uris"], ["https://app.stress.test/callback"])
        self.assertEqual(app["grant_types"], ["authorization_code", "refresh_token"])
        self.assertEqual(app["response_types"], ["code"])
        # No secret: the login uses PKCE.
        self.assertEqual(app["token_endpoint_auth_method"], "none")
        # Hydra issues a refresh token only for offline_access.
        self.assertEqual(app["scope"].split(), ["openid", "offline_access"])
        self.assertIs(app["skip_consent"], True)

    def test_api_is_a_confidential_client_credentials_client(self):
        api = realm.api_rep()
        self.assertEqual(api["grant_types"], ["client_credentials"])
        self.assertEqual(api["response_types"], [])
        self.assertEqual(api["token_endpoint_auth_method"], "client_secret_basic")
        # Hydra generates the secret.
        self.assertNotIn("client_secret", api)

    def test_an_identity_has_a_verified_email_and_at_most_one_kind_of_password(self):
        bare = realm.identity("e@x", "A", "B")
        self.assertEqual(bare["schema_id"], "default")
        self.assertEqual(bare["traits"], {"email": "e@x", "name": {"first": "A", "last": "B"}})
        self.assertEqual(bare["state"], "active")
        # Verified: no verification message is ever due.
        self.assertEqual(
            bare["verifiable_addresses"],
            [{"value": "e@x", "via": "email", "verified": True, "status": "completed"}],
        )
        self.assertNotIn("credentials", bare)
        pw = realm.identity("e@x", "A", "B", password="pw")
        self.assertEqual(pw["credentials"], {"password": {"config": {"password": "pw"}}})
        hashed = realm.identity("e@x", "A", "B", hashed_password="$argon2id$h")
        self.assertEqual(hashed["credentials"], {"password": {"config": {"hashed_password": "$argon2id$h"}}})

    def test_the_unusable_hash_has_the_runs_argon2id_parameters_and_random_salt_and_digest(self):
        h = realm.unusable_hash()
        parts = h.split("$")
        self.assertEqual(parts[:4], ["", "argon2id", "v=19", "m=19456,t=2,p=1"])
        self.assertEqual(len(parts), 6)
        # Unpadded standard base64, as Kratos encodes them.
        self.assertNotIn("=", parts[4] + parts[5])
        self.assertEqual(len(b64decode(parts[4])), 16)
        self.assertEqual(len(b64decode(parts[5])), 32)
        self.assertNotEqual(realm.unusable_hash(), h)
        fixed = realm.unusable_hash(rand=lambda n: b"\0" * n)
        self.assertEqual(fixed, "$argon2id$v=19$m=19456,t=2,p=1$" + "A" * 22 + "$" + "A" * 43)

    def test_login_users_come_in_batches_with_the_password(self):
        batches = list(realm.login_batches(G, batch=100))
        self.assertEqual([len(b) for b in batches], [100, 100, 50])
        first, last = batches[0][0], batches[-1][-1]
        self.assertEqual(first["traits"]["email"], "user000001@ory.stress.test")
        self.assertEqual(last["traits"]["email"], "user000250@ory.stress.test")
        self.assertEqual(first["credentials"], {"password": {"config": {"password": "user-pw"}}})
        # Kratos takes at most 200 identities with a plaintext password per request.
        self.assertLessEqual(realm.LOGIN_BATCH, 200)

    def test_batch_body_and_result(self):
        self.assertEqual(realm.batch_body([{"a": 1}]), {"identities": [{"create": {"a": 1}}]})
        answer = {
            "identities": [
                {"action": "create", "identity": "u1"},
                {"action": "error", "error": {"code": 409}},
            ]
        }
        self.assertEqual(realm.batch_result(answer), (1, 1))
        self.assertEqual(realm.batch_result({}), (0, 0))

    def test_update_env_replaces_keys_and_keeps_the_file_private(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "generator.env")
            with open(p, "w") as f:
                f.write("A=1\nB=2\n")
            realm.update_env(p, {"B": "3", "C": "4"})
            self.assertEqual(realm.read_env(p), {"A": "1", "B": "3", "C": "4"})
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
