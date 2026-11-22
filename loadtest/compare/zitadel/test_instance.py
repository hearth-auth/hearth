"""Tests for instance.py: the Zitadel realm of the comparison must match the Hearth run's realm.

Usage: python3 -I loadtest/compare/zitadel/test_instance.py
"""
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import instance  # noqa: E402

G = {
    "STRESS_BASE": "https://zitadel.stress.test:8443",
    "STRESS_HOST": "zitadel.stress.test",
    "STRESS_SERVER_IP": "127.0.0.1",
    "STRESS_REDIRECT_URI": "https://app.stress.test/callback",
    "STRESS_LOGIN_USERS": "250",
    "STRESS_USER_PASSWORD": "user-pw",
    "STRESS_REALM": "stress",
}


class InstanceTest(unittest.TestCase):
    def test_app_is_a_public_code_client_with_refresh_tokens_and_jwt_access_tokens(self):
        app = instance.app_rep(G)
        self.assertEqual(app["redirectUris"], ["https://app.stress.test/callback"])
        self.assertEqual(app["responseTypes"], ["OIDC_RESPONSE_TYPE_CODE"])
        self.assertEqual(
            app["grantTypes"], ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"]
        )
        # No secret: Zitadel requires PKCE for it.
        self.assertEqual(app["authMethodType"], "OIDC_AUTH_METHOD_TYPE_NONE")
        # The harness reads iat and exp from the access token.
        self.assertEqual(app["accessTokenType"], "OIDC_TOKEN_TYPE_JWT")
        # devMode would allow non-https redirect URIs.
        self.assertIs(app["devMode"], False)

    def test_api_introspects_with_basic_auth_and_cc_is_a_service_account_with_jwts(self):
        self.assertEqual(instance.api_rep(), {"name": "api", "authMethodType": "API_AUTH_METHOD_TYPE_BASIC"})
        cc = instance.cc_rep()
        self.assertEqual(cc["userName"], "cc")
        self.assertEqual(cc["accessTokenType"], "ACCESS_TOKEN_TYPE_JWT")

    def test_login_users_are_named_as_lib_js_names_them_and_carry_the_password(self):
        batches = list(instance.login_batches(G, batch=100))
        self.assertEqual([len(b) for b in batches], [100, 100, 50])
        users = [h["user"] for b in batches for h in b]
        self.assertEqual(users[0]["userName"], "user000001@zitadel.stress.test")
        self.assertEqual(users[-1]["userName"], "user000250@zitadel.stress.test")
        self.assertEqual(len({u["userName"] for u in users}), 250)
        for u in users:
            self.assertEqual(u["password"], "user-pw")
            self.assertEqual(u["email"], {"email": u["userName"], "isEmailVerified": True})
            # The login page goes straight from the password to the application.
            self.assertIs(u["passwordChangeRequired"], False)
            # Zitadel picks the id.
            self.assertNotIn("userId", u)

    def test_a_human_without_a_password_has_no_password_field(self):
        self.assertNotIn("password", instance.human("e@x", "Bulk", "7")["user"])

    def test_import_body_adds_to_the_existing_organization_with_a_timeout(self):
        body = instance.import_body("4006", "stress", [instance.human("e@x", "B", "1")])
        (org,) = body["dataOrgs"]["orgs"]
        self.assertEqual(org["orgId"], "4006")
        self.assertEqual(org["org"], {"name": "stress"})
        self.assertEqual(len(org["humanUsers"]), 1)
        # ImportData refuses a request without one.
        self.assertEqual(body["timeout"], "5m")

    def test_import_result_counts_users_and_ignores_the_existing_organization(self):
        body = {
            "errors": [
                {"type": "org", "id": "4006", "message": "Errors.Org.AlreadyExists"},
                {"type": "human_user", "id": "", "message": "Errors.User.AlreadyExists"},
            ],
            "success": {"orgs": [{"orgId": "4006", "humanUserIds": ["41", "42"]}]},
        }
        self.assertEqual(instance.import_result(body), (2, 1))
        self.assertEqual(instance.import_result({"success": {"orgs": [{"orgId": "4006"}]}}), (0, 0))
        self.assertEqual(instance.import_result({}), (0, 0))

    def test_update_env_replaces_keys_keeps_others_and_writes_mode_0600(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "generator.env")
            with open(path, "w") as f:
                f.write("PRODUCT=zitadel\nSTRESS_API_SECRET=old\n")
            # Wider than 0600, so the test sees update_env tighten it.
            os.chmod(path, 0o640)
            instance.update_env(path, {"STRESS_API_SECRET": "new", "STRESS_CC_SECRET": "cc"})
            self.assertEqual(
                instance.read_env(path),
                {"PRODUCT": "zitadel", "STRESS_API_SECRET": "new", "STRESS_CC_SECRET": "cc"},
            )
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
