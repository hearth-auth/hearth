"""Tests for realm.py: the Keycloak realm of the comparison must match the Hearth run's realm.

Usage: python3 -I loadtest/compare/keycloak/test_realm.py
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import realm  # noqa: E402

G = {
    "STRESS_BASE": "https://keycloak.stress.test:8443",
    "STRESS_HOST": "keycloak.stress.test",
    "STRESS_SERVER_IP": "127.0.0.1",
    "STRESS_REDIRECT_URI": "https://app.stress.test/callback",
    "STRESS_LOGIN_USERS": "250",
    "STRESS_USER_PASSWORD": "user-pw",
    "STRESS_ADMIN_EMAIL": "admin@keycloak.stress.test",
    "STRESS_ADMIN_PASSWORD": "admin-pw",
    "STRESS_REALM": "stress",
    "STRESS_APP_CLIENT_ID": "app",
    "STRESS_API_CLIENT_ID": "api",
    "STRESS_API_SECRET": "api-secret",
}


class RealmTest(unittest.TestCase):
    def setUp(self):
        self.rep = realm.realm_rep(G)
        self.clients = {c["clientId"]: c for c in self.rep["clients"]}

    def test_token_settings_match_the_hearth_run(self):
        self.assertEqual(self.rep["realm"], "stress")
        self.assertTrue(self.rep["enabled"])
        self.assertEqual(self.rep["accessTokenLifespan"], 3600)
        # Hearth rotates refresh tokens and refuses a reused one.
        self.assertIs(self.rep["revokeRefreshToken"], True)
        self.assertEqual(self.rep["refreshTokenMaxReuse"], 0)

    def test_app_is_a_public_client_with_pkce_s256_only(self):
        app = self.clients["app"]
        self.assertIs(app["publicClient"], True)
        self.assertIs(app["standardFlowEnabled"], True)
        self.assertIs(app["directAccessGrantsEnabled"], False)
        self.assertIs(app["implicitFlowEnabled"], False)
        self.assertEqual(app["redirectUris"], ["https://app.stress.test/callback"])
        self.assertEqual(app["attributes"]["pkce.code.challenge.method"], "S256")
        # Only the admin's sign-in asks for the admin API scope.
        self.assertIn("kc-admin-api", app["optionalClientScopes"])
        self.assertNotIn("defaultClientScopes", app)
        # Only the roles the app needs: realm-admin, for the admin's token.
        self.assertIs(app["fullScopeAllowed"], False)
        self.assertEqual(
            self.rep["clientScopeMappings"], {"realm-management": [{"client": "app", "roles": ["realm-admin"]}]}
        )

    def test_user_tokens_carry_the_api_audience_for_introspection(self):
        (mapper,) = self.clients["app"]["protocolMappers"]
        self.assertEqual(mapper["protocolMapper"], "oidc-audience-mapper")
        self.assertEqual(mapper["config"]["included.client.audience"], "api")
        self.assertEqual(mapper["config"]["access.token.claim"], "true")

    def test_api_is_a_confidential_service_account_client(self):
        api = self.clients["api"]
        self.assertIs(api["publicClient"], False)
        self.assertEqual(api["clientAuthenticatorType"], "client-secret")
        self.assertEqual(api["secret"], "api-secret")
        self.assertIs(api["serviceAccountsEnabled"], True)
        self.assertIs(api["standardFlowEnabled"], False)
        self.assertIs(api["directAccessGrantsEnabled"], False)
        self.assertIs(api["fullScopeAllowed"], False)

    def test_the_only_user_in_the_realm_is_its_admin(self):
        (admin,) = self.rep["users"]
        self.assertEqual(admin["username"], "admin@keycloak.stress.test")
        self.assertEqual(admin["email"], "admin@keycloak.stress.test")
        self.assertEqual(admin["clientRoles"], {"realm-management": ["realm-admin"]})
        self.assertEqual(admin["credentials"], [{"type": "password", "value": "admin-pw", "temporary": False}])
        self.assertIs(admin["emailVerified"], True)

    def test_login_users_are_named_as_lib_js_names_them_and_batched(self):
        batches = list(realm.login_batches(G))
        self.assertEqual([len(b["users"]) for b in batches], [100, 100, 50])
        users = [u for b in batches for u in b["users"]]
        self.assertEqual(users[0]["username"], "user000001@keycloak.stress.test")
        self.assertEqual(users[-1]["email"], "user000250@keycloak.stress.test")
        self.assertEqual(len({u["username"] for u in users}), 250)
        for u in users:
            self.assertEqual(u["credentials"], [{"type": "password", "value": "user-pw", "temporary": False}])
            # Keycloak's default user profile asks for both names; without them
            # the login page asks the user to update the profile.
            self.assertTrue(u["firstName"] and u["lastName"])
            self.assertIs(u["enabled"], True)
            self.assertIs(u["emailVerified"], True)
        # A duplicate fails the batch instead of passing unnoticed.
        self.assertTrue(all(b["ifResourceExists"] == "FAIL" for b in batches))

    def test_read_env_skips_comments_and_keeps_equals_in_values(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write("# comment\nA=1\n\nB=x=y\n")
        try:
            self.assertEqual(realm.read_env(f.name), {"A": "1", "B": "x=y"})
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
