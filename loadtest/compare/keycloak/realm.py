"""The `stress` realm of the Keycloak comparison run (#913), through Keycloak's admin REST API.

Usage: realm.py <bundle>

Signs in as the bootstrap admin of the master realm, creates the realm (clients and the realm
admin) and then adds the login users with their password through partialImport, 100 per request.
Keycloak hashes each password with its configured Argon2id settings. The 1M password-less users
come later, from the seed (k6/prepare.js through the Keycloak adapter).

The realm mirrors the Hearth realm of gen-config.sh:
  app    public client: authorization code + PKCE (S256 required), refresh tokens
  api    confidential client: client credentials (service account), introspection
  admin  the realm admin (realm-management realm-admin), as Hearth's realm.admin seed user
  users  user000001@<host> ... with one password, as gen-config.sh's seed_users

Settings that differ from Keycloak's defaults, each to match the Hearth run:
  accessTokenLifespan 3600   gen-config.sh's token.access_token_ttl (1 h)
  revokeRefreshToken true    Hearth rotates refresh tokens and refuses a reused one
  refreshTokenMaxReuse 0     (the same)
and what Keycloak needs for the journeys: an audience mapper that puts `api` in the users' tokens
(introspection), the optional kc-admin-api scope on `app` and the realm-admin role in its scope
(the admin REST API). Full scope is off on both clients, as Keycloak advises.

The bundle (keycloak.sh up) gives server.env (bootstrap admin) and generator.env (the rest). No
password or secret is printed.
"""
import http.client
import json
import socket
import ssl
import sys
import urllib.parse

LOGIN_BATCH = 100
# The optional client scopes Keycloak 26.8 gives a new client.
OPTIONAL_SCOPES = ["address", "phone", "offline_access", "organization", "microprofile-jwt"]
# The built-in scope that the admin REST API requires (server_admin guide, "Accessing the Admin
# REST API with your own clients").
ADMIN_API_SCOPE = "kc-admin-api"


def api_audience(api_client_id):
    """The api client in the user tokens' audience, so that it may introspect them.

    Keycloak refuses to introspect a token for a client outside its `aud` ("Client 'api' is not in
    the token audience"); the server_admin guide's "Audience support" adds it with this mapper.
    """
    return {
        "name": "api audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.client.audience": api_client_id,
            "access.token.claim": "true",
            "id.token.claim": "false",
            "introspection.token.claim": "true",
        },
    }


def read_env(path):
    """KEY=value lines of an env file, as a dict."""
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def user_email(i, host):
    """Login user i (1-based), as lib.js userEmail() names them."""
    return f"user{i:06d}@{host}"


def user_rep(email, first, last, password=None):
    """A user for the admin API; the email is also the username."""
    rep = {
        "username": email,
        "email": email,
        "firstName": first,
        "lastName": last,
        "enabled": True,
        "emailVerified": True,
    }
    if password is not None:
        rep["credentials"] = [{"type": "password", "value": password, "temporary": False}]
    return rep


def realm_rep(g):
    """The realm without its login users, from generator.env values `g`."""
    admin = user_rep(g["STRESS_ADMIN_EMAIL"], "Realm", "Admin", g["STRESS_ADMIN_PASSWORD"])
    admin["clientRoles"] = {"realm-management": ["realm-admin"]}
    return {
        "realm": g["STRESS_REALM"],
        "enabled": True,
        "accessTokenLifespan": 3600,
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
        "clients": [
            {
                "clientId": g["STRESS_APP_CLIENT_ID"],
                "publicClient": True,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False,
                "implicitFlowEnabled": False,
                # Keycloak logs a deprecation warning at every token request of a client with
                # full scope; its advice is to map the roles the client needs (below).
                "fullScopeAllowed": False,
                "redirectUris": [g["STRESS_REDIRECT_URI"]],
                "attributes": {"pkce.code.challenge.method": "S256"},
                # Keycloak's defaults plus kc-admin-api, which the admin's sign-in asks for.
                "optionalClientScopes": OPTIONAL_SCOPES + [ADMIN_API_SCOPE],
                "protocolMappers": [api_audience(g["STRESS_API_CLIENT_ID"])],
            },
            {
                "clientId": g["STRESS_API_CLIENT_ID"],
                "publicClient": False,
                "clientAuthenticatorType": "client-secret",
                "secret": g["STRESS_API_SECRET"],
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": True,
                # As for app: no per-request warning; the service account needs no roles.
                "fullScopeAllowed": False,
            },
        ],
        "users": [admin],
        # The admin's realm-management roles in the app's tokens, for the admin REST API.
        "clientScopeMappings": {
            "realm-management": [{"client": g["STRESS_APP_CLIENT_ID"], "roles": ["realm-admin"]}]
        },
    }


def login_batches(g, batch=LOGIN_BATCH):
    """partialImport bodies for the login users, `batch` users each."""
    n, host, pw = int(g["STRESS_LOGIN_USERS"]), g["STRESS_HOST"], g["STRESS_USER_PASSWORD"]
    for lo in range(1, n + 1, batch):
        users = [user_rep(user_email(i, host), "User", str(i), pw) for i in range(lo, min(lo + batch, n + 1))]
        yield {"ifResourceExists": "FAIL", "users": users}


class Server:
    """HTTPS to the server by its name, at the address the generator uses."""

    def __init__(self, g, cafile):
        url = urllib.parse.urlsplit(g["STRESS_BASE"])
        self.host, self.port = url.hostname, url.port or 443
        self.ip = g["STRESS_SERVER_IP"]
        self.ctx = ssl.create_default_context(cafile=cafile)

    def request(self, method, path, body=None, headers=None, timeout=300):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout)
        conn.sock = self.ctx.wrap_socket(
            socket.create_connection((self.ip, self.port), timeout), server_hostname=self.host
        )
        try:
            conn.request(method, path, body=body, headers=headers or {})
            res = conn.getresponse()
            return res.status, res.read()
        finally:
            conn.close()


def admin_auth(s, k):
    """Headers for the admin API as the master realm's bootstrap admin.

    The master realm's tokens live 60 s, so each request gets a new one.
    """
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": k["KC_BOOTSTRAP_ADMIN_USERNAME"],
            "password": k["KC_BOOTSTRAP_ADMIN_PASSWORD"],
        }
    )
    status, body = s.request(
        "POST",
        "/realms/master/protocol/openid-connect/token",
        form,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        sys.exit(f"realm: master admin sign-in answered {status}")
    return {"Authorization": f"Bearer {json.loads(body)['access_token']}", "Content-Type": "application/json"}


def main(bundle):
    g = read_env(f"{bundle}/generator.env")
    k = read_env(f"{bundle}/server.env")
    s = Server(g, f"{bundle}/ca.crt")
    status, _ = s.request("POST", "/admin/realms", json.dumps(realm_rep(g)), admin_auth(s, k))
    if status != 201:
        sys.exit(f"realm: creating realm {g['STRESS_REALM']} answered {status}")
    added = 0
    for b in login_batches(g):
        path = f"/admin/realms/{g['STRESS_REALM']}/partialImport"
        status, body = s.request("POST", path, json.dumps(b), admin_auth(s, k))
        if status != 200:
            sys.exit(f"realm: importing login users answered {status}")
        added += json.loads(body)["added"]
    print(f"realm {g['STRESS_REALM']}: created, {added} login users added")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__))
