"""The stress realm of the Authentik comparison run (#913), through Authentik's API and blueprints.

Usage: realm.py <bundle>
       realm.py hash                  (reads a password on stdin, prints its hash; authentik.sh
                                       uses it for akadmin's AUTHENTIK_BOOTSTRAP_PASSWORD_HASH)
       realm.py bulk <dir> <host> <from> <to> <batch>
                                      (writes the seed's blueprints: bulk<from> .. bulk<to - 1>,
                                       <batch> users per file)

The API calls use the bootstrap token (AUTHENTIK_BOOTSTRAP_TOKEN, the automated install's API
token of akadmin). The realm mirrors the Hearth realm of gen-config.sh:
  app    OAuth2/OpenID provider and application, a public client (no secret): authorization code
         with PKCE and refresh tokens (the offline_access scope mapping: Authentik issues a refresh
         token only for it). Its authorization flow is the vendor's implicit-consent flow, the
         documented flow for first-party applications (no consent page). Refresh tokens rotate at
         every use (refresh_token_threshold seconds=0, the default) and a used one is refused.
         It also has the `goauthentik.io/api` scope mapping: the realm admin signs in through the
         login page with that scope, and the access token is then an API token (Authentik's API
         authentication guide), as Keycloak's admin signs in with its kc-admin-api scope
  api    confidential OAuth2/OpenID provider and application: the introspect journey
         authenticates as it (Authentik introspects only for a confidential provider), so the app
         provider names it as a federated provider (the documented cross-provider introspection).
         The client credentials journey uses it too, see `cc`
  cc     a service account with an app password token (POST /core/users/service_account/): the
         client credentials grant of `api`, Authentik's documented machine-to-machine way
         (machine clients authenticate with a username and an app password token, not with the
         provider's secret). STRESS_CC_CLIENT_ID is the api provider's client id and
         STRESS_CC_SECRET is base64(username:token), the documented client_secret form, so the
         journey sends client_secret_basic as for the other products
  admin  akadmin (bootstrap), email admin@<host>: signs in through the login page like the users
  users  user000001@<host> ... with one password, as gen-config.sh's seed_users: a blueprint
         (<bundle>/blueprints/logins.yaml, applied by authentik.sh) with a hash of the password in
         Authentik's default format, so no password is sent to Authentik and the import hashes
         nothing. Each login checks the hash in full (1,000,000 iterations), as for any user

Every access token is a JWT signed with the vendor's "authentik Self-signed Certificate" (RS256),
the key the vendor's own OpenID conformance blueprint uses; without a signing key Authentik would
sign with HS256 and the client secret. Access tokens live 1 h.

The seed's users (bulk_files) get no password_hash: a blueprint user without a password gets
Django's unusable password, as a user made through the users API without one. Setting a hash
would send a password_set audit event per user, and each event queues worker tasks (the
notification rules), background work per user that the seed must not cause.

The generated client ids, the api secret and the cc credentials go to generator.env. No password,
token or secret is printed.
"""
import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import string
import sys
import time
import urllib.parse

# Django's PBKDF2PasswordHasher, the first entry of Django's default PASSWORD_HASHERS, which
# Authentik keeps: PBKDF2-SHA256 with 1,000,000 iterations (Django 5.2) and a 22-character salt
# (128 bits from letters and digits, Django's salt_entropy). A hash with other parameters is
# re-hashed by Django at the next successful login, a write the run must not cause.
PBKDF2_ITERATIONS = 1_000_000
SALT_CHARS = string.ascii_letters + string.digits
SALT_LEN = 22
SIGNING_KEY = "authentik Self-signed Certificate"
AUTHORIZATION_FLOW = "default-provider-authorization-implicit-consent"
INVALIDATION_FLOW = "default-provider-invalidation-flow"
SCOPE = "goauthentik.io/providers/oauth2/scope-"
APP_SCOPES = ["openid", "email", "profile", "offline_access", "authentik_api"]
API_SCOPES = ["openid", "profile"]


def read_env(path):
    """KEY=value lines of an env file, as a dict (single quotes around a value are dropped)."""
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if len(v) >= 2 and v[0] == v[-1] == "'":
                    v = v[1:-1]
                out[k] = v
    return out


def update_env(path, values):
    """Sets KEY=value lines in an env file (replacing a key that is there), mode 0600."""
    lines = []
    if os.path.exists(path):
        with open(path) as f:
            lines = [ln.rstrip("\n") for ln in f]
    keep = [ln for ln in lines if ln.split("=", 1)[0] not in values]
    keep += [f"{k}={v}" for k, v in values.items()]
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(keep) + "\n")
    os.replace(path + ".tmp", path)


def salt(choice=secrets.choice):
    """A salt as Django makes one (get_random_string(22))."""
    return "".join(choice(SALT_CHARS) for _ in range(SALT_LEN))


def pbkdf2_hash(password, salt_value, iterations=PBKDF2_ITERATIONS):
    """`password`'s hash in Django's pbkdf2_sha256 format: algorithm$iterations$salt$digest."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_value.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt_value}${base64.b64encode(dk).decode()}"


def user_email(i, host):
    """Login user i (1-based), as lib.js userEmail() names them."""
    return f"user{i:06d}@{host}"


def blueprint_user(email, name, password_hash=None):
    """A blueprint entry that creates the user `email` (also its username).

    `must_created`: an existing user makes the blueprint invalid, so a file is applied in full or
    not at all. `password_hash` is a blueprint-only field (the users API refuses it); without one
    the user gets Django's unusable password.
    """
    attrs = {"name": name, "email": email, "is_active": True}
    if password_hash is not None:
        attrs["password_hash"] = password_hash
    return {
        "model": "authentik_core.user",
        "state": "must_created",
        "identifiers": {"username": email},
        "attrs": attrs,
    }


def blueprint(name, entries):
    """A blueprint (YAML, written as JSON, which YAML reads) with `entries`."""
    return json.dumps({"version": 1, "metadata": {"name": name}, "entries": entries})


def login_blueprint(g, password_hash):
    """The blueprint of the login users: all of them, with the hash of their password."""
    n, host = int(g["STRESS_LOGIN_USERS"]), g["STRESS_HOST"]
    users = [blueprint_user(user_email(i, host), f"User {i}", password_hash) for i in range(1, n + 1)]
    return blueprint("compare - login users", users)


def bulk_files(host, lo, hi, batch):
    """(file name, blueprint) of the seed's users bulk<lo> .. bulk<hi - 1>, `batch` per file.

    The names are those of prepare.js (bulk%08d@<host>, "Bulk <i>"); no password (see the module
    docstring). Each file is one transaction when applied.
    """
    for start in range(lo, hi, batch):
        end = min(start + batch, hi)
        users = [blueprint_user(f"bulk{i:08d}@{host}", f"Bulk {i}") for i in range(start, end)]
        yield f"bulk-{start:08d}-{end:08d}.yaml", blueprint(f"compare - bulk {start}-{end}", users)


def write_file(path, content):
    """Writes `content` to `path` (mode 0644: the worker's image user reads it), atomically."""
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.replace(path + ".tmp", path)


def provider_rep(name, flows, scopes, signing_key, confidential, grant_types, redirect_uri=None):
    """An OAuth2/OpenID provider: access tokens 1 h, refresh tokens rotated at every use."""
    rep = {
        "name": name,
        "authorization_flow": flows["authorization"],
        "invalidation_flow": flows["invalidation"],
        "client_type": "confidential" if confidential else "public",
        "grant_types": grant_types,
        "property_mappings": scopes,
        "signing_key": signing_key,
        "access_token_validity": "hours=1",
        # seconds=0, the default: a new refresh token at every refresh, the used one revoked.
        "refresh_token_threshold": "seconds=0",
        "redirect_uris": [],
    }
    if redirect_uri:
        rep["redirect_uris"] = [{"matching_mode": "strict", "url": redirect_uri, "redirect_uri_type": "authorization"}]
    return rep


def cc_secret(username, token):
    """The client_secret of Authentik's client credentials grant: base64(username:app password)."""
    return base64.b64encode(f"{username}:{token}".encode()).decode()


class Server:
    """HTTPS to Authentik's API by its name, at the address the generator uses, as akadmin."""

    def __init__(self, g, cafile, token):
        u = urllib.parse.urlsplit(g["STRESS_BASE"])
        self.host, self.port, self.ip = u.hostname, u.port, g["STRESS_SERVER_IP"]
        self.token = token
        ctx = ssl.create_default_context(cafile=cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx = ctx

    def call(self, method, path, body=None, want=200, timeout=60):
        """The JSON answer of an API call; exits (without the body) on another status."""
        status, data = self._send(method, path, body, timeout)
        if status != want:
            sys.exit(f"realm: {method} {path} answered {status}")
        return json.loads(data or b"{}")

    def one(self, path):
        """The only result of a list call."""
        results = self.call("GET", path)["results"]
        if len(results) != 1:
            sys.exit(f"realm: GET {path} found {len(results)} objects, not 1")
        return results[0]

    def _send(self, method, path, body, timeout):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout)
        conn.sock = self.ctx.wrap_socket(
            socket.create_connection((self.ip, self.port), timeout), server_hostname=self.host
        )
        if body is not None:
            body = json.dumps(body)
        try:
            conn.request(
                method,
                path,
                body=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            res = conn.getresponse()
            return res.status, res.read()
        finally:
            conn.close()


def main(bundle):
    g = read_env(f"{bundle}/generator.env")
    s = read_env(f"{bundle}/server.env")
    ak = Server(g, f"{bundle}/ca.crt", s["BOOTSTRAP_TOKEN"])

    # The bootstrap token is read by the worker on its first start; wait for it.
    for _ in range(120):
        status, _ = ak._send("GET", "/api/v3/core/users/me/", None, 30)
        if status == 200:
            break
        time.sleep(1)
    else:
        sys.exit("realm: the bootstrap token does not work after 120 s")

    flows = {
        "authorization": ak.one(f"/api/v3/flows/instances/?slug={AUTHORIZATION_FLOW}")["pk"],
        "invalidation": ak.one(f"/api/v3/flows/instances/?slug={INVALIDATION_FLOW}")["pk"],
    }
    key = ak.one(f"/api/v3/crypto/certificatekeypairs/?name={urllib.parse.quote(SIGNING_KEY)}")["pk"]

    def scopes(names):
        return [ak.one(f"/api/v3/propertymappings/provider/scope/?managed={SCOPE}{n}")["pk"] for n in names]

    api = ak.call(
        "POST",
        "/api/v3/providers/oauth2/",
        provider_rep("api", flows, scopes(API_SCOPES), key, True, ["client_credentials"]),
        want=201,
    )
    app_rep = provider_rep(
        "app", flows, scopes(APP_SCOPES), key, False, ["authorization_code", "refresh_token"], g["STRESS_REDIRECT_URI"]
    )
    # The api provider may introspect the app provider's tokens.
    app_rep["jwt_federation_providers"] = [api["pk"]]
    app = ak.call("POST", "/api/v3/providers/oauth2/", app_rep, want=201)
    for p in (app, api):
        ak.call("POST", "/api/v3/core/applications/", {"name": p["name"], "slug": p["name"], "provider": p["pk"]}, want=201)
    cc = ak.call("POST", "/api/v3/core/users/service_account/", {"name": "cc", "create_group": False, "expiring": False})

    update_env(
        f"{bundle}/generator.env",
        {
            "STRESS_APP_CLIENT_ID": app["client_id"],
            "STRESS_API_CLIENT_ID": api["client_id"],
            "STRESS_API_SECRET": api["client_secret"],
            "STRESS_CC_CLIENT_ID": api["client_id"],
            "STRESS_CC_SECRET": cc_secret(cc["username"], cc["token"]),
        },
    )

    os.makedirs(f"{bundle}/blueprints", exist_ok=True)
    os.chmod(f"{bundle}/blueprints", 0o755)
    login_hash = pbkdf2_hash(g["STRESS_USER_PASSWORD"], salt())
    write_file(f"{bundle}/blueprints/logins.yaml", login_blueprint(g, login_hash))
    print(f"realm {g['STRESS_REALM']}: providers, applications and the service account created")


def main_bulk(out, host, lo, hi, batch):
    os.makedirs(out, exist_ok=True)
    os.chmod(out, 0o755)
    for name, content in bulk_files(host, lo, hi, batch):
        write_file(os.path.join(out, name), content)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "hash":
        print(pbkdf2_hash(sys.stdin.read(), salt()))
    elif len(sys.argv) == 7 and sys.argv[1] == "bulk":
        main_bulk(sys.argv[2], sys.argv[3], *(int(x) for x in sys.argv[4:7]))
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        sys.exit(__doc__)
