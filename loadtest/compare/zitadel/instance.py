"""The stress realm of the Zitadel comparison run (#913), through Zitadel's own APIs.

Usage: instance.py <bundle>

Zitadel's `setup` already made the realm: the first instance, its organization (ZT_ORG), the realm
admin (the first human, IAM_OWNER) and a service account whose PAT it wrote to <bundle>/setup.pat.
With that PAT this script creates the clients and then imports the login users with their password
through the bulk path (POST /admin/v1/import), 100 per request. Zitadel hashes each password with
its configured Argon2id settings. The 1M password-less users come later, from the seed (k6/prepare.js
through the Zitadel adapter).

The realm mirrors the Hearth realm of gen-config.sh:
  app    public client (user agent, no secret): authorization code + PKCE, refresh tokens
  api    API application with a generated secret (basic auth): introspection
  cc     service account with a generated secret: the client credentials journey (in Zitadel an
         API application is a resource server only and cannot take that grant)
  users  user000001@<host> ... with one password, as gen-config.sh's seed_users

Settings that differ from Zitadel's defaults (the instance-wide ones are in compose.yaml):
  accessTokenType JWT        on app and cc: the harness reads iat and exp from the access token,
                             as Hearth's and Keycloak's tokens carry them (Zitadel's default is an
                             opaque token)

Zitadel's own choices that stay: refresh tokens rotate (each refresh answers a new one and the old
one is refused), client secrets are stored with the SecretHasher default (bcrypt, cost 4).

The generated client ids and secrets go to generator.env, with the hash that the seed gives the
bulk users (unusable_hash). No password or secret is printed.
"""
import base64
import http.client
import json
import os
import secrets
import socket
import ssl
import sys
import time
import urllib.parse

LOGIN_BATCH = 100
# The run's Argon2id parameters (compose.yaml), as Zitadel encodes them.
ARGON2ID_PARAMS = "$argon2id$v=19$m=19456,t=2,p=1"
# The machine user of the client credentials journey.
CC_USERNAME = "cc"
# ImportData requires a timeout; a batch of 100 password users takes seconds.
IMPORT_TIMEOUT = "5m"


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


def user_email(i, host):
    """Login user i (1-based), as lib.js userEmail() names them."""
    return f"user{i:06d}@{host}"


def human(email, first, last, password=None):
    """A human user of the import (DataHumanUser); the email is also the username.

    The email is verified and no password change is asked for, so the login page goes straight
    from the password to the application. Zitadel picks the user id.
    """
    user = {
        "userName": email,
        "profile": {"firstName": first, "lastName": last},
        "email": {"email": email, "isEmailVerified": True},
        "passwordChangeRequired": False,
    }
    if password is not None:
        user["password"] = password
    return {"user": user}


def unusable_hash(rand=secrets.token_bytes):
    """A well-formed Argon2id hash with the run's parameters and random salt and digest.

    The bulk users get it as their `hashedPassword` (the import's documented field for hashes
    from another system). No password matches it, so they have no usable password, as Hearth's
    bulk users. Without any password Zitadel would put each user in its initial state: an
    initialization code and an email per user, work that a real deployment's users do not cause
    and Hearth's seed does not do. Zitadel only parses an imported hash (it hashes nothing), and
    Argon2id is its configured hasher, so its verifier is on.
    """
    def b64(b):
        return base64.b64encode(b).decode().rstrip("=")

    return f"{ARGON2ID_PARAMS}${b64(rand(16))}${b64(rand(32))}"


def import_body(org_id, org_name, humans):
    """A POST /admin/v1/import body that adds `humans` to the existing organization.

    The import first tries to create the organization; for an existing one that fails (reported
    in `errors` with type "org") and the users are added to it.
    """
    return {
        "dataOrgs": {"orgs": [{"orgId": org_id, "org": {"name": org_name}, "humanUsers": humans}]},
        "timeout": IMPORT_TIMEOUT,
    }


def import_result(body):
    """(imported, failed) of an import response: users added, and users that failed."""
    orgs = (body.get("success") or {}).get("orgs") or []
    imported = sum(len(o.get("humanUserIds") or []) for o in orgs)
    failed = sum(1 for e in body.get("errors") or [] if e.get("type") == "human_user")
    return imported, failed


def app_rep(g):
    """The public `app` client: authorization code with PKCE and refresh tokens."""
    return {
        "name": "app",
        "redirectUris": [g["STRESS_REDIRECT_URI"]],
        "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
        "grantTypes": ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"],
        # A browser application without a secret; Zitadel requires PKCE for it.
        "appType": "OIDC_APP_TYPE_USER_AGENT",
        "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
        "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
        "devMode": False,
    }


def api_rep():
    """The `api` resource server: introspects the users' tokens with basic auth."""
    return {"name": "api", "authMethodType": "API_AUTH_METHOD_TYPE_BASIC"}


def cc_rep():
    """The service account of the client credentials journey."""
    return {"userName": CC_USERNAME, "name": "client credentials", "accessTokenType": "ACCESS_TOKEN_TYPE_JWT"}


def login_batches(g, batch=LOGIN_BATCH):
    """Lists of `human` entries for the login users, `batch` users each."""
    n, host, pw = int(g["STRESS_LOGIN_USERS"]), g["STRESS_HOST"], g["STRESS_USER_PASSWORD"]
    for lo in range(1, n + 1, batch):
        yield [human(user_email(i, host), "User", str(i), pw) for i in range(lo, min(lo + batch, n + 1))]


class Server:
    """HTTPS to the server by its name, at the address the generator uses."""

    def __init__(self, g, cafile, token):
        url = urllib.parse.urlsplit(g["STRESS_BASE"])
        self.host, self.port = url.hostname, url.port or 443
        self.ip = g["STRESS_SERVER_IP"]
        ctx = ssl.create_default_context(cafile=cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx = ctx
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def call(self, method, path, body=None, want=200, timeout=300, wait_s=0):
        """The JSON answer of an API call; exits (without the body) on another status.

        With `wait_s`, a `503` is retried each second for up to that long: a Zitadel that has just
        started answers /debug/ready before its APIs serve.
        """
        for _ in range(wait_s):
            status, data = self._send(method, path, body, timeout)
            if status != 503:
                break
            time.sleep(1)
        else:
            status, data = self._send(method, path, body, timeout)
        if status != want:
            sys.exit(f"instance: {method} {path} answered {status}")
        return json.loads(data or b"{}")

    def _send(self, method, path, body, timeout):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout)
        conn.sock = self.ctx.wrap_socket(
            socket.create_connection((self.ip, self.port), timeout), server_hostname=self.host
        )
        try:
            conn.request(method, path, body=None if body is None else json.dumps(body), headers=self.headers)
            res = conn.getresponse()
            return res.status, res.read()
        finally:
            conn.close()


def main(bundle):
    g = read_env(f"{bundle}/generator.env")
    with open(f"{bundle}/setup.pat") as f:
        token = f.read().strip()
    s = Server(g, f"{bundle}/ca.crt", token)

    org = s.call("GET", "/management/v1/orgs/me", wait_s=60)["org"]
    if org["name"] != g["STRESS_REALM"]:
        sys.exit(f"instance: the service account's organization is not {g['STRESS_REALM']}")
    project = s.call("POST", "/management/v1/projects", {"name": g["STRESS_REALM"]})["id"]
    app = s.call("POST", f"/management/v1/projects/{project}/apps/oidc", app_rep(g))
    api = s.call("POST", f"/management/v1/projects/{project}/apps/api", api_rep())
    cc = s.call("POST", "/management/v1/users/machine", cc_rep())["userId"]
    cc_secret = s.call("PUT", f"/management/v1/users/{cc}/secret")
    update_env(
        f"{bundle}/generator.env",
        {
            "STRESS_APP_CLIENT_ID": app["clientId"],
            "STRESS_API_CLIENT_ID": api["clientId"],
            "STRESS_API_SECRET": api["clientSecret"],
            "STRESS_CC_CLIENT_ID": cc_secret["clientId"],
            "STRESS_CC_SECRET": cc_secret["clientSecret"],
            "STRESS_BULK_PASSWORD_HASH": unusable_hash(),
        },
    )

    added = 0
    for humans in login_batches(g):
        body = s.call("POST", "/admin/v1/import", import_body(org["id"], org["name"], humans))
        imported, failed = import_result(body)
        if failed or imported != len(humans):
            sys.exit(f"instance: importing login users: {imported} imported, {failed} failed")
        added += imported
    print(f"realm {g['STRESS_REALM']}: clients created, {added} login users added")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__))
