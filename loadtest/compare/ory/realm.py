"""The stress realm of the Ory comparison run (#913), through Hydra's and Kratos's admin APIs.

Usage: realm.py <bundle>

Hydra keeps the clients, Kratos the users. This script creates the two Hydra clients and then
imports the realm admin and the login users with their password through Kratos's bulk path
(PATCH /admin/identities), 100 per request (Kratos takes at most 200 with a plaintext password).
Kratos hashes each password with its configured Argon2id settings (kratos.yaml). The 1M users
without a usable password come later, from the seed (k6/prepare.js through the Ory adapter).

The realm mirrors the Hearth realm of gen-config.sh:
  app    public client (no secret): authorization code + PKCE, refresh tokens (offline_access),
         skip_consent: a first-party client, so the consent page accepts at once (Ory's
         documented setup; the field can only be set through the admin API)
  api    confidential client with a secret Hydra generates (client_secret_basic): the client
         credentials journey. Introspection is Hydra's admin endpoint, which takes no client
         authentication (Ory: keep the admin port off the public network)
  admin  admin@<host>: signs in through the login page like the users, as the other products'
         realm admins do. Kratos's admin API has no authentication of its own (Ory: keep it off
         the public network), so the admin journeys carry no token
  users  user000001@<host> ... with one password, as gen-config.sh's seed_users

Hydra's own choices that stay: refresh tokens rotate (a used one is refused
and its family revoked), client secrets are stored as PBKDF2-SHA256 hashes (25,000 iterations).

The generated client ids and the secret go to generator.env, with the hash that the seed gives
the bulk users (unusable_hash). No password or secret is printed.
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
HYDRA_ADMIN_PORT = 4445
KRATOS_ADMIN_PORT = 4434
SCHEMA_ID = "default"
# The run's Argon2id parameters (kratos.yaml), as Kratos encodes them.
ARGON2ID_PARAMS = "$argon2id$v=19$m=19456,t=2,p=1"


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


def identity(email, first, last, password=None, hashed_password=None):
    """A Kratos createIdentityBody: the email is the password identifier, already verified.

    With `password` Kratos hashes it (Argon2id, kratos.yaml); with `hashed_password` it stores
    the hash as given (the documented import of hashes from another system). The verified address
    means no verification message is ever due for the user.
    """
    body = {
        "schema_id": SCHEMA_ID,
        "traits": {"email": email, "name": {"first": first, "last": last}},
        "state": "active",
        "verifiable_addresses": [
            {"value": email, "via": "email", "verified": True, "status": "completed"}
        ],
    }
    if password is not None:
        body["credentials"] = {"password": {"config": {"password": password}}}
    elif hashed_password is not None:
        body["credentials"] = {"password": {"config": {"hashed_password": hashed_password}}}
    return body


def unusable_hash(rand=secrets.token_bytes):
    """A well-formed Argon2id hash with the run's parameters and random salt and digest.

    The bulk users get it as their `hashed_password`. No password matches it, so they have no
    usable password, as Hearth's bulk users; Kratos would also take users without any credential,
    but a password user with Argon2id parameters is what a migrated deployment holds. Kratos only
    stores an imported hash (it hashes nothing), so the seed costs no Argon2id work, as Hearth's
    seed costs none. Kratos encodes salt and digest in unpadded standard base64.
    """
    def b64(b):
        return base64.b64encode(b).decode().rstrip("=")

    return f"{ARGON2ID_PARAMS}${b64(rand(16))}${b64(rand(32))}"


def batch_body(identities):
    """A PATCH /admin/identities body that creates `identities`."""
    return {"identities": [{"create": i} for i in identities]}


def batch_result(body):
    """(created, failed) of a PATCH /admin/identities answer."""
    items = body.get("identities") or []
    created = sum(1 for i in items if i.get("action") == "create" and i.get("identity"))
    return created, len(items) - created


def app_rep(g):
    """The public `app` client: authorization code with PKCE and refresh tokens, no consent page."""
    return {
        "client_name": "app",
        "redirect_uris": [g["STRESS_REDIRECT_URI"]],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        # Hydra issues a refresh token only for offline_access (or offline).
        "scope": "openid offline_access",
        "token_endpoint_auth_method": "none",
        "skip_consent": True,
    }


def api_rep():
    """The confidential `api` client of the client credentials journey; Hydra makes its secret."""
    return {
        "client_name": "api",
        "grant_types": ["client_credentials"],
        "response_types": [],
        "token_endpoint_auth_method": "client_secret_basic",
    }


def login_batches(g, batch=LOGIN_BATCH):
    """Lists of `identity` bodies for the login users, `batch` users each."""
    n, host, pw = int(g["STRESS_LOGIN_USERS"]), g["STRESS_HOST"], g["STRESS_USER_PASSWORD"]
    for lo in range(1, n + 1, batch):
        yield [identity(user_email(i, host), "User", str(i), password=pw) for i in range(lo, min(lo + batch, n + 1))]


class Server:
    """HTTPS to one of the server's admin ports by its name, at the address the generator uses."""

    def __init__(self, g, cafile, port):
        self.host = urllib.parse.urlsplit(g["STRESS_BASE"]).hostname
        self.port = port
        self.ip = g["STRESS_SERVER_IP"]
        ctx = ssl.create_default_context(cafile=cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx = ctx

    def call(self, method, path, body=None, want=200, timeout=300, wait_s=0):
        """The JSON answer of an API call; exits (without the body) on another status.

        With `wait_s`, a refused connection or a `503` is retried each second for up to that long.
        """
        for _ in range(wait_s):
            try:
                status, data = self._send(method, path, body, timeout)
            except OSError:
                time.sleep(1)
                continue
            if status != 503:
                break
            time.sleep(1)
        else:
            status, data = self._send(method, path, body, timeout)
        if status != want:
            sys.exit(f"realm: {method} {path} answered {status}")
        return json.loads(data or b"{}")

    def _send(self, method, path, body, timeout):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout)
        conn.sock = self.ctx.wrap_socket(
            socket.create_connection((self.ip, self.port), timeout), server_hostname=self.host
        )
        try:
            conn.request(
                method,
                path,
                body=None if body is None else json.dumps(body),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            res = conn.getresponse()
            return res.status, res.read()
        finally:
            conn.close()


def main(bundle):
    g = read_env(f"{bundle}/generator.env")
    hydra = Server(g, f"{bundle}/ca.crt", HYDRA_ADMIN_PORT)
    kratos = Server(g, f"{bundle}/ca.crt", KRATOS_ADMIN_PORT)

    app = hydra.call("POST", "/admin/clients", app_rep(g), want=201, wait_s=60)
    api = hydra.call("POST", "/admin/clients", api_rep(), want=201)
    update_env(
        f"{bundle}/generator.env",
        {
            "STRESS_APP_CLIENT_ID": app["client_id"],
            "STRESS_API_CLIENT_ID": api["client_id"],
            "STRESS_API_SECRET": api["client_secret"],
            "STRESS_BULK_PASSWORD_HASH": unusable_hash(),
        },
    )

    admin = identity(g["STRESS_ADMIN_EMAIL"], "Realm", "Admin", password=g["STRESS_ADMIN_PASSWORD"])
    added = 0
    for i, batch in enumerate(login_batches(g)):
        if i == 0:
            batch = [admin] + batch
        body = kratos.call("PATCH", "/admin/identities", batch_body(batch), wait_s=60)
        created, failed = batch_result(body)
        if failed or created != len(batch):
            sys.exit(f"realm: importing login users: {created} created, {failed} failed")
        added += created - (1 if i == 0 else 0)
    print(f"realm {g['STRESS_REALM']}: clients created, the admin and {added} login users added")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__))
