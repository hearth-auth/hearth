# Hearth Python SDK

Python client for the [Hearth](https://github.com/hearth-auth/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/specs/SDK.md).

## Installation

```bash
pip install hearth-sdk
```

## Quick start

```python
from hearth import HearthClient

client = HearthClient(
    issuer_url="https://hearth.example.com",
    client_id="<your-client-id>",
)
```

## Permission delivery modes

Hearth supports three permission delivery modes controlled by the `access_token_authorization`
field on the OAuth client registration. The Python SDK exposes all three via explicit middleware
and client methods. **Mode is always configured explicitly — the SDK never auto-detects it from
JWT claim presence.**

### embedded (default)

Permissions are embedded in the JWT at issuance. No network call on the hot path.

```python
from hearth.middleware import WsgiPermissionMiddleware

# Flask example
app.wsgi_app = WsgiPermissionMiddleware(
    app.wsgi_app,
    client=client,
    permission="docs.write",
    mode="embedded",
)
```

### decision

The server makes a live per-request decision via `POST /oauth/authorize`. Fail-closed on errors.

```python
# Starlette / FastAPI example
from hearth.middleware import RequirePermissionMiddleware

app = RequirePermissionMiddleware(
    app,
    client=client,
    permission="docs.write",
    mode="decision",
)
```

Or call directly (returns `CheckPermissionResponse(allowed=False)` on any error):

```python
result = client.check_permission(access_token, "docs.write")
if not result.allowed:
    raise PermissionError("forbidden")
```

### introspection

The server introspects the token live via `POST /realms/{realm_id}/introspect` (RFC 7662).
The response echoes a `mode` field; middleware rejects tokens whose echoed mode does not
match the configured expectation.

```python
from hearth.middleware import RequirePermissionMiddleware

app = RequirePermissionMiddleware(
    app,
    client=client,
    permission="docs.write",
    mode="introspection",
    client_id="<resource-server-client-id>",
    client_secret="<secret>",   # optional for public clients
)
```

Or call directly:

```python
from hearth.errors import AuthorizationModeMismatchError

resp = client.introspect(access_token, client_id="<cid>", client_secret="<sec>")
if not resp.active:
    raise PermissionError("inactive token")
if resp.mode != "introspection":
    raise AuthorizationModeMismatchError("introspection", resp.mode or "embedded")
if "docs.write" not in (resp.permissions or []):
    raise PermissionError("forbidden")
```

## Troubleshooting

**`DiscoveryError`** — verify `issuer_url` is reachable and returns a valid `/.well-known/openid-configuration`.

**`JWKSFetchError`** — check network connectivity to the JWKS endpoint. The SDK retries once on a cache miss before returning this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Refresh the token or re-authenticate.

**`TokenInvalidError`** — JWT signature does not match any key in the JWKS. If the server recently rotated keys the SDK will re-fetch once automatically; persistent failures indicate a key mismatch.

**`TokenAudienceError`** — the token's `aud` claim does not contain the configured audience. Verify `client_id` matches the audience your authorization server issues.

See [docs/specs/SDK.md](../../docs/specs/SDK.md) Section 5 for the full error taxonomy.

---

## Agent Authentication (M5)

Enable `agent_auth.capabilities.identity = true` (plus `advanced = true` for AATs/transaction tokens) in `hearth.yaml`.

```python
import httpx, hashlib, json, base64, time, uuid
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# ── DPoP proof (RFC 9449) ──────────────────────────────────────────────────
priv = ec.generate_private_key(ec.SECP256R1())
pub = priv.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
pub_numbers = priv.public_key().public_numbers()
x = base64.urlsafe_b64encode(pub_numbers.x.to_bytes(32, "big")).rstrip(b"=").decode()
y = base64.urlsafe_b64encode(pub_numbers.y.to_bytes(32, "big")).rstrip(b"=").decode()

canonical = json.dumps({"crv": "P-256", "kty": "EC", "x": x, "y": y}, separators=(",", ":"))
thumbprint = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()

def b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

def make_dpop_proof(htm: str, htu: str, nonce: str | None = None) -> str:
    header = {"alg": "ES256", "jwk": {"crv": "EC", "kty": "EC", "x": x, "y": y}, "typ": "dpop+jwt"}
    claims = {"htm": htm, "htu": htu, "iat": int(time.time()), "jti": str(uuid.uuid4())}
    if nonce:
        claims["nonce"] = nonce
    signing_input = f"{b64u(header)}.{b64u(claims)}"
    der_sig = priv.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)  # convert DER → raw r||s for JWT
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input}.{base64.urlsafe_b64encode(raw_sig).rstrip(b'=').decode()}"

# ── client_credentials + DPoP ─────────────────────────────────────────────
token_url = f"{base_url}/realms/{realm_id}/token"
resp = httpx.post(token_url, data={"grant_type": "client_credentials"}, auth=(client_id, secret),
                  headers={"DPoP": make_dpop_proof("POST", token_url)})
nonce = resp.headers.get("dpop-nonce")
resp = httpx.post(token_url, data={"grant_type": "client_credentials"}, auth=(client_id, secret),
                  headers={"DPoP": make_dpop_proof("POST", token_url, nonce)})
access_token = resp.json()["access_token"]
# Decoded JWT claims will contain: cnf.jkt == thumbprint

# ── AAT (admin token required for /v1/aats) ────────────────────────────────
root_aat = httpx.post(f"{base_url}/v1/aats", json={
    "realm_id": realm_id, "agent_id": agent_id,
    "tools": [{"tool_name": "read_docs", "constraints": None}],
    "expires_in_secs": 3600,
}, headers={"Authorization": f"Bearer {admin_token}"}).json()

# ── Transaction token ──────────────────────────────────────────────────────
txn = httpx.post(f"{base_url}/v1/transaction-tokens", json={
    "realm_id": realm_id,
    "requesting_agent_id": agent_a_id,
    "target_agent_id": agent_b_id,
    "txn_id": f"txn-{uuid.uuid4()}",
}, headers={"Authorization": f"Bearer {admin_token}"}).json()
```

For the full surface (draft tracking, RFC 8693 exchange, Agent Card), see the [TypeScript SDK README](../typescript/README.md#agent-authentication-m5).
