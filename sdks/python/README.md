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
