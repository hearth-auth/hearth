---
title: Python SDK quickstart
sidebar_label: Python
description: Verify Hearth tokens and enforce RBAC in a Python service in under 5 minutes. Covers Flask, FastAPI/Starlette, WSGI/ASGI middleware, and the auth code + PKCE callback.
---

# Python SDK quickstart

Add token verification and permission checks to a Python service in under 5 minutes using `hearth-sdk`.

## Install

```bash
pip install hearth-sdk
```

## Start Hearth locally

```bash
# from the hearth repo root
make dev
# → binds http://127.0.0.1:8420

curl -X POST http://127.0.0.1:8420/admin/bootstrap
# → { "realm_id": "…", "access_token": "…" }
```

## Auth code flow with PKCE

Python apps typically run the PKCE callback server-side. The browser redirects to your Python server with `?code=…`; your server exchanges the code for tokens.

### Step 1 — Redirect the browser

Build the authorization URL and redirect the user. Python has no helper — use `urllib` or an OIDC library:

```python
import secrets, hashlib, base64, urllib.parse

HEARTH_URL = "https://hearth.example.com"
REALM_ID   = "<realm_id>"
CLIENT_ID  = "<client_id>"

# PKCE (RFC 7636)
raw       = secrets.token_bytes(32)
verifier  = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
digest    = hashlib.sha256(verifier.encode()).digest()
challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
state     = secrets.token_hex(16)  # CSRF token

params = {
    "response_type":          "code",
    "client_id":              CLIENT_ID,
    "redirect_uri":           "https://myapp.example.com/callback",
    "scope":                  "openid profile email",
    "state":                  state,
    "code_challenge":         challenge,
    "code_challenge_method":  "S256",
}
auth_url = f"{HEARTH_URL}/realms/{REALM_ID}/authorize?" + urllib.parse.urlencode(params)
# store verifier + state in session, then redirect to auth_url
```

### Step 2 — Exchange the code

In your callback handler:

```python
import httpx

# verify request.args["state"] == session["state"] first
code     = request.args["code"]
verifier = session["pkce_verifier"]

resp = httpx.post(
    f"{HEARTH_URL}/realms/{REALM_ID}/token",
    data={
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  "https://myapp.example.com/callback",
        "client_id":     CLIENT_ID,
        "code_verifier": verifier,
    },
)
tokens = resp.json()
# tokens["access_token"], tokens["refresh_token"], tokens["expires_in"]
```

## Initialize the client

```python
from hearth import HearthClient

client = HearthClient(
    issuer_url="https://hearth.example.com",
    client_id="<your-client-id>",
)
```

`HearthClient` auto-discovers endpoint URLs from the OIDC discovery document and caches the JWKS with auto-refresh on key miss.

## Verify tokens

```python
from hearth.errors import TokenExpiredError, TokenInvalidError

try:
    claims = client.verify_token(access_token)
    # claims.sub, claims.roles, claims.groups, claims.permissions
except TokenExpiredError:
    pass  # 401 — ask client to refresh
except TokenInvalidError:
    pass  # 401 — reject the request
```

## RBAC permission checks

Permission checks are **synchronous and zero-network** — they read the embedded JWT claims:

```python
if claims.has_permission("invoices.write"):
    render_invoice_form()

if claims.has_role("billing-admin"):
    render_billing_panel()

if claims.in_group("engineering"):
    render_internal_tooling()
```

## Middleware

### WSGI (Flask, Django)

```python
from hearth.middleware import WsgiPermissionMiddleware

# Flask example — wraps the WSGI app
app.wsgi_app = WsgiPermissionMiddleware(
    app.wsgi_app,
    client=client,
    permission="docs.write",
    mode="embedded",
)
```

### ASGI (FastAPI, Starlette)

```python
from hearth.middleware import RequirePermissionMiddleware

# FastAPI / Starlette example
app = RequirePermissionMiddleware(
    app,
    client=client,
    permission="docs.write",
    mode="embedded",
)
```

Both middleware types respond `401 Unauthorized` on missing/invalid tokens and `403 Forbidden` on permission failures.

## Permission delivery modes

| Mode | How it works | When to use |
|------|-------------|-------------|
| `embedded` (default) | Permissions baked into the JWT at issuance. Zero extra network calls. | Most services |
| `decision` | Live per-request `POST /oauth/authorize`. Fail-closed on errors. | When post-issuance role changes must take effect immediately |
| `introspection` | `POST /realms/{id}/introspect` (RFC 7662). Echoes a `mode` field that is validated. | Stateless resource servers |

```python
# Decision mode — direct call
result = client.check_permission(access_token, "docs.write")
if not result.allowed:
    raise PermissionError("forbidden")

# Introspection mode — direct call
from hearth.errors import AuthorizationModeMismatchError

resp = client.introspect(access_token, client_id="<cid>", client_secret="<sec>")
if not resp.active:
    raise PermissionError("inactive token")
if resp.mode != "introspection":
    raise AuthorizationModeMismatchError("introspection", resp.mode or "embedded")
if "docs.write" not in (resp.permissions or []):
    raise PermissionError("forbidden")
```

## Error types

| Error | When raised |
|-------|-------------|
| `TokenExpiredError` | `exp` in the past |
| `TokenInvalidError` | Signature invalid or malformed JWT |
| `TokenIssuerError` | `iss` mismatch |
| `TokenAudienceError` | `aud` mismatch |
| `DiscoveryError` | OIDC discovery unreachable |
| `JWKSFetchError` | JWKS endpoint unreachable |
| `AuthorizationModeMismatchError` | Server echoed a mode different from configured |
| `IntrospectionError` | Introspection endpoint error |

## Next steps

- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [Python type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/python/README.md) — full API surface
