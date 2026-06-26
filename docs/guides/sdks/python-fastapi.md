---
title: Authenticate a FastAPI app with Hearth
sidebar_label: FastAPI
description: >
  Protect FastAPI routes with Hearth tokens using the dedicated FastAPI adapter.
  Covers Depends() injection, VerifiedClaims, require_permission, and pydantic-settings configuration.
---

# Authenticate a FastAPI app with Hearth

This guide is for **FastAPI developers** who want to protect routes with Hearth tokens. The `hearth-sdk` package ships a dedicated FastAPI adapter — `hearth.fastapi` — that integrates with FastAPI's `Depends()` injection system and types verified claims so they propagate into OpenAPI schema generation automatically.

:::note[Dedicated adapter vs generic ASGI middleware]
This page covers the `hearth.fastapi` adapter, which uses `Depends()` injection and returns a typed `VerifiedClaims` object per route handler. For **Starlette** (without FastAPI's DI layer) or any other ASGI app, use the generic [`RequirePermissionMiddleware`](./python.md#asgi--starlette) from `hearth.middleware` instead.
:::

## Install

```bash
pip install hearth-sdk fastapi uvicorn
# Optional: environment-variable configuration
pip install pydantic-settings
```

## Set up the adapter

```python
from hearth import HearthClient
from hearth.fastapi import HearthFastAPIDep

client = HearthClient(
    base_url="https://hearth.example.com",
    realm_id="<realm-id>",
)

# Create the reusable dependency — call it auth by convention
auth = HearthFastAPIDep(client=client, mode="embedded")
```

`HearthFastAPIDep` is a callable you pass to `Depends()`. It verifies the `Authorization: Bearer` header on every request and returns a `VerifiedClaims` object.

:::info[What is `mode`?]
The `mode` parameter controls how Hearth checks permissions. `"embedded"` (the default) reads claims directly from the JWT — zero extra network calls. See [Permission delivery modes](#permission-delivery-modes) for all options.
:::

## Protect a route

Inject `auth` into any route handler via `Depends()`:

```python
from fastapi import FastAPI, Depends
from hearth.fastapi import VerifiedClaims

app = FastAPI()

@app.get("/profile")
def get_profile(claims: VerifiedClaims = Depends(auth)):
    return {
        "sub":         claims.sub,
        "roles":       claims.roles,
        "permissions": claims.permissions,
    }
```

`auth` raises `HTTP 401 Unauthorized` on a missing or invalid token. FastAPI never calls the route handler on failure.

## Require a permission

Use `require_permission()` to create a dependency alias that gate-checks a specific permission:

```python
from hearth.fastapi import require_permission

# Define per-permission aliases at module level for readability
ReadDocs  = require_permission("docs.read",  dep=auth)
WriteDocs = require_permission("docs.write", dep=auth)

@app.get("/docs")
def list_docs(claims: ReadDocs):
    return {"docs": []}

@app.post("/docs")
def create_doc(claims: WriteDocs):
    return {"created": True, "author": claims.sub}
```

`ReadDocs` is an `Annotated[VerifiedClaims, Depends(...)]` type alias — FastAPI injects the verified claims **and** enforces the permission in one annotation. Routes with an insufficient permission receive `HTTP 403 Forbidden`.

## VerifiedClaims fields

Every protected route receives a `VerifiedClaims` object with all JWT claims pre-parsed:

| Field | Type | Description |
|-------|------|-------------|
| `sub` | `str` | Subject (user ID) |
| `iss` | `str` | Issuer URL |
| `exp` | `int \| None` | Expiry (Unix seconds) |
| `aud` | `list[str] \| None` | Audiences |
| `permissions` | `list[str]` | Embedded permission set (`permissions` claim) |
| `roles` | `list[str]` | Assigned roles (`roles` claim) |
| `groups` | `list[str]` | Group memberships (`groups` claim) |
| `organization_id` | `str \| None` | Organization (`oid` claim) |
| `jti` | `str \| None` | JWT ID |

Helper methods for inline checks:

```python
@app.get("/docs")
def list_docs(claims: VerifiedClaims = Depends(auth)):
    if not claims.has_permission("docs.read"):
        raise HTTPException(status_code=403)
    if claims.has_role("editor"):
        ...
    if claims.in_group("content-team"):
        ...
    return {"docs": []}
```

## Permission delivery modes

`HearthFastAPIDep` accepts an explicit `mode` — it never auto-detects the mode from JWT claim presence (per spec §15.3):

| Mode | How it works | When to use |
|------|-------------|-------------|
| `"embedded"` (default) | Permissions baked into the JWT at issuance. Zero extra network calls on the hot path. | Most services |
| `"decision"` | Live per-request `POST /oauth/authorize`. Fail-closed on errors. | When post-issuance role changes must take effect immediately |
| `"introspection"` | `POST /realms/{id}/introspect` (RFC 7662). Echoes a `mode` field that is validated. | Stateless resource servers delegating trust to the authorization server |

```python
# Introspection mode — supply client credentials for your resource server
auth = HearthFastAPIDep(
    client=client,
    mode="introspection",
    audience="my-api",  # optional: expected `aud` value
)
```

## Required-action tokens

If a user has a pending required action (e.g. MFA enrollment, email verification), their token carries `token_type: "required_action"`. The FastAPI adapter automatically rejects these with `HTTP 401` and a `WWW-Authenticate: Bearer realm="hearth", error="required_action"` header. No extra handling is needed in route handlers.

## Configure from environment variables

Install `pydantic-settings` to read Hearth configuration from environment variables instead of hard-coded values:

```bash
pip install pydantic-settings
```

```python
from hearth.fastapi import HearthSettings, HearthFastAPIDep

settings = HearthSettings()   # reads HEARTH_BASE_URL, HEARTH_REALM_ID, etc.
client   = settings.to_client()
auth     = HearthFastAPIDep(client=client, mode="embedded")
```

| Variable | Description |
|----------|-------------|
| `HEARTH_BASE_URL` | Hearth server URL — e.g. `https://hearth.example.com` |
| `HEARTH_REALM_ID` | Target realm ID |
| `HEARTH_CLIENT_ID` | OAuth client ID (optional) |
| `HEARTH_CLIENT_SECRET` | Client secret — **never** commit to source control |

## Full working example

```python
# main.py
import os
from fastapi import FastAPI, Depends
from hearth import HearthClient
from hearth.fastapi import HearthFastAPIDep, VerifiedClaims, require_permission

client = HearthClient(
    base_url=os.environ["HEARTH_BASE_URL"],
    realm_id=os.environ["HEARTH_REALM_ID"],
)
auth      = HearthFastAPIDep(client=client, mode="embedded")
WriteDocs = require_permission("docs.write", dep=auth)

app = FastAPI()

@app.get("/profile")
def profile(claims: VerifiedClaims = Depends(auth)):
    return {"sub": claims.sub, "roles": claims.roles}

@app.post("/docs")
def create_doc(claims: WriteDocs):
    return {"created": True, "author": claims.sub}
```

Run locally:

```bash
HEARTH_BASE_URL=http://127.0.0.1:8420 HEARTH_REALM_ID=<realm-id> uvicorn main:app
```

## Next steps

- [Python SDK quickstart](./python.md) — `HearthClient`, PKCE login, and the generic WSGI/ASGI middleware for Flask and Starlette
- [Django adapter](./python-django.md) — class-based `MIDDLEWARE` integration and `@require_permission` decorator for Django
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Permission delivery modes](./python.md#permission-delivery-modes) — full comparison of embedded, introspection, and decision modes
