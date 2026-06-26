---
title: Authenticate a Django app with Hearth
sidebar_label: Django
description: >
  Protect Django views with Hearth tokens using the dedicated Django middleware adapter.
  Covers HearthDjangoMiddleware, the @require_permission decorator, and Django settings configuration.
---

# Authenticate a Django app with Hearth

This guide is for **Django developers** who want to protect views with Hearth tokens. The `hearth-sdk` package ships a dedicated Django middleware adapter — `hearth.django` — that integrates with Django's `MIDDLEWARE` settings list, attaches the verified token to every request, and provides a `@require_permission` per-view decorator.

:::note[Dedicated adapter vs generic WSGI middleware]
This page covers the `hearth.django` adapter, which reads its configuration from Django's `settings.py` and sets `request.hearth_token` on every request. For **Flask** or any other WSGI application, use the generic [`WsgiPermissionMiddleware`](./python.md#wsgi--flask) from `hearth.middleware` instead.
:::

## Install

```bash
pip install hearth-sdk django
```

## Configure Django settings

Add `HearthDjangoMiddleware` to your `MIDDLEWARE` list and supply at least one Hearth client config:

```python
# settings.py
import os
from hearth import HearthClient

# Option A — pre-built client (preferred)
HEARTH_CLIENT = HearthClient(
    base_url=os.environ["HEARTH_BASE_URL"],
    realm_id=os.environ["HEARTH_REALM_ID"],
)

HEARTH_MODE = "embedded"   # "embedded" | "introspection" | "decision"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # ... other middleware ...
    "hearth.django.HearthDjangoMiddleware",
]
```

The middleware extracts the Bearer token from the `Authorization` header on every request and sets `request.hearth_token` — either the raw JWT string or `None` if the header is absent.

:::tip[Building the client automatically]
You can omit `HEARTH_CLIENT` and set `HEARTH_BASE_URL` + `HEARTH_REALM_ID` instead. The middleware constructs a `HearthClient` on startup. The pre-built `HEARTH_CLIENT` option is preferred because it lets you reuse a single client across middleware and other code.
:::

## Access the token in a view

```python
# views.py
from django.http import JsonResponse

def profile(request):
    if not request.hearth_token:
        return JsonResponse({"error": "unauthorized"}, status=401)
    return JsonResponse({"authenticated": True})
```

Checking `request.hearth_token` directly is useful for views that serve both authenticated and anonymous users. For views that always require a valid token, use the `@require_permission` decorator or the global permission gate.

## Per-view `@require_permission` decorator

Use `@require_permission` to gate individual views on a specific permission:

```python
# views.py
from django.http import JsonResponse
from hearth.django import require_permission

@require_permission("docs.read")
def list_docs(request):
    return JsonResponse({"docs": []})

@require_permission("docs.write")
def create_doc(request):
    return JsonResponse({"created": True})
```

The decorator reads `request.hearth_token` when set by `HearthDjangoMiddleware`, or extracts the Bearer token directly from the `Authorization` header — both work regardless of middleware order.

Views protected by `@require_permission` return:
- `403 Forbidden` — token missing or lacks the required permission.
- `401 Unauthorized` (`WWW-Authenticate: Bearer realm="hearth", error="required_action"`) — token has `token_type: "required_action"` (user must complete a pending required action before accessing the API).

## Global permission gate

Set `HEARTH_PERMISSION` in `settings.py` to require a permission on **every** request the middleware processes:

```python
# settings.py
HEARTH_PERMISSION = "app.access"
```

Any request whose token lacks `app.access` receives `403 Forbidden`. Requests with no `Authorization` header also receive `403`.

## Django settings reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `HEARTH_CLIENT` | `HearthClient` | — | Pre-built client (preferred). |
| `HEARTH_BASE_URL` | `str` | — | Hearth server URL. Used when `HEARTH_CLIENT` is absent. |
| `HEARTH_REALM_ID` | `str` | — | Target realm ID. Used when `HEARTH_CLIENT` is absent. |
| `HEARTH_MODE` | `str` | `"embedded"` | Authorization mode: `"embedded"`, `"introspection"`, or `"decision"`. |
| `HEARTH_PERMISSION` | `str` | — | When set, every request must carry a token with this permission. |
| `HEARTH_CLIENT_ID` | `str` | `""` | Required for `mode="introspection"`. |
| `HEARTH_CLIENT_SECRET` | `str` | `""` | Optional client secret for introspection. |
| `HEARTH_ORGANIZATION_ID` | `str` | — | Org scope for decision/introspection checks. |
| `HEARTH_RESOURCE` | `str` | — | RFC 8707 resource indicator. |

## Permission delivery modes

The `HEARTH_MODE` / `mode=` parameter is always explicit — the adapter never auto-detects the mode from JWT claim presence (per spec §15.3):

| Mode | How it works | When to use |
|------|-------------|-------------|
| `"embedded"` (default) | Permissions baked into the JWT at issuance. Zero extra network calls on the hot path. | Most services |
| `"decision"` | Live per-request `POST /oauth/authorize`. Fail-closed on errors. | When post-issuance role changes must take effect immediately |
| `"introspection"` | `POST /realms/{id}/introspect` (RFC 7662). Echoes a `mode` field that is validated. | Stateless resource servers delegating trust to the authorization server |

Introspection mode requires `HEARTH_CLIENT_ID`:

```python
# settings.py
HEARTH_MODE      = "introspection"
HEARTH_CLIENT_ID = "<resource-server-client-id>"
# HEARTH_CLIENT_SECRET = "<secret>"  # optional
```

## Required-action tokens

If a user has a pending required action (e.g. MFA enrollment, email verification), their token carries `token_type: "required_action"`. Both `HearthDjangoMiddleware` and `@require_permission` automatically return `401 Unauthorized` with `WWW-Authenticate: Bearer realm="hearth", error="required_action"` — no extra handling is needed in views.

## Full working example

```python
# settings.py
import os
from hearth import HearthClient

HEARTH_CLIENT = HearthClient(
    base_url=os.environ["HEARTH_BASE_URL"],
    realm_id=os.environ["HEARTH_REALM_ID"],
)
HEARTH_MODE = "embedded"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    # ...
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "hearth.django.HearthDjangoMiddleware",
]

ROOT_URLCONF = "myapp.urls"
```

```python
# views.py
from django.http import JsonResponse
from hearth.django import require_permission

def profile(request):
    """Works for both authenticated and anonymous users."""
    if request.hearth_token:
        return JsonResponse({"authenticated": True})
    return JsonResponse({"authenticated": False})

@require_permission("docs.read")
def list_docs(request):
    return JsonResponse({"docs": []})

@require_permission("docs.write")
def create_doc(request):
    return JsonResponse({"created": True})
```

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("profile/",  views.profile),
    path("docs/",     views.list_docs),
    path("docs/new/", views.create_doc),
]
```

## Next steps

- [Python SDK quickstart](./python.md) — `HearthClient`, PKCE login, and the generic WSGI/ASGI middleware for Flask and Starlette
- [FastAPI adapter](./python-fastapi.md) — `Depends()` injection, `VerifiedClaims`, and the `require_permission()` type alias for FastAPI
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Permission delivery modes](./python.md#permission-delivery-modes) — full comparison of embedded, introspection, and decision modes
