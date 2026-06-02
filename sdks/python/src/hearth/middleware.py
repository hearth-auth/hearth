"""Mode-aware ASGI and WSGI permission middleware for Hearth.

Both ``RequirePermissionMiddleware`` (ASGI) and ``WsgiPermissionMiddleware``
(WSGI) enforce an explicit ``mode`` parameter — they MUST NOT auto-detect the
mode from JWT claim presence.  Per spec §15.3: absence of a ``permissions``
claim in the token does NOT trigger a fallback to a network mode.

Usage (ASGI / Starlette / FastAPI)::

    from hearth import HearthClient
    from hearth.middleware import RequirePermissionMiddleware

    client = HearthClient(base_url, realm_id=realm_id)
    app = RequirePermissionMiddleware(
        app,
        client=client,
        permission="docs.write",
        mode="embedded",          # "embedded" | "introspection" | "decision"
    )

Usage (WSGI / Flask / Django)::

    from hearth.middleware import WsgiPermissionMiddleware

    app.wsgi_app = WsgiPermissionMiddleware(
        app.wsgi_app,
        client=client,
        permission="docs.write",
        mode="decision",
    )
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional, TYPE_CHECKING

from .claims import Claims
from .errors import AuthorizationModeMismatchError, RequiredActionError

if TYPE_CHECKING:
    from .client import HearthClient

# ASGI/WSGI callable type aliases (not enforced at runtime, only for type checkers).
ASGIApp = Callable[..., Awaitable[None]]
WSGIApp = Callable[..., object]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _extract_bearer_asgi(scope: dict) -> Optional[str]:
    """Return the Bearer token from an ASGI HTTP scope, or None."""
    for name, value in scope.get("headers", []):
        if name.lower() == b"authorization":
            auth = value.decode("latin-1")
            if auth.startswith("Bearer "):
                return auth[7:]
    return None


def _extract_bearer_environ(environ: dict) -> Optional[str]:
    """Return the Bearer token from a WSGI environ dict, or None."""
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def _check_embedded(token: str, permission: str) -> bool:
    """Decode JWT locally and check ``permissions`` claim.

    Returns ``False`` when the claim is absent — never falls back to a network
    mode (design constraint: absence of claim ≠ switch mode).
    """
    try:
        claims = Claims.decode(token)
        perms = claims.get("permissions") or []
        return permission in perms
    except Exception:
        return False


def _check_introspection_sync(
    client: "HearthClient",
    token: str,
    permission: str,
    client_id: str,
    client_secret: Optional[str],
    expected_mode: str,
) -> bool:
    """Call POST /introspect, validate the echoed mode, then check the permission.

    :raises AuthorizationModeMismatchError: when the server echoes a mode that
        differs from ``expected_mode``.  Callers should map this to a denial.
    """
    resp = client.introspect(token, client_id=client_id, client_secret=client_secret)
    if not resp.active:
        return False
    # An absent mode field defaults to "embedded" (server omits it for embedded clients).
    echoed = resp.mode or "embedded"
    if echoed != expected_mode:
        raise AuthorizationModeMismatchError(expected_mode, echoed)
    return permission in (resp.permissions or [])


def _is_required_action_token(token: str) -> bool:
    """Return True when the token's token_type claim is 'required_action'."""
    try:
        return Claims.decode(token).token_type() == "required_action"
    except Exception:
        return False


async def _send_401_required_action(send: Callable) -> None:
    """Emit a minimal HTTP 401 ASGI response for required-action tokens (spec §6 rule 6)."""
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            [b"content-type", b"text/plain; charset=utf-8"],
            [b"www-authenticate", b'Bearer realm="hearth", error="required_action"'],
        ],
    })
    await send({"type": "http.response.body", "body": b"Required actions pending"})


async def _send_403(send: Callable) -> None:
    """Emit a minimal HTTP 403 ASGI response."""
    await send({
        "type": "http.response.start",
        "status": 403,
        "headers": [[b"content-type", b"text/plain; charset=utf-8"]],
    })
    await send({"type": "http.response.body", "body": b"Forbidden"})


def _wsgi_401_required_action(start_response: Callable) -> list:
    """Return a minimal HTTP 401 WSGI response for required-action tokens (spec §6 rule 6)."""
    start_response(
        "401 Unauthorized",
        [
            ("Content-Type", "text/plain"),
            ("WWW-Authenticate", 'Bearer realm="hearth", error="required_action"'),
        ],
    )
    return [b"Required actions pending"]


def _wsgi_403(start_response: Callable) -> list:
    """Return a minimal HTTP 403 WSGI response."""
    start_response("403 Forbidden", [("Content-Type", "text/plain")])
    return [b"Forbidden"]


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------

class RequirePermissionMiddleware:
    """ASGI middleware that enforces a Hearth permission check on every HTTP request.

    Non-HTTP connections (WebSocket, lifespan) pass through without checks.

    :param app: The downstream ASGI application.
    :param client: An authenticated :class:`~hearth.client.HearthClient`.
    :param permission: Permission string to require, e.g. ``"docs.write"``.
    :param mode: Authorization mode.  Must be one of ``"embedded"``,
        ``"introspection"``, or ``"decision"``.  NEVER auto-detected.
    :param client_id: Required when ``mode="introspection"``.
    :param client_secret: Optional client secret for introspection.
    :param organization_id: Optional org-scope for decision/introspection checks.
    :param resource: Optional RFC 8707 resource indicator.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        client: "HearthClient",
        permission: str,
        mode: str,
        client_id: str = "",
        client_secret: str = "",
        organization_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> None:
        self._app = app
        self._client = client
        self._permission = permission
        self._mode = mode
        self._client_id = client_id
        self._client_secret = client_secret or None
        self._organization_id = organization_id
        self._resource = resource

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        token = _extract_bearer_asgi(scope)
        if not token:
            await _send_403(send)
            return

        if _is_required_action_token(token):
            # Spec §6 rule 6: required_action tokens must never be accepted for
            # general API access — respond 401 and do not call next.
            await _send_401_required_action(send)
            return

        try:
            allowed = await self._check(token)
        except Exception:
            # Fail-closed on any error (mode mismatch, network, etc.)
            allowed = False

        if not allowed:
            await _send_403(send)
            return

        await self._app(scope, receive, send)

    async def _check(self, token: str) -> bool:
        if self._mode == "embedded":
            return _check_embedded(token, self._permission)

        if self._mode == "decision":
            # Run sync network call in thread pool to avoid blocking event loop.
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._client.check_permission(
                    token,
                    self._permission,
                    organization_id=self._organization_id,
                    resource=self._resource,
                ),
            )
            return result.allowed

        if self._mode == "introspection":
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: _check_introspection_sync(
                    self._client,
                    token,
                    self._permission,
                    self._client_id,
                    self._client_secret,
                    self._mode,
                ),
            )

        # Unknown mode — misconfiguration. Deny.
        return False


# ---------------------------------------------------------------------------
# WSGI middleware
# ---------------------------------------------------------------------------

class WsgiPermissionMiddleware:
    """WSGI middleware that enforces a Hearth permission check on every request.

    :param app: The downstream WSGI application.
    :param client: An authenticated :class:`~hearth.client.HearthClient`.
    :param permission: Permission string to require, e.g. ``"docs.write"``.
    :param mode: Authorization mode.  Must be one of ``"embedded"``,
        ``"introspection"``, or ``"decision"``.  NEVER auto-detected.
    :param client_id: Required when ``mode="introspection"``.
    :param client_secret: Optional client secret for introspection.
    :param organization_id: Optional org-scope for decision/introspection checks.
    :param resource: Optional RFC 8707 resource indicator.
    """

    def __init__(
        self,
        app: WSGIApp,
        *,
        client: "HearthClient",
        permission: str,
        mode: str,
        client_id: str = "",
        client_secret: str = "",
        organization_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> None:
        self._app = app
        self._client = client
        self._permission = permission
        self._mode = mode
        self._client_id = client_id
        self._client_secret = client_secret or None
        self._organization_id = organization_id
        self._resource = resource

    def __call__(self, environ: dict, start_response: Callable) -> object:
        token = _extract_bearer_environ(environ)
        if not token:
            return _wsgi_403(start_response)

        if _is_required_action_token(token):
            # Spec §6 rule 6: required_action tokens must never be accepted for
            # general API access — respond 401 and do not call next.
            return _wsgi_401_required_action(start_response)

        try:
            allowed = self._check(token)
        except Exception:
            # Fail-closed on any error (mode mismatch, network, etc.)
            allowed = False

        if not allowed:
            return _wsgi_403(start_response)

        return self._app(environ, start_response)

    def _check(self, token: str) -> bool:
        if self._mode == "embedded":
            return _check_embedded(token, self._permission)

        if self._mode == "decision":
            result = self._client.check_permission(
                token,
                self._permission,
                organization_id=self._organization_id,
                resource=self._resource,
            )
            return result.allowed

        if self._mode == "introspection":
            return _check_introspection_sync(
                self._client,
                token,
                self._permission,
                self._client_id,
                self._client_secret,
                self._mode,
            )

        # Unknown mode — misconfiguration. Deny.
        return False
