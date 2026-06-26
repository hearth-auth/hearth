"""Django class-based middleware adapter for Hearth authentication.

Provides :class:`HearthDjangoMiddleware` for installation via Django's
``MIDDLEWARE`` settings list, and :func:`require_permission` as a per-view
decorator.

Usage (settings.py)::

    from hearth import HearthClient

    HEARTH_CLIENT = HearthClient("https://auth.example.com", realm_id="my-realm")
    HEARTH_MODE = "embedded"        # "embedded" | "introspection" | "decision"
    # Optional — enforce this permission on every request:
    HEARTH_PERMISSION = "app.access"

    MIDDLEWARE = [
        ...
        "hearth.django.HearthDjangoMiddleware",
    ]

Usage (views.py)::

    from hearth.django import require_permission

    @require_permission("docs.write")
    def my_view(request):
        token = request.hearth_token  # set by HearthDjangoMiddleware
        return HttpResponse("ok")
"""

from __future__ import annotations

from functools import wraps
from typing import Callable, Optional, TYPE_CHECKING

try:
    from django.conf import settings as django_settings
    from django.http import HttpRequest, HttpResponse
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "hearth.django requires Django. "
        "Install it with: pip install django"
    ) from _exc

from .middleware import (
    _check_embedded,
    _check_introspection_sync,
    _extract_bearer_environ,
    _is_required_action_token,
)

if TYPE_CHECKING:
    from .client import HearthClient


# ---------------------------------------------------------------------------
# Django-specific HTTP response helpers
# ---------------------------------------------------------------------------

def _django_403() -> HttpResponse:
    """Return a minimal 403 Forbidden Django response."""
    return HttpResponse("Forbidden", status=403, content_type="text/plain")


def _django_401_required_action() -> HttpResponse:
    """Return a 401 Unauthorized Django response for required-action tokens (spec §6 rule 6)."""
    resp = HttpResponse("Required actions pending", status=401, content_type="text/plain")
    resp["WWW-Authenticate"] = 'Bearer realm="hearth", error="required_action"'
    return resp


# ---------------------------------------------------------------------------
# Shared sync permission check
# ---------------------------------------------------------------------------

def _sync_check(
    client: Optional["HearthClient"],
    token: str,
    permission: str,
    mode: str,
    client_id: str = "",
    client_secret: str = "",
    organization_id: Optional[str] = None,
    resource: Optional[str] = None,
) -> bool:
    """Check a permission synchronously, dispatching on *mode*.

    Returns ``False`` when *mode* is unknown or a required *client* is absent.
    Never raises — callers should catch and treat exceptions as denial.
    """
    if mode == "embedded":
        return _check_embedded(token, permission)

    if mode == "decision":
        if client is None:
            return False
        result = client.check_permission(
            token,
            permission,
            organization_id=organization_id,
            resource=resource,
        )
        return result.allowed

    if mode == "introspection":
        if client is None:
            return False
        return _check_introspection_sync(
            client,
            token,
            permission,
            client_id,
            client_secret,
            mode,
        )

    # Unknown mode — misconfiguration. Deny.
    return False


# ---------------------------------------------------------------------------
# HearthDjangoMiddleware
# ---------------------------------------------------------------------------

class HearthDjangoMiddleware:
    """Django new-style class middleware for Hearth token extraction.

    Extracts the Bearer token from every request's ``Authorization`` header and
    sets ``request.hearth_token`` for downstream views.  Optionally enforces a
    global permission gate when ``HEARTH_PERMISSION`` is configured.

    **Required Django settings** (at least one of):

    * ``HEARTH_CLIENT`` — a pre-built :class:`~hearth.client.HearthClient`
      instance (preferred).
    * ``HEARTH_BASE_URL`` + ``HEARTH_REALM_ID`` — used to build a client
      automatically.

    **Optional Django settings**:

    * ``HEARTH_MODE`` (str) — ``"embedded"`` (default), ``"introspection"``,
      or ``"decision"``.
    * ``HEARTH_PERMISSION`` (str) — when set, every request must carry a token
      that passes this permission gate; missing or denied tokens receive 403.
    * ``HEARTH_CLIENT_ID`` (str) — required for ``introspection`` mode.
    * ``HEARTH_CLIENT_SECRET`` (str) — optional client secret for introspection.
    * ``HEARTH_ORGANIZATION_ID`` (str) — org scope for decision/introspection.
    * ``HEARTH_RESOURCE`` (str) — RFC 8707 resource indicator.

    After the middleware runs, ``request.hearth_token`` is set to the raw JWT
    string or ``None`` if no ``Authorization`` header was present.
    """

    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response
        self._client: Optional["HearthClient"] = getattr(django_settings, "HEARTH_CLIENT", None)
        if self._client is None:
            base_url = getattr(django_settings, "HEARTH_BASE_URL", None)
            realm_id = getattr(django_settings, "HEARTH_REALM_ID", None)
            if base_url and realm_id:
                from .client import HearthClient as _HearthClient
                self._client = _HearthClient(base_url, realm_id=realm_id)
        self._mode: str = getattr(django_settings, "HEARTH_MODE", "embedded")
        self._permission: Optional[str] = getattr(django_settings, "HEARTH_PERMISSION", None)
        self._client_id: str = getattr(django_settings, "HEARTH_CLIENT_ID", "")
        self._client_secret: str = getattr(django_settings, "HEARTH_CLIENT_SECRET", "")
        self._organization_id: Optional[str] = getattr(django_settings, "HEARTH_ORGANIZATION_ID", None)
        self._resource: Optional[str] = getattr(django_settings, "HEARTH_RESOURCE", None)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        token = _extract_bearer_environ(request.META)
        request.hearth_token = token  # always set, even when None

        if token and _is_required_action_token(token):
            # Spec §6 rule 6: required_action tokens must not be used for API access.
            return _django_401_required_action()

        if self._permission:
            if not token:
                return _django_403()
            try:
                allowed = _sync_check(
                    self._client,
                    token,
                    self._permission,
                    self._mode,
                    client_id=self._client_id,
                    client_secret=self._client_secret,
                    organization_id=self._organization_id,
                    resource=self._resource,
                )
            except Exception:
                # Fail-closed on any error (mode mismatch, network, etc.)
                allowed = False
            if not allowed:
                return _django_403()

        return self.get_response(request)


# ---------------------------------------------------------------------------
# @require_permission view decorator
# ---------------------------------------------------------------------------

def require_permission(
    permission: str,
    *,
    client: Optional["HearthClient"] = None,
    mode: str = "embedded",
    client_id: str = "",
    client_secret: str = "",
    organization_id: Optional[str] = None,
    resource: Optional[str] = None,
) -> Callable:
    """View decorator that enforces a Hearth permission check on a specific view.

    Uses ``request.hearth_token`` when set by :class:`HearthDjangoMiddleware`,
    or extracts the Bearer token directly from the ``Authorization`` header.

    :param permission: Permission string to require, e.g. ``"docs.write"``.
    :param client: A :class:`~hearth.client.HearthClient` instance.  Falls back
        to ``settings.HEARTH_CLIENT`` when not provided.
    :param mode: Authorization mode.  Must be ``"embedded"``,
        ``"introspection"``, or ``"decision"``.  Defaults to ``"embedded"``.
    :param client_id: Required when ``mode="introspection"``.
    :param client_secret: Optional client secret for introspection.
    :param organization_id: Optional org-scope for decision/introspection checks.
    :param resource: Optional RFC 8707 resource indicator.

    Usage::

        @require_permission("docs.write")
        def my_view(request):
            return HttpResponse("ok")

        # With a non-embedded mode:
        @require_permission("docs.write", client=hearth_client, mode="decision")
        def my_view(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            # Prefer token already extracted by HearthDjangoMiddleware.
            token = getattr(request, "hearth_token", None) or _extract_bearer_environ(request.META)
            if not token:
                return _django_403()

            if _is_required_action_token(token):
                return _django_401_required_action()

            # Resolve client: explicit arg > settings.HEARTH_CLIENT.
            _client = client or getattr(django_settings, "HEARTH_CLIENT", None)
            if _client is None and mode != "embedded":
                return _django_403()

            try:
                allowed = _sync_check(
                    _client,
                    token,
                    permission,
                    mode,
                    client_id=client_id,
                    client_secret=client_secret,
                    organization_id=organization_id,
                    resource=resource,
                )
            except Exception:
                # Fail-closed on any error.
                allowed = False

            if not allowed:
                return _django_403()

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
