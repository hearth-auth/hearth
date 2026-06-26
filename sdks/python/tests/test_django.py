"""TDD tests for hearth.django — Django class-based middleware adapter.

Run with:
  cd sdks/python && .venv/bin/pytest tests/test_django.py -v
"""

from __future__ import annotations

import base64
import json
from typing import Optional
from unittest.mock import MagicMock, patch

import httpx
import pytest

# Configure minimal Django settings before importing Django or hearth.django.
from django.conf import settings as _django_settings

if not _django_settings.configured:
    _django_settings.configure(
        SECRET_KEY="test-hearth-only",
        DATABASES={},
        INSTALLED_APPS=[],
    )

from django.http import HttpRequest, HttpResponse

from hearth.django import HearthDjangoMiddleware, require_permission


# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict) -> str:
    """Build a minimal unsigned JWT for testing local-decode paths."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."


def _make_required_action_jwt() -> str:
    """Build a JWT whose token_type is required_action."""
    return _make_jwt({"sub": "u", "token_type": "required_action"})


def _make_request(token: Optional[str] = None) -> HttpRequest:
    """Build a Django HttpRequest with an optional Authorization header."""
    req = HttpRequest()
    req.META["REQUEST_METHOD"] = "GET"
    req.META["PATH_INFO"] = "/api/test"
    if token:
        req.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return req


def _ok_response(_request):
    return HttpResponse("ok", status=200)


def _mock_settings(
    *,
    client=None,
    mode: str = "embedded",
    permission: Optional[str] = None,
    client_id: str = "",
    client_secret: str = "",
):
    """Return a context manager that patches hearth.django.django_settings."""
    mock = MagicMock()
    mock.HEARTH_CLIENT = client
    mock.HEARTH_MODE = mode
    mock.HEARTH_PERMISSION = permission
    mock.HEARTH_CLIENT_ID = client_id
    mock.HEARTH_CLIENT_SECRET = client_secret
    mock.HEARTH_ORGANIZATION_ID = None
    mock.HEARTH_RESOURCE = None
    # Also configure base URL / realm as None so no HearthClient is auto-built.
    mock.HEARTH_BASE_URL = None
    mock.HEARTH_REALM_ID = None
    return patch("hearth.django.django_settings", mock)


# ---------------------------------------------------------------------------
# HearthDjangoMiddleware — token propagation
# ---------------------------------------------------------------------------

class TestHearthDjangoMiddlewareTokenPropagation:
    """Middleware correctly sets request.hearth_token."""

    def test_sets_hearth_token_when_authorization_header_present(self):
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)

        with _mock_settings():
            mw = HearthDjangoMiddleware(_ok_response)

        mw(req)
        assert req.hearth_token == token

    def test_sets_hearth_token_none_when_no_authorization_header(self):
        req = _make_request()

        with _mock_settings():
            mw = HearthDjangoMiddleware(_ok_response)

        mw(req)
        assert req.hearth_token is None

    def test_passes_through_to_next_when_no_global_permission(self):
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("inner", status=200))

        with _mock_settings():
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 200
        inner.assert_called_once()

    def test_passes_through_without_token_when_no_global_permission(self):
        """No-auth requests pass through when no HEARTH_PERMISSION is configured."""
        req = _make_request()
        inner = MagicMock(return_value=HttpResponse("ok", status=200))

        with _mock_settings():
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 200
        inner.assert_called_once()


# ---------------------------------------------------------------------------
# HearthDjangoMiddleware — required-action tokens
# ---------------------------------------------------------------------------

class TestHearthDjangoMiddlewareRequiredAction:
    def test_required_action_token_returns_401(self):
        token = _make_required_action_jwt()
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))

        with _mock_settings():
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 401
        inner.assert_not_called()

    def test_required_action_response_includes_www_authenticate_header(self):
        token = _make_required_action_jwt()
        req = _make_request(token)

        with _mock_settings():
            mw = HearthDjangoMiddleware(_ok_response)

        resp = mw(req)
        assert "WWW-Authenticate" in resp
        assert "required_action" in resp["WWW-Authenticate"]


# ---------------------------------------------------------------------------
# HearthDjangoMiddleware — global permission gate (embedded mode)
# ---------------------------------------------------------------------------

class TestHearthDjangoMiddlewareGlobalPermission:
    def _make_client(self):
        return MagicMock()

    def test_global_permission_allows_valid_embedded_token(self):
        token = _make_jwt({"sub": "user-1", "permissions": ["app.access"]})
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))

        with _mock_settings(permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 200
        inner.assert_called_once()

    def test_global_permission_denies_missing_permission(self):
        token = _make_jwt({"sub": "user-1", "permissions": ["other.perm"]})
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))

        with _mock_settings(permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 403
        inner.assert_not_called()

    def test_global_permission_denies_missing_token(self):
        req = _make_request()  # no Authorization header
        inner = MagicMock(return_value=HttpResponse("ok"))

        with _mock_settings(permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 403
        inner.assert_not_called()

    def test_global_permission_denies_absent_permissions_claim(self):
        """Absence of permissions claim must NOT trigger mode fallback — deny."""
        token = _make_jwt({"sub": "user-1"})  # no permissions claim
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))

        with _mock_settings(permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 403
        inner.assert_not_called()

    def test_global_permission_denies_on_exception(self):
        """Any error during permission check must fail closed (403)."""
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))
        client = MagicMock()
        client.check_permission.side_effect = RuntimeError("boom")

        with _mock_settings(client=client, mode="decision", permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 403
        inner.assert_not_called()


# ---------------------------------------------------------------------------
# HearthDjangoMiddleware — decision mode via network (global gate)
# ---------------------------------------------------------------------------

class TestHearthDjangoMiddlewareDecisionMode:
    def test_decision_mode_allows_when_server_returns_allowed(self):
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))
        client = MagicMock()
        client.check_permission.return_value = MagicMock(allowed=True)

        with _mock_settings(client=client, mode="decision", permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 200
        inner.assert_called_once()

    def test_decision_mode_denies_when_server_denies(self):
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))
        client = MagicMock()
        client.check_permission.return_value = MagicMock(allowed=False)

        with _mock_settings(client=client, mode="decision", permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 403
        inner.assert_not_called()


# ---------------------------------------------------------------------------
# @require_permission decorator — embedded mode
# ---------------------------------------------------------------------------

class TestRequirePermissionEmbedded:
    def test_allows_valid_permission(self):
        token = _make_jwt({"permissions": ["docs.write"]})
        req = _make_request(token)

        with _mock_settings():
            @require_permission("docs.write")
            def view(request):
                return HttpResponse("view response")

        resp = view(req)
        assert resp.status_code == 200

    def test_denies_missing_permission(self):
        token = _make_jwt({"permissions": ["other.perm"]})
        req = _make_request(token)

        with _mock_settings():
            @require_permission("docs.write")
            def view(request):
                return HttpResponse("view response")

        resp = view(req)
        assert resp.status_code == 403

    def test_denies_no_token(self):
        req = _make_request()  # no Authorization header

        with _mock_settings():
            @require_permission("docs.write")
            def view(request):
                return HttpResponse("view response")

        resp = view(req)
        assert resp.status_code == 403

    def test_required_action_token_returns_401(self):
        token = _make_required_action_jwt()
        req = _make_request(token)

        with _mock_settings():
            @require_permission("docs.write")
            def view(request):
                return HttpResponse("view response")

        resp = view(req)
        assert resp.status_code == 401

    def test_uses_hearth_token_set_by_middleware(self):
        """Decorator reads request.hearth_token instead of re-extracting from META."""
        token = _make_jwt({"permissions": ["docs.write"]})
        req = _make_request()  # no Authorization header in META
        req.hearth_token = token  # but middleware already extracted it

        with _mock_settings():
            @require_permission("docs.write")
            def view(request):
                return HttpResponse("ok")

        resp = view(req)
        assert resp.status_code == 200

    def test_view_receives_original_args_and_kwargs(self):
        token = _make_jwt({"permissions": ["docs.write"]})
        req = _make_request(token)
        captured = {}

        with _mock_settings():
            @require_permission("docs.write")
            def view(request, pk, extra=None):
                captured["pk"] = pk
                captured["extra"] = extra
                return HttpResponse("ok")

        resp = view(req, 42, extra="hello")
        assert resp.status_code == 200
        assert captured == {"pk": 42, "extra": "hello"}

    def test_denies_absent_permissions_claim_stays_embedded(self):
        """Absence of permissions claim must not trigger fallback to another mode."""
        token = _make_jwt({"sub": "user-1"})  # no permissions claim
        req = _make_request(token)

        with _mock_settings():
            @require_permission("docs.write")
            def view(request):
                return HttpResponse("ok")

        resp = view(req)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# @require_permission decorator — decision mode via network
# ---------------------------------------------------------------------------

class TestRequirePermissionDecisionMode:
    def test_decision_mode_allows_when_server_returns_allowed(self):
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)
        client = MagicMock()
        client.check_permission.return_value = MagicMock(allowed=True)

        with _mock_settings(client=client):
            @require_permission("docs.write", client=client, mode="decision")
            def view(request):
                return HttpResponse("ok")

        resp = view(req)
        assert resp.status_code == 200

    def test_decision_mode_denies_on_network_error(self):
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)
        client = MagicMock()
        client.check_permission.side_effect = RuntimeError("network down")

        with _mock_settings(client=client):
            @require_permission("docs.write", client=client, mode="decision")
            def view(request):
                return HttpResponse("ok")

        resp = view(req)
        assert resp.status_code == 403

    def test_decision_mode_denies_when_server_denies(self):
        token = _make_jwt({"sub": "user-1"})
        req = _make_request(token)
        client = MagicMock()
        client.check_permission.return_value = MagicMock(allowed=False)

        with _mock_settings(client=client):
            @require_permission("docs.write", client=client, mode="decision")
            def view(request):
                return HttpResponse("ok")

        resp = view(req)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Integration: middleware + decorator together
# ---------------------------------------------------------------------------

class TestMiddlewareAndDecoratorIntegration:
    """Show that middleware sets hearth_token and the decorator uses it."""

    def test_middleware_propagates_token_to_decorator(self):
        token = _make_jwt({"permissions": ["reports.read"]})
        req = _make_request(token)

        with _mock_settings():
            mw = HearthDjangoMiddleware(None)  # get_response will be replaced

            @require_permission("reports.read")
            def protected_view(request):
                return HttpResponse("report data")

            # Simulate the middleware + view together.
            def get_response(request):
                return protected_view(request)

            mw.get_response = get_response

        resp = mw(req)
        assert resp.status_code == 200
        # Token was set on request by middleware.
        assert req.hearth_token == token

    def test_middleware_denies_before_view_when_global_gate_set(self):
        """When HEARTH_PERMISSION is configured, the middleware blocks before the view."""
        token = _make_jwt({"permissions": []})  # no permissions at all
        req = _make_request(token)
        inner = MagicMock(return_value=HttpResponse("ok"))

        with _mock_settings(permission="app.access"):
            mw = HearthDjangoMiddleware(inner)

        resp = mw(req)
        assert resp.status_code == 403
        inner.assert_not_called()
