"""Tests for check_permission(), introspect(), and mode-aware middleware.

TDD: written before implementation. Run with `pytest sdks/python/tests/`.
"""

from __future__ import annotations

import base64
import json
from typing import Optional
from unittest.mock import MagicMock, patch

import httpx
import pytest

from hearth.client import HearthClient
from hearth.errors import AuthorizationModeMismatchError, HearthError
from hearth.types import (
    AccessTokenAuthorizationMode,
    CheckPermissionResponse,
    IntrospectResponse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict) -> str:
    """Build a minimal unsigned JWT for testing local-decode paths."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."


# ---------------------------------------------------------------------------
# check_permission — decision-mode network call
# ---------------------------------------------------------------------------

class TestCheckPermission:
    def _client(self) -> HearthClient:
        return HearthClient("http://localhost:8420", realm_id="realm-1")

    def test_allowed_true_when_server_returns_allowed(self, respx_mock):
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        c = self._client()
        result = c.check_permission("tok", "docs.write")
        assert result.allowed is True

    def test_allowed_false_when_server_denies(self, respx_mock):
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            return_value=httpx.Response(200, json={"allowed": False})
        )
        c = self._client()
        result = c.check_permission("tok", "docs.write")
        assert result.allowed is False

    def test_fail_closed_on_http_error(self, respx_mock):
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            return_value=httpx.Response(503, text="unavailable")
        )
        c = self._client()
        result = c.check_permission("tok", "docs.write")
        assert result.allowed is False

    def test_fail_closed_on_network_error(self, respx_mock):
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            side_effect=httpx.ConnectError("down")
        )
        c = self._client()
        result = c.check_permission("tok", "docs.write")
        assert result.allowed is False

    def test_forwards_organization_id(self, respx_mock):
        captured = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"allowed": True})

        respx_mock.post("http://localhost:8420/oauth/authorize").mock(side_effect=handler)
        c = self._client()
        c.check_permission("tok", "docs.write", organization_id="org-abc")
        assert captured["body"].get("organization_id") == "org-abc"

    def test_forwards_resource(self, respx_mock):
        captured = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"allowed": True})

        respx_mock.post("http://localhost:8420/oauth/authorize").mock(side_effect=handler)
        c = self._client()
        c.check_permission("tok", "docs.write", resource="urn:docs:1")
        assert captured["body"].get("resource") == "urn:docs:1"


# ---------------------------------------------------------------------------
# introspect — RFC 7662 introspection
# ---------------------------------------------------------------------------

class TestIntrospect:
    def _client(self) -> HearthClient:
        return HearthClient("http://localhost:8420", realm_id="realm-1")

    def test_active_token(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/introspect").mock(
            return_value=httpx.Response(200, json={
                "active": True,
                "sub": "user_abc",
                "mode": "introspection",
                "permissions": ["docs.read"],
            })
        )
        c = self._client()
        result = c.introspect("tok", client_id="cid", client_secret="sec")
        assert result.active is True
        assert result.sub == "user_abc"
        assert result.mode == "introspection"
        assert "docs.read" in (result.permissions or [])

    def test_inactive_token(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/introspect").mock(
            return_value=httpx.Response(200, json={"active": False})
        )
        c = self._client()
        result = c.introspect("tok", client_id="cid")
        assert result.active is False

    def test_raises_on_server_error(self, respx_mock):
        respx_mock.post("http://localhost:8420/realms/realm-1/introspect").mock(
            return_value=httpx.Response(401, text="unauthorized")
        )
        c = self._client()
        with pytest.raises(HearthError):
            c.introspect("tok", client_id="cid")


# ---------------------------------------------------------------------------
# WSGI middleware — sync, covers all three modes
# ---------------------------------------------------------------------------

class TestWsgiMiddleware:
    """Tests for WsgiPermissionMiddleware."""

    def _client(self) -> HearthClient:
        return HearthClient("http://localhost:8420", realm_id="realm-1")

    def _environ(self, token: Optional[str] = None) -> dict:
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/data"}
        if token:
            environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return environ

    def _start_response(self):
        calls = []
        def sr(status, headers):
            calls.append((status, headers))
        sr.calls = calls
        return sr

    # -- embedded mode --

    def test_embedded_allows_valid_permission(self):
        from hearth.middleware import WsgiPermissionMiddleware
        token = _make_jwt({"permissions": ["docs.write"]})
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        sr = self._start_response()
        environ = self._environ(token)
        result = mw(environ, sr)
        assert result == [b"ok"]
        inner.assert_called_once()

    def test_embedded_denies_missing_permission(self):
        from hearth.middleware import WsgiPermissionMiddleware
        token = _make_jwt({"permissions": ["other.perm"]})
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        sr = self._start_response()
        mw(self._environ(token), sr)
        assert sr.calls[0][0].startswith("403")
        inner.assert_not_called()

    def test_embedded_denies_no_token(self):
        from hearth.middleware import WsgiPermissionMiddleware
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        sr = self._start_response()
        mw(self._environ(None), sr)
        assert sr.calls[0][0].startswith("403")

    def test_embedded_does_not_fallback_when_permissions_absent(self):
        """Absence of permissions claim must NOT trigger mode fallback — stay embedded, deny."""
        from hearth.middleware import WsgiPermissionMiddleware
        token = _make_jwt({"sub": "user-1"})  # no permissions claim
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        sr = self._start_response()
        mw(self._environ(token), sr)
        assert sr.calls[0][0].startswith("403")
        inner.assert_not_called()

    # -- decision mode --

    def test_decision_allows_when_server_returns_allowed(self, respx_mock):
        from hearth.middleware import WsgiPermissionMiddleware
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="decision"
        )
        sr = self._start_response()
        mw(self._environ("sometoken"), sr)
        inner.assert_called_once()

    def test_decision_denies_on_network_error(self, respx_mock):
        from hearth.middleware import WsgiPermissionMiddleware
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            side_effect=httpx.ConnectError("down")
        )
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="decision"
        )
        sr = self._start_response()
        mw(self._environ("sometoken"), sr)
        assert sr.calls[0][0].startswith("403")
        inner.assert_not_called()

    # -- introspection mode --

    def test_introspection_allows_correct_mode_echo(self, respx_mock):
        from hearth.middleware import WsgiPermissionMiddleware
        respx_mock.post("http://localhost:8420/realms/realm-1/introspect").mock(
            return_value=httpx.Response(200, json={
                "active": True,
                "mode": "introspection",
                "permissions": ["docs.write"],
            })
        )
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner,
            client=self._client(),
            permission="docs.write",
            mode="introspection",
            client_id="cid",
            client_secret="sec",
        )
        sr = self._start_response()
        mw(self._environ("tok"), sr)
        inner.assert_called_once()

    def test_introspection_denies_mode_mismatch(self, respx_mock):
        """Server echoes 'embedded' but we expected 'introspection' → deny."""
        from hearth.middleware import WsgiPermissionMiddleware
        respx_mock.post("http://localhost:8420/realms/realm-1/introspect").mock(
            return_value=httpx.Response(200, json={
                "active": True,
                "mode": "embedded",  # mismatch
                "permissions": ["docs.write"],
            })
        )
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner,
            client=self._client(),
            permission="docs.write",
            mode="introspection",
            client_id="cid",
        )
        sr = self._start_response()
        mw(self._environ("tok"), sr)
        assert sr.calls[0][0].startswith("403")
        inner.assert_not_called()

    def test_introspection_denies_inactive_token(self, respx_mock):
        from hearth.middleware import WsgiPermissionMiddleware
        respx_mock.post("http://localhost:8420/realms/realm-1/introspect").mock(
            return_value=httpx.Response(200, json={"active": False})
        )
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner,
            client=self._client(),
            permission="docs.write",
            mode="introspection",
            client_id="cid",
        )
        sr = self._start_response()
        mw(self._environ("tok"), sr)
        assert sr.calls[0][0].startswith("403")


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------

class TestAsgiMiddleware:
    """Tests for RequirePermissionMiddleware (ASGI)."""

    def _client(self) -> HearthClient:
        return HearthClient("http://localhost:8420", realm_id="realm-1")

    def _scope(self, token: Optional[str] = None) -> dict:
        headers = []
        if token:
            headers.append((b"authorization", f"Bearer {token}".encode()))
        return {"type": "http", "headers": headers}

    async def _collect_response(self, app, scope) -> dict:
        messages = []

        async def receive():
            return {"type": "http.request"}

        async def send(msg):
            messages.append(msg)

        await app(scope, receive, send)
        return {
            "status": messages[0]["status"] if messages else None,
            "body": messages[1]["body"] if len(messages) > 1 else b"",
        }

    @pytest.mark.asyncio
    async def test_embedded_allows_valid_permission(self):
        from hearth.middleware import RequirePermissionMiddleware
        token = _make_jwt({"permissions": ["docs.write"]})

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        resp = await self._collect_response(mw, self._scope(token))
        assert resp["status"] == 200

    @pytest.mark.asyncio
    async def test_embedded_denies_missing_permission(self):
        from hearth.middleware import RequirePermissionMiddleware
        token = _make_jwt({"permissions": []})

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        resp = await self._collect_response(mw, self._scope(token))
        assert resp["status"] == 403

    @pytest.mark.asyncio
    async def test_embedded_no_fallback_when_permissions_claim_absent(self):
        """Design constraint: absence of permissions claim must not switch mode."""
        from hearth.middleware import RequirePermissionMiddleware
        token = _make_jwt({"sub": "u1"})  # no permissions claim

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        resp = await self._collect_response(mw, self._scope(token))
        assert resp["status"] == 403

    @pytest.mark.asyncio
    async def test_decision_allows_when_server_allowed(self, respx_mock):
        from hearth.middleware import RequirePermissionMiddleware
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="decision"
        )
        resp = await self._collect_response(mw, self._scope("tok"))
        assert resp["status"] == 200

    @pytest.mark.asyncio
    async def test_decision_fail_closed_on_network_error(self, respx_mock):
        from hearth.middleware import RequirePermissionMiddleware
        respx_mock.post("http://localhost:8420/oauth/authorize").mock(
            side_effect=httpx.ConnectError("down")
        )

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="decision"
        )
        resp = await self._collect_response(mw, self._scope("tok"))
        assert resp["status"] == 403

    @pytest.mark.asyncio
    async def test_introspection_denies_mode_mismatch(self, respx_mock):
        from hearth.middleware import RequirePermissionMiddleware
        respx_mock.post("http://localhost:8420/realms/realm-1/introspect").mock(
            return_value=httpx.Response(200, json={
                "active": True,
                "mode": "embedded",  # mismatch: we expect introspection
                "permissions": ["docs.write"],
            })
        )

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner,
            client=self._client(),
            permission="docs.write",
            mode="introspection",
            client_id="cid",
        )
        resp = await self._collect_response(mw, self._scope("tok"))
        assert resp["status"] == 403

    @pytest.mark.asyncio
    async def test_non_http_scope_passes_through(self):
        from hearth.middleware import RequirePermissionMiddleware

        called = []

        async def inner(scope, receive, send):
            called.append(True)

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        # WebSocket scope — should pass through without auth check
        await mw({"type": "websocket", "headers": []}, None, None)
        assert called == [True]
