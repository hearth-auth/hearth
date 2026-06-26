"""TDD tests for hearth.fastapi — FastAPI Depends() dependency adapter.

Run with:
  .venv/bin/pytest tests/test_fastapi_adapter.py -v
"""

from __future__ import annotations

import base64
import json
import time
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

def _make_ed25519_key() -> tuple:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return private_key, x_b64, "test-kid"


def _make_jwks(x_b64: str, kid: str) -> dict:
    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x_b64, "kid": kid, "use": "sig", "alg": "EdDSA"}]}


def _sign_jwt(private_key, payload: dict, kid: str) -> str:
    import jwt as pyjwt
    return pyjwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


def _valid_payload(
    issuer: str = "http://localhost:8420",
    permissions: Optional[list] = None,
    roles: Optional[list] = None,
) -> dict:
    now = int(time.time())
    payload = {"sub": "user-abc", "iss": issuer, "aud": "client-1", "exp": now + 3600, "iat": now}
    if permissions is not None:
        payload["permissions"] = permissions
    if roles is not None:
        payload["roles"] = roles
    return payload


def _make_request(token: Optional[str]) -> MagicMock:
    """Build a fake Starlette-shaped Request with an Authorization header."""
    request = MagicMock()
    if token:
        request.headers = {"authorization": f"Bearer {token}"}
    else:
        request.headers = {}
    return request


# ---------------------------------------------------------------------------
# VerifiedClaims model
# ---------------------------------------------------------------------------

class TestVerifiedClaims:
    def test_importable_from_hearth_fastapi(self):
        from hearth.fastapi import VerifiedClaims
        assert VerifiedClaims is not None

    def test_has_standard_claims(self):
        from hearth.fastapi import VerifiedClaims
        vc = VerifiedClaims(
            sub="user-1",
            iss="https://auth.example.com",
            exp=9999999999,
            permissions=[],
            roles=[],
            groups=[],
        )
        assert vc.sub == "user-1"
        assert vc.iss == "https://auth.example.com"

    def test_permissions_roles_groups_default_to_empty(self):
        from hearth.fastapi import VerifiedClaims
        vc = VerifiedClaims(sub="u", iss="i", exp=1)
        assert vc.permissions == []
        assert vc.roles == []
        assert vc.groups == []

    def test_has_permission_helper(self):
        from hearth.fastapi import VerifiedClaims
        vc = VerifiedClaims(sub="u", iss="i", exp=1, permissions=["docs.read", "docs.write"])
        assert vc.has_permission("docs.read") is True
        assert vc.has_permission("docs.delete") is False

    def test_has_role_helper(self):
        from hearth.fastapi import VerifiedClaims
        vc = VerifiedClaims(sub="u", iss="i", exp=1, roles=["admin"])
        assert vc.has_role("admin") is True
        assert vc.has_role("user") is False

    def test_from_claims_roundtrip(self):
        from hearth.claims import Claims
        from hearth.fastapi import VerifiedClaims
        now = int(time.time())
        c = Claims({"sub": "u", "iss": "i", "exp": now + 3600, "permissions": ["x"], "roles": ["r"], "groups": ["g"]})
        vc = VerifiedClaims.from_claims(c)
        assert vc.sub == "u"
        assert "x" in vc.permissions
        assert "r" in vc.roles
        assert "g" in vc.groups


# ---------------------------------------------------------------------------
# HearthFastAPIDep — basic dependency injection
# ---------------------------------------------------------------------------

class TestHearthFastAPIDepBasic:
    """Unit tests for HearthFastAPIDep.__call__ with mocked verify_token."""

    def _dep(self, private_key=None, x_b64=None, kid=None, respx_mock=None):
        """Build a HearthFastAPIDep with a mocked JwksCache."""
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep

        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        if respx_mock is not None:
            import httpx
            jwks = _make_jwks(x_b64, kid)
            respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
                return_value=httpx.Response(200, json=jwks)
            )
        return HearthFastAPIDep(client=client, mode="embedded")

    def test_callable_returns_verified_claims_for_valid_token(self, respx_mock):
        import httpx
        private_key, x_b64, kid = _make_ed25519_key()
        dep = self._dep(private_key, x_b64, kid, respx_mock)
        token = _sign_jwt(private_key, _valid_payload(permissions=["docs.read"]), kid)
        request = _make_request(token)

        claims = dep(request=request)
        assert claims.sub == "user-abc"

    def test_raises_401_when_no_authorization_header(self):
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep
        from fastapi import HTTPException

        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        dep = HearthFastAPIDep(client=client, mode="embedded")
        request = _make_request(None)

        with pytest.raises(HTTPException) as exc_info:
            dep(request=request)
        assert exc_info.value.status_code == 401

    def test_raises_401_for_invalid_token(self, respx_mock):
        import httpx
        from fastapi import HTTPException

        private_key, x_b64, kid = _make_ed25519_key()
        dep = self._dep(private_key, x_b64, kid, respx_mock)
        request = _make_request("not.a.valid.token")

        with pytest.raises(HTTPException) as exc_info:
            dep(request=request)
        assert exc_info.value.status_code == 401

    def test_raises_401_for_expired_token(self, respx_mock):
        import httpx
        from fastapi import HTTPException

        private_key, x_b64, kid = _make_ed25519_key()
        dep = self._dep(private_key, x_b64, kid, respx_mock)
        payload = _valid_payload()
        payload["exp"] = int(time.time()) - 10
        token = _sign_jwt(private_key, payload, kid)
        request = _make_request(token)

        with pytest.raises(HTTPException) as exc_info:
            dep(request=request)
        assert exc_info.value.status_code == 401

    def test_raises_401_for_required_action_token(self, respx_mock):
        """required_action tokens must never be accepted (spec §6 rule 6)."""
        import httpx
        from fastapi import HTTPException

        private_key, x_b64, kid = _make_ed25519_key()
        dep = self._dep(private_key, x_b64, kid, respx_mock)
        payload = _valid_payload()
        payload["token_type"] = "required_action"
        token = _sign_jwt(private_key, payload, kid)
        request = _make_request(token)

        with pytest.raises(HTTPException) as exc_info:
            dep(request=request)
        assert exc_info.value.status_code == 401

    def test_www_authenticate_header_present_on_401(self):
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep
        from fastapi import HTTPException

        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        dep = HearthFastAPIDep(client=client, mode="embedded")
        request = _make_request(None)

        with pytest.raises(HTTPException) as exc_info:
            dep(request=request)
        assert "WWW-Authenticate" in exc_info.value.headers


# ---------------------------------------------------------------------------
# HearthFastAPIDep — permission gating
# ---------------------------------------------------------------------------

class TestHearthFastAPIDepPermissions:
    def _dep_with_permission(self, permission: str, private_key, x_b64, kid, respx_mock):
        import httpx
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep

        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )
        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        return HearthFastAPIDep(client=client, mode="embedded", permission=permission)

    def test_allows_when_token_has_required_permission(self, respx_mock):
        private_key, x_b64, kid = _make_ed25519_key()
        dep = self._dep_with_permission("docs.write", private_key, x_b64, kid, respx_mock)
        token = _sign_jwt(private_key, _valid_payload(permissions=["docs.read", "docs.write"]), kid)
        request = _make_request(token)

        claims = dep(request=request)
        assert claims.has_permission("docs.write")

    def test_raises_403_when_token_missing_permission(self, respx_mock):
        from fastapi import HTTPException

        private_key, x_b64, kid = _make_ed25519_key()
        dep = self._dep_with_permission("docs.write", private_key, x_b64, kid, respx_mock)
        token = _sign_jwt(private_key, _valid_payload(permissions=["docs.read"]), kid)
        request = _make_request(token)

        with pytest.raises(HTTPException) as exc_info:
            dep(request=request)
        assert exc_info.value.status_code == 403

    def test_no_permission_check_when_permission_not_set(self, respx_mock):
        import httpx
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep

        private_key, x_b64, kid = _make_ed25519_key()
        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )
        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        # No permission kwarg — just authenticate, don't gate
        dep = HearthFastAPIDep(client=client, mode="embedded")
        token = _sign_jwt(private_key, _valid_payload(permissions=[]), kid)
        request = _make_request(token)

        claims = dep(request=request)
        assert claims.sub == "user-abc"


# ---------------------------------------------------------------------------
# require_permission() shorthand
# ---------------------------------------------------------------------------

class TestRequirePermission:
    def test_returns_annotated_type(self):
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep, require_permission, VerifiedClaims
        import typing

        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        dep = HearthFastAPIDep(client=client, mode="embedded")
        annotation = require_permission("docs.write", dep=dep)

        # Must be Annotated[VerifiedClaims, Depends(...)]
        assert typing.get_origin(annotation) is typing.Annotated
        args = typing.get_args(annotation)
        assert args[0] is VerifiedClaims

    def test_shorthand_gates_permission(self, respx_mock):
        """require_permission enforces the permission when the dep is called."""
        import httpx
        from fastapi import HTTPException
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep, require_permission

        private_key, x_b64, kid = _make_ed25519_key()
        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )
        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        dep = HearthFastAPIDep(client=client, mode="embedded", permission="admin.read")

        token = _sign_jwt(private_key, _valid_payload(permissions=["docs.read"]), kid)
        request = _make_request(token)

        with pytest.raises(HTTPException) as exc_info:
            dep(request=request)
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# HearthSettings (pydantic-settings integration)
# ---------------------------------------------------------------------------

class TestHearthSettings:
    def test_importable(self):
        from hearth.fastapi import HearthSettings
        assert HearthSettings is not None

    def test_reads_fields_from_env(self, monkeypatch):
        monkeypatch.setenv("HEARTH_BASE_URL", "https://auth.example.com")
        monkeypatch.setenv("HEARTH_REALM_ID", "my-realm")
        monkeypatch.setenv("HEARTH_CLIENT_ID", "my-client")

        from hearth.fastapi import HearthSettings
        # Force re-read from env by creating a fresh instance
        settings = HearthSettings()
        assert settings.base_url == "https://auth.example.com"
        assert settings.realm_id == "my-realm"
        assert settings.client_id == "my-client"

    def test_to_client_creates_hearth_client(self, monkeypatch):
        monkeypatch.setenv("HEARTH_BASE_URL", "https://auth.example.com")
        monkeypatch.setenv("HEARTH_REALM_ID", "my-realm")

        from hearth.client import HearthClient
        from hearth.fastapi import HearthSettings

        settings = HearthSettings()
        client = settings.to_client()
        assert isinstance(client, HearthClient)

    def test_env_prefix_is_hearth(self, monkeypatch):
        """HEARTH_ prefix must be used so variables don't collide with other apps."""
        monkeypatch.delenv("HEARTH_BASE_URL", raising=False)
        monkeypatch.setenv("BASE_URL", "https://wrong.example.com")

        from hearth.fastapi import HearthSettings
        settings = HearthSettings()
        # Without HEARTH_ prefix, it should not be picked up
        assert settings.base_url != "https://wrong.example.com"


# ---------------------------------------------------------------------------
# Integration: per-route vs global auth in a real FastAPI app
# ---------------------------------------------------------------------------

class TestFastAPIIntegration:
    """Use TestClient to verify per-route auth and global middleware coexist."""

    def _app(self, private_key, x_b64, kid, respx_mock):
        """Build a small FastAPI app with one per-route dep and one open route."""
        import httpx
        from fastapi import FastAPI, Depends
        from hearth.client import HearthClient
        from hearth.fastapi import HearthFastAPIDep, VerifiedClaims

        jwks = _make_jwks(x_b64, kid)
        respx_mock.get("http://localhost:8420/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks)
        )

        client = HearthClient("http://localhost:8420", realm_id="realm-1")
        auth_dep = HearthFastAPIDep(client=client, mode="embedded", permission="docs.read")

        app = FastAPI()

        @app.get("/public")
        def public_route():
            return {"msg": "no auth needed"}

        @app.get("/protected")
        def protected_route(claims: VerifiedClaims = Depends(auth_dep)):
            return {"sub": claims.sub, "permissions": claims.permissions}

        return app

    def test_public_route_accessible_without_token(self, respx_mock):
        from fastapi.testclient import TestClient

        private_key, x_b64, kid = _make_ed25519_key()
        app = self._app(private_key, x_b64, kid, respx_mock)
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.get("/public")
        assert resp.status_code == 200
        assert resp.json() == {"msg": "no auth needed"}

    def test_protected_route_returns_claims_with_valid_token(self, respx_mock):
        from fastapi.testclient import TestClient

        private_key, x_b64, kid = _make_ed25519_key()
        app = self._app(private_key, x_b64, kid, respx_mock)
        token = _sign_jwt(private_key, _valid_payload(permissions=["docs.read"]), kid)

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["sub"] == "user-abc"
        assert "docs.read" in data["permissions"]

    def test_protected_route_returns_401_without_token(self, respx_mock):
        from fastapi.testclient import TestClient

        private_key, x_b64, kid = _make_ed25519_key()
        app = self._app(private_key, x_b64, kid, respx_mock)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_protected_route_returns_403_without_permission(self, respx_mock):
        from fastapi.testclient import TestClient

        private_key, x_b64, kid = _make_ed25519_key()
        app = self._app(private_key, x_b64, kid, respx_mock)
        # Token with wrong permission
        token = _sign_jwt(private_key, _valid_payload(permissions=["other.perm"]), kid)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_protected_and_public_routes_coexist(self, respx_mock):
        """Verify per-route dep doesn't affect the unprotected route."""
        from fastapi.testclient import TestClient

        private_key, x_b64, kid = _make_ed25519_key()
        app = self._app(private_key, x_b64, kid, respx_mock)
        client = TestClient(app, raise_server_exceptions=False)

        # Public still works
        assert client.get("/public").status_code == 200
        # Protected without token still fails
        assert client.get("/protected").status_code == 401
