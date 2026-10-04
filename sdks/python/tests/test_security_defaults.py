"""sdk-security-defaults: the audience check is always on, and the RBAC
predicates verify the token before they read a claim.

Scenarios: openspec sdk-support-contract, "JWT validation steps" (check 4)
and "Claim checks verify the token signature".
"""

from __future__ import annotations

import base64
import json

import pytest

from hearth import HearthClient
from hearth.client import DEFAULT_AUDIENCE
from hearth.errors import TokenAudienceError

from .signing import install_test_key, sign_jwt, unsigned_jwt

ISSUER = "http://localhost:8420"


def _client(**kwargs) -> HearthClient:
    return install_test_key(HearthClient(ISSUER, realm_id="r1", **kwargs))


def _tamper(token: str, **changes) -> str:
    """Edit the payload of a signed token, keeping the original signature."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims.update(changes)
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{forged}.{signature}"


class TestAudienceDefault:
    def test_default_audience_is_hearth(self):
        assert DEFAULT_AUDIENCE == "hearth"

    def test_rejects_token_for_another_api(self):
        token = sign_jwt({"sub": "u1", "aud": "other-api"})
        with pytest.raises(TokenAudienceError) as exc:
            _client().verify_token(token)
        assert exc.value.expected == "hearth"

    def test_rejects_token_without_aud(self):
        token = sign_jwt({"sub": "u1", "aud": None})
        with pytest.raises(TokenAudienceError):
            _client().verify_token(token)

    def test_accepts_token_for_hearth(self):
        token = sign_jwt({"sub": "u1", "aud": "hearth"})
        assert _client().verify_token(token).subject() == "u1"

    def test_protected_resource_sets_its_audience(self):
        client = _client(audience="https://api.example.com")
        ok = sign_jwt({"sub": "u1", "aud": "https://api.example.com"})
        assert client.verify_token(ok).subject() == "u1"
        with pytest.raises(TokenAudienceError):
            client.verify_token(sign_jwt({"sub": "u1", "aud": "hearth"}))

    def test_client_id_is_not_the_audience(self):
        client = _client(client_id="my-client")
        with pytest.raises(TokenAudienceError):
            client.verify_token(sign_jwt({"sub": "u1", "aud": "my-client"}))

    def test_per_call_audience_overrides(self):
        token = sign_jwt({"sub": "u1", "aud": "billing"})
        assert _client().verify_token(token, audience="billing").subject() == "u1"


class TestPredicatesVerify:
    def _signed(self, **claims) -> str:
        return sign_jwt({"sub": "u1", "aud": "hearth", **claims})

    def test_valid_token_grants(self):
        token = self._signed(
            permissions=["docs.read"], roles=["admin"], groups=["eng"], oid="org_1"
        )
        client = _client()
        assert client.has_permission(token, "docs.read") is True
        assert client.has_role(token, "admin") is True
        assert client.in_group(token, "eng") is True
        assert client.in_org(token, "org_1") is True

    def test_tampered_permissions_claim_is_not_held(self):
        token = _tamper(
            self._signed(permissions=["docs.read"]),
            permissions=["docs.read", "admin.write"],
        )
        assert _client().has_permission(token, "admin.write") is False

    def test_tampered_role_group_org_are_not_held(self):
        token = _tamper(self._signed(), roles=["admin"], groups=["eng"], oid="org_1")
        client = _client()
        assert client.has_role(token, "admin") is False
        assert client.in_group(token, "eng") is False
        assert client.in_org(token, "org_1") is False

    def test_unsigned_token_grants_nothing(self):
        token = unsigned_jwt(
            {"sub": "u1", "iss": ISSUER, "aud": "hearth", "permissions": ["x"]}
        )
        assert _client().has_permission(token, "x") is False

    def test_wrong_audience_grants_nothing(self):
        token = sign_jwt({"sub": "u1", "aud": "other-api", "permissions": ["x"]})
        assert _client().has_permission(token, "x") is False

    def test_predicates_are_instance_methods(self):
        token = self._signed(permissions=["x"])
        with pytest.raises(TypeError):
            HearthClient.has_permission(token, "x")  # type: ignore[call-arg]
