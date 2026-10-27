"""The embedded-mode authorization gates must verify a token before trusting it.

Every gate under test here reads the ``permissions`` claim to decide whether a
request proceeds.  Reading that claim out of an unverified JWT means an
unauthenticated attacker can mint ``{"alg":"none"}`` with
``permissions: ["admin.write"]`` and be let through, so each gate is exercised
against exactly that forgery as well as against a properly signed token.

Run with:
  .venv/bin/pytest tests/test_middleware_verification.py -v
"""

from __future__ import annotations

import asyncio
import base64
import json
import time

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hearth.client import HearthClient
from hearth.middleware import RequirePermissionMiddleware, WsgiPermissionMiddleware

BASE_URL = "http://localhost:8420"
JWKS_URL = f"{BASE_URL}/.well-known/jwks.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key() -> tuple:
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return private_key, x_b64, "test-kid"


def _jwks(x_b64: str, kid: str) -> dict:
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x_b64,
                "kid": kid,
                "use": "sig",
                "alg": "EdDSA",
            }
        ]
    }


def _payload(permissions: list | None = None, **extra) -> dict:
    now = int(time.time())
    body = {
        "sub": "user-abc",
        "iss": BASE_URL,
        "aud": "hearth",
        "exp": now + 3600,
        "iat": now,
    }
    if permissions is not None:
        body["permissions"] = permissions
    body.update(extra)
    return body


def _sign(private_key, payload: dict, kid: str) -> str:
    import jwt as pyjwt

    return pyjwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def unsigned_admin_token() -> str:
    """An ``alg: none`` forgery claiming ``admin.write``. Costs the attacker nothing."""
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(_payload(permissions=['admin.write']))}."


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------


async def _call_asgi(mw, token: str | None) -> int:
    """Drive an ASGI middleware once and return the response status."""
    status, _ = await _asgi_response(mw, token)
    return status


async def _asgi_response(mw, token: str | None) -> tuple[int, dict[str, str]]:
    """Drive an ASGI middleware once; return the status and the headers."""
    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    scope = {"type": "http", "method": "GET", "path": "/", "headers": headers}
    status = {"code": None, "downstream": False, "headers": {}}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            status["code"] = message["status"]
            status["headers"] = {
                bytes(k).decode().lower(): bytes(v).decode()
                for k, v in message.get("headers", [])
            }

    async def downstream(scope_, receive_, send_):
        status["downstream"] = True
        await send_({"type": "http.response.start", "status": 200, "headers": []})
        await send_({"type": "http.response.body", "body": b"ok"})

    mw._app = downstream
    await mw(scope, receive, send)
    return status["code"], status["headers"]


@respx.mock
def test_asgi_embedded_rejects_unsigned_token():
    _, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    mw = RequirePermissionMiddleware(
        None, client=client, permission="admin.write", mode="embedded"
    )
    status, headers = asyncio.run(_asgi_response(mw, unsigned_admin_token()))
    assert status == 401, "ASGI embedded gate admitted an alg:none forgery"
    assert headers["www-authenticate"] == 'Bearer realm="hearth", error="invalid_token"'


@respx.mock
def test_asgi_embedded_rejects_wrong_key_token():
    signing_key, _, kid = _make_key()  # the attacker's key
    _, x_b64, _ = _make_key()  # the realm's published key
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    token = _sign(signing_key, _payload(permissions=["admin.write"]), kid)
    mw = RequirePermissionMiddleware(
        None, client=client, permission="admin.write", mode="embedded"
    )
    assert asyncio.run(_call_asgi(mw, token)) == 401


@respx.mock
def test_asgi_embedded_accepts_signed_token():
    signing_key, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    token = _sign(signing_key, _payload(permissions=["admin.write"]), kid)
    mw = RequirePermissionMiddleware(
        None, client=client, permission="admin.write", mode="embedded"
    )
    assert asyncio.run(_call_asgi(mw, token)) == 200


@respx.mock
def test_asgi_embedded_denies_signed_token_without_the_permission():
    signing_key, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    token = _sign(signing_key, _payload(permissions=["docs.read"]), kid)
    mw = RequirePermissionMiddleware(
        None, client=client, permission="admin.write", mode="embedded"
    )
    assert asyncio.run(_call_asgi(mw, token)) == 403


# ---------------------------------------------------------------------------
# WSGI middleware
# ---------------------------------------------------------------------------


def _call_wsgi(mw, token: str | None) -> str:
    status, _ = _wsgi_response(mw, token)
    return status


def _wsgi_response(mw, token: str | None) -> tuple[str, dict[str, str]]:
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = {k.lower(): v for k, v in headers}

    def downstream(environ, start_response_):
        start_response_("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    mw._app = downstream
    environ = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
    mw(environ, start_response)
    return captured["status"], captured["headers"]


@respx.mock
def test_wsgi_embedded_rejects_unsigned_token():
    _, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    mw = WsgiPermissionMiddleware(
        None, client=client, permission="admin.write", mode="embedded"
    )
    status, headers = _wsgi_response(mw, unsigned_admin_token())
    assert status.startswith("401"), "WSGI embedded gate admitted an alg:none forgery"
    assert headers["www-authenticate"] == 'Bearer realm="hearth", error="invalid_token"'


@respx.mock
def test_wsgi_embedded_accepts_signed_token():
    signing_key, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    token = _sign(signing_key, _payload(permissions=["admin.write"]), kid)
    mw = WsgiPermissionMiddleware(
        None, client=client, permission="admin.write", mode="embedded"
    )
    assert _call_wsgi(mw, token).startswith("200")


# ---------------------------------------------------------------------------
# Django middleware and @require_permission
# ---------------------------------------------------------------------------


@respx.mock
def test_django_sync_check_rejects_unsigned_token():
    from hearth.django import _sync_check

    _, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    from hearth.middleware import _Unauthenticated

    with pytest.raises(_Unauthenticated):
        _sync_check(client, unsigned_admin_token(), "admin.write", "embedded")


@respx.mock
def test_django_sync_check_accepts_signed_token():
    from hearth.django import _sync_check

    signing_key, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    token = _sign(signing_key, _payload(permissions=["admin.write"]), kid)
    assert _sync_check(client, token, "admin.write", "embedded") is True


def test_django_sync_check_without_a_client_is_fail_closed():
    """Embedded mode cannot verify without a client, so it must deny."""
    from hearth.django import _sync_check

    assert _sync_check(None, unsigned_admin_token(), "admin.write", "embedded") is False


# ---------------------------------------------------------------------------
# 25.2 — nbf on the verify path
# ---------------------------------------------------------------------------


@respx.mock
def test_verify_token_rejects_not_yet_valid_token():
    from hearth.errors import TokenNotYetValidError

    signing_key, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    token = _sign(signing_key, _payload(nbf=int(time.time()) + 3600), kid)
    with pytest.raises(TokenNotYetValidError):
        client.verify_token(token)


@respx.mock
def test_verify_token_accepts_past_nbf():
    signing_key, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")

    token = _sign(signing_key, _payload(nbf=int(time.time()) - 3600), kid)
    assert client.verify_token(token).subject() == "user-abc"


# ---------------------------------------------------------------------------
# 401 vs 403 (sdk-support-contract "Resource-server middleware", #634)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["embedded", "introspection", "decision"])
def test_asgi_answers_401_with_a_bearer_challenge_without_a_token(mode):
    mw = RequirePermissionMiddleware(
        None,
        client=HearthClient(BASE_URL, realm_id="r1"),
        permission="admin.write",
        mode=mode,
        client_id="cid",
    )
    status, headers = asyncio.run(_asgi_response(mw, None))
    assert status == 401
    assert headers["www-authenticate"] == 'Bearer realm="hearth"'


@pytest.mark.parametrize("mode", ["embedded", "introspection", "decision"])
def test_wsgi_answers_401_with_a_bearer_challenge_without_a_token(mode):
    mw = WsgiPermissionMiddleware(
        None,
        client=HearthClient(BASE_URL, realm_id="r1"),
        permission="admin.write",
        mode=mode,
        client_id="cid",
    )
    status, headers = _wsgi_response(mw, None)
    assert status.startswith("401")
    assert headers["www-authenticate"] == 'Bearer realm="hearth"'


@respx.mock
def test_introspection_answers_401_for_an_inactive_token():
    respx.post(f"{BASE_URL}/realms/r1/introspect").mock(
        return_value=httpx.Response(200, json={"active": False})
    )
    mw = WsgiPermissionMiddleware(
        None,
        client=HearthClient(BASE_URL, realm_id="r1"),
        permission="admin.write",
        mode="introspection",
        client_id="cid",
        client_secret="secret",
    )
    status, headers = _wsgi_response(mw, "opaque-or-revoked")
    assert status.startswith("401")
    assert headers["www-authenticate"] == 'Bearer realm="hearth", error="invalid_token"'


@respx.mock
def test_a_valid_token_without_the_permission_is_403_without_a_challenge():
    signing_key, x_b64, kid = _make_key()
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(x_b64, kid)))
    client = HearthClient(BASE_URL, realm_id="r1")
    token = _sign(signing_key, _payload(permissions=["docs.read"]), kid)

    mw = WsgiPermissionMiddleware(
        None, client=client, permission="admin.write", mode="embedded"
    )
    status, headers = _wsgi_response(mw, token)
    assert status.startswith("403")
    assert "www-authenticate" not in headers
