"""Realm-path endpoints carry no ``X-Realm-ID`` header.

``/realms/{realm}/...`` names the realm in the path. The server refuses a
request whose ``X-Realm-ID`` does not resolve to that same realm
(``400 realm_mismatch``), and the client's ``realm_id`` is the realm *name*
here, not its UUID. Found by the shared conformance harness: every
``client_credentials()`` call against a live server answered 400.
"""

from __future__ import annotations

import httpx
import pytest

BASE = "http://localhost:8420"
TOKEN_OK = {"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 60}


def _client():
    from hearth.client import HearthClient

    return HearthClient(
        BASE, realm_id="realm-1", client_id="svc-client", client_secret="secret"
    )


def _capture(respx_mock, path: str, body: dict) -> dict:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = request.headers
        return httpx.Response(200, json=body)

    respx_mock.post(f"{BASE}{path}").mock(side_effect=handler)
    return seen


@pytest.mark.parametrize(
    ("path", "body", "call"),
    [
        ("/realms/realm-1/token", TOKEN_OK, lambda c: c.client_credentials()),
        ("/realms/realm-1/token", TOKEN_OK, lambda c: c.poll_device_token("dc")),
        ("/realms/realm-1/token", TOKEN_OK, lambda c: c.exchange_magic_link("ml")),
        (
            "/realms/realm-1/device/authorize",
            {
                "device_code": "dc",
                "user_code": "UC",
                "verification_uri": f"{BASE}/device",
                "expires_in": 600,
                "interval": 5,
            },
            lambda c: c.start_device_flow(),
        ),
        (
            "/realms/realm-1/introspect",
            {"active": False},
            lambda c: c.introspect("tok", client_id="cid", client_secret="sec"),
        ),
    ],
)
def test_realm_path_request_has_no_realm_header(respx_mock, path, body, call):
    seen = _capture(respx_mock, path, body)
    call(_client())
    assert "x-realm-id" not in seen["headers"]
