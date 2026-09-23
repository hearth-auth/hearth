"""HearthClient.register_client — ``POST /clients`` is an admin call.

The server answers ``401 missing authorization header`` without a bearer
token, deserializes the proto ``RegisterClientRequest`` (``client_name``, an
unknown ``name`` key is a ``422``), and replies ``201 Created`` with the proto
``OAuthClient`` shape (``client_id`` / ``client_name``).
"""

from __future__ import annotations

import json

import httpx
import pytest

from hearth import HearthClient, HearthError, RegisterClientRequest

BASE = "http://localhost:8420"

CREATED = {
    "client_id": "c-1",
    "client_name": "My App",
    "redirect_uris": ["https://app.example.com/cb"],
    "created_at": 1,
    "grant_types": ["authorization_code"],
}


def _req() -> RegisterClientRequest:
    return RegisterClientRequest(name="My App", redirect_uris=["https://app.example.com/cb"])


def test_register_client_sends_configured_token(respx_mock):
    route = respx_mock.post(f"{BASE}/clients").mock(
        return_value=httpx.Response(201, json=CREATED)
    )
    client = HearthClient(BASE, "realm-1", access_token="admin-token-xyz")

    created = client.register_client(_req())

    assert route.called
    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "Bearer admin-token-xyz"
    assert sent.headers["X-Realm-ID"] == "realm-1"
    body = json.loads(sent.content)
    assert body["client_name"] == "My App"
    assert "name" not in body
    assert created.id == "c-1"
    assert created.name == "My App"
    assert created.redirect_uris == ["https://app.example.com/cb"]


def test_register_client_explicit_token_overrides_configured(respx_mock):
    route = respx_mock.post(f"{BASE}/clients").mock(
        return_value=httpx.Response(201, json=CREATED)
    )
    client = HearthClient(BASE, "realm-1", access_token="configured")

    client.register_client(_req(), access_token="explicit")

    assert route.calls.last.request.headers["Authorization"] == "Bearer explicit"


def test_register_client_without_any_token_fails_before_the_network(respx_mock):
    route = respx_mock.post(f"{BASE}/clients").mock(
        return_value=httpx.Response(201, json=CREATED)
    )
    client = HearthClient(BASE, "realm-1")

    with pytest.raises(HearthError) as exc:
        client.register_client(_req())

    assert exc.value.status_code == 401
    assert not route.called


def test_register_client_surfaces_server_error(respx_mock):
    respx_mock.post(f"{BASE}/clients").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )
    client = HearthClient(BASE, "realm-1", access_token="weak")

    with pytest.raises(HearthError) as exc:
        client.register_client(_req())

    assert exc.value.status_code == 403
