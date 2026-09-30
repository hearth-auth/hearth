"""AdminClient create/update client — the wire shape ``/admin/applications`` accepts.

``POST /admin/applications`` deserializes the proto ``RegisterClientRequest``
(the same body as ``POST /clients``): the name key is ``client_name`` and an
unknown ``name`` key is a ``422``. ``PATCH /admin/applications/{id}`` reads
``client_name`` too, but ignores unknown keys, so a ``name`` key answers
``200`` and renames nothing. Every client route answers with the proto
``OAuthClient`` shape (``client_id`` / ``client_name``).
"""

from __future__ import annotations

import json

import httpx

from hearth.admin import AdminClient
from hearth.types import CreateClientRequest, UpdateClientRequest

BASE = "http://localhost:8420"

SERVER_CLIENT = {
    "client_id": "c-1",
    "client_name": "My App",
    "redirect_uris": ["https://app.example.com/cb"],
    "created_at": 1,
    "is_confidential": True,
    "grant_types": ["authorization_code"],
}


def _admin() -> AdminClient:
    return AdminClient(BASE, "admin-token", "realm-1")


def test_create_client_sends_client_name_not_name(respx_mock):
    route = respx_mock.post(f"{BASE}/admin/applications").mock(
        return_value=httpx.Response(201, json=SERVER_CLIENT)
    )

    created = _admin().create_client(
        CreateClientRequest(name="My App", redirect_uris=["https://app.example.com/cb"])
    )

    body = json.loads(route.calls.last.request.content)
    assert body == {
        "client_name": "My App",
        "redirect_uris": ["https://app.example.com/cb"],
    }
    assert created.id == "c-1"
    assert created.name == "My App"


def test_create_client_sends_trust_level_as_proto_enum_name(respx_mock):
    # The proto body's `trust_level` is the `ClientTrustLevel` enum; the
    # server rejects the snake_case spelling `first_party` with a 422.
    route = respx_mock.post(f"{BASE}/admin/applications").mock(
        return_value=httpx.Response(201, json=SERVER_CLIENT)
    )

    _admin().create_client(
        CreateClientRequest(name="My App", trust_level="first_party")
    )

    body = json.loads(route.calls.last.request.content)
    assert body["trust_level"] == "CLIENT_TRUST_LEVEL_FIRST_PARTY"


def test_update_client_sends_client_name_not_name(respx_mock):
    route = respx_mock.patch(f"{BASE}/admin/applications/c-1").mock(
        return_value=httpx.Response(
            200, json={**SERVER_CLIENT, "client_name": "Renamed"}
        )
    )

    updated = _admin().update_client("c-1", UpdateClientRequest(name="Renamed"))

    body = json.loads(route.calls.last.request.content)
    assert body == {"client_name": "Renamed"}
    assert updated.id == "c-1"
    assert updated.name == "Renamed"


def test_update_client_keeps_snake_case_trust_level(respx_mock):
    # PATCH reads `trust_level` as a plain string (`first_party` /
    # `third_party`), not the proto enum.
    route = respx_mock.patch(f"{BASE}/admin/applications/c-1").mock(
        return_value=httpx.Response(200, json=SERVER_CLIENT)
    )

    _admin().update_client("c-1", UpdateClientRequest(trust_level="first_party"))

    body = json.loads(route.calls.last.request.content)
    assert body == {"trust_level": "first_party"}


def test_list_clients_parses_server_shape(respx_mock):
    respx_mock.get(f"{BASE}/admin/applications").mock(
        return_value=httpx.Response(200, json={"items": [SERVER_CLIENT]})
    )

    page = _admin().list_clients()

    assert [c.id for c in page.items] == ["c-1"]
    assert page.items[0].name == "My App"


def test_regenerate_client_secret_posts_and_returns_the_new_secret(respx_mock):
    route = respx_mock.post(f"{BASE}/admin/applications/c-1/regenerate-secret").mock(
        return_value=httpx.Response(
            200, json={**SERVER_CLIENT, "client_secret": "new-secret"}
        )
    )

    client = _admin().regenerate_client_secret("c-1")

    assert route.called
    assert client.id == "c-1"
    assert client.secret == "new-secret"
