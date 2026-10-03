"""AdminClient organizations and generated-client wiring.

``/admin/organizations`` (src/protocol/http/admin/orgs.rs) speaks snake_case
JSON: ``{id, slug, display_name, status, member_limit, mfa_required,
attributes, created_at, updated_at}``. Creates answer ``201``, deletes and the
extra-role add/remove answer ``204`` with an empty body.
"""

from __future__ import annotations

import json

import httpx
import pytest

from hearth.admin import AdminClient
from hearth.errors import HearthError
from hearth.types import (
    CreateOrganizationRequest,
    UpdateOrganizationRequest,
    UpdateUserRequest,
)

BASE = "http://localhost:8420"

SERVER_ORG = {
    "id": "0b6f3c1e-0000-4000-8000-000000000001",
    "slug": "acme",
    "display_name": "Acme",
    "status": "active",
    "member_limit": None,
    "mfa_required": False,
    "attributes": {"tier": "gold"},
    "created_at": 1,
    "updated_at": 2,
}
ORG_ID = SERVER_ORG["id"]


def _admin() -> AdminClient:
    return AdminClient(BASE, "admin-token", "realm-1")


def test_requests_carry_bearer_and_realm_headers(respx_mock):
    route = respx_mock.get(f"{BASE}/admin/organizations/{ORG_ID}").mock(
        return_value=httpx.Response(200, json=SERVER_ORG)
    )

    _admin().get_organization(ORG_ID)

    headers = route.calls.last.request.headers
    assert headers["authorization"] == "Bearer admin-token"
    assert headers["x-realm-id"] == "realm-1"


def test_create_organization_posts_snake_case_body(respx_mock):
    route = respx_mock.post(f"{BASE}/admin/organizations").mock(
        return_value=httpx.Response(201, json=SERVER_ORG)
    )

    org = _admin().create_organization(
        CreateOrganizationRequest(
            slug="acme", display_name="Acme", attributes={"tier": "gold"}
        )
    )

    body = json.loads(route.calls.last.request.content)
    assert body == {
        "slug": "acme",
        "display_name": "Acme",
        "attributes": {"tier": "gold"},
    }
    assert org.id == ORG_ID
    assert org.display_name == "Acme"
    assert org.attributes == {"tier": "gold"}
    assert org.mfa_required is False


def test_list_organizations_passes_cursor_and_limit(respx_mock):
    route = respx_mock.get(f"{BASE}/admin/organizations").mock(
        return_value=httpx.Response(
            200, json={"items": [SERVER_ORG], "next_cursor": "50"}
        )
    )

    page = _admin().list_organizations(cursor="0", limit=50)

    params = route.calls.last.request.url.params
    assert params["cursor"] == "0"
    assert params["limit"] == "50"
    assert [o.slug for o in page.items] == ["acme"]
    assert page.next_cursor == "50"


def test_update_organization_patches_only_given_fields(respx_mock):
    route = respx_mock.patch(f"{BASE}/admin/organizations/{ORG_ID}").mock(
        return_value=httpx.Response(200, json={**SERVER_ORG, "status": "suspended"})
    )

    org = _admin().update_organization(
        ORG_ID, UpdateOrganizationRequest(status="suspended")
    )

    assert json.loads(route.calls.last.request.content) == {"status": "suspended"}
    assert org.status == "suspended"


def test_delete_organization_accepts_204(respx_mock):
    route = respx_mock.delete(f"{BASE}/admin/organizations/{ORG_ID}").mock(
        return_value=httpx.Response(204)
    )

    assert _admin().delete_organization(ORG_ID) is None
    assert route.called


def test_member_roles_list_add_remove(respx_mock):
    roles = f"{BASE}/admin/organizations/{ORG_ID}/members/u-1/roles"
    listed = respx_mock.get(roles).mock(
        return_value=httpx.Response(200, json={"items": ["billing"]})
    )
    added = respx_mock.post(roles).mock(return_value=httpx.Response(204))
    removed = respx_mock.delete(f"{roles}/billing").mock(
        return_value=httpx.Response(204)
    )

    admin = _admin()
    assert admin.list_member_roles(ORG_ID, "u-1") == ["billing"]
    admin.add_member_role(ORG_ID, "u-1", "billing")
    admin.remove_member_role(ORG_ID, "u-1", "billing")

    assert listed.called
    assert json.loads(added.calls.last.request.content) == {"role_name": "billing"}
    assert removed.called


def test_error_status_raises_hearth_error_with_plain_text_body(respx_mock):
    respx_mock.get(f"{BASE}/admin/organizations/{ORG_ID}").mock(
        return_value=httpx.Response(404, text="not found")
    )

    with pytest.raises(HearthError) as err:
        _admin().get_organization(ORG_ID)
    assert err.value.status_code == 404


def test_update_user_sends_status_as_proto_enum_name(respx_mock):
    # PATCH /admin/users/{id} deserializes the proto UpdateUserRequest: the
    # status is the UserStatus enum name; `active` is refused as invalid.
    route = respx_mock.patch(f"{BASE}/admin/users/u-1").mock(
        return_value=httpx.Response(
            200, json={"id": "u-1", "username": "u", "status": "USER_STATUS_DISABLED"}
        )
    )

    _admin().update_user("u-1", UpdateUserRequest(status="disabled"))

    body = json.loads(route.calls.last.request.content)
    assert body == {"status": "USER_STATUS_DISABLED"}


def test_base_url_path_prefix_is_kept(respx_mock):
    route = respx_mock.get("http://gw.example/hearth/admin/users/u-1").mock(
        return_value=httpx.Response(
            200, json={"id": "u-1", "username": "u", "status": "a"}
        )
    )

    AdminClient("http://gw.example/hearth/", "t", "r").get_user("u-1")

    assert route.called
