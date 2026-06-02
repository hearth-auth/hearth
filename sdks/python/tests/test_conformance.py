"""Spec conformance tests for §4 Claims, §5 Errors, §6 Middleware, §12 Admin.

TDD: written before implementation. Run with `pytest sdks/python/tests/`.
"""

from __future__ import annotations

import base64
import json
from typing import Optional
from unittest.mock import MagicMock

import httpx
import pytest

from hearth.claims import Claims


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
# §4 Claims — new methods
# ---------------------------------------------------------------------------

class TestClaimsNewMethods:
    """Tests for spec §4 methods added in this conformance pass."""

    def test_scope_returns_space_delimited_string(self):
        c = Claims({"scope": "openid profile email"})
        assert c.scope() == "openid profile email"

    def test_scope_returns_empty_string_when_absent(self):
        c = Claims({})
        assert c.scope() == ""

    def test_in_group_true_when_group_present(self):
        c = Claims({"groups": ["eng", "admin"]})
        assert c.in_group("eng") is True

    def test_in_group_false_when_group_absent(self):
        c = Claims({"groups": ["eng"]})
        assert c.in_group("admin") is False

    def test_in_group_false_when_claim_absent(self):
        c = Claims({})
        assert c.in_group("eng") is False

    def test_in_org_true_when_oid_matches(self):
        c = Claims({"oid": "org_abc"})
        assert c.in_org("org_abc") is True

    def test_in_org_false_when_oid_differs(self):
        c = Claims({"oid": "org_abc"})
        assert c.in_org("org_xyz") is False

    def test_in_org_false_when_claim_absent(self):
        c = Claims({})
        assert c.in_org("org_abc") is False

    def test_token_type_returns_value(self):
        c = Claims({"token_type": "access"})
        assert c.token_type() == "access"

    def test_token_type_returns_empty_string_when_absent(self):
        c = Claims({})
        assert c.token_type() == ""

    def test_token_type_required_action(self):
        c = Claims({"token_type": "required_action"})
        assert c.token_type() == "required_action"

    def test_organization_id_returns_oid(self):
        c = Claims({"oid": "org_123"})
        assert c.organization_id() == "org_123"

    def test_organization_id_returns_none_when_absent(self):
        c = Claims({})
        assert c.organization_id() is None

    def test_org_groups_returns_list(self):
        c = Claims({"org_groups": ["/acme/eng", "/acme/admin"]})
        assert c.org_groups() == ["/acme/eng", "/acme/admin"]

    def test_org_groups_returns_empty_list_when_absent(self):
        c = Claims({})
        assert c.org_groups() == []

    def test_existing_has_role_still_works(self):
        c = Claims({"roles": ["admin"]})
        assert c.hasRole("admin") is True
        assert c.hasRole("user") is False

    def test_existing_has_permission_still_works(self):
        c = Claims({"permissions": ["docs.write"]})
        assert c.hasPermission("docs.write") is True

    def test_scopes_list_still_works(self):
        c = Claims({"scope": "openid profile"})
        assert c.scopes() == ["openid", "profile"]


# ---------------------------------------------------------------------------
# §5 Errors — RequiredActionError
# ---------------------------------------------------------------------------

class TestRequiredActionError:
    def test_is_hearth_sdk_error(self):
        from hearth.errors import RequiredActionError, HearthSdkError
        err = RequiredActionError(required_actions=["VERIFY_EMAIL"])
        assert isinstance(err, HearthSdkError)

    def test_required_actions_field(self):
        from hearth.errors import RequiredActionError
        err = RequiredActionError(required_actions=["VERIFY_EMAIL", "UPDATE_PASSWORD"])
        assert err.required_actions == ["VERIFY_EMAIL", "UPDATE_PASSWORD"]

    def test_redirect_uri_optional_default_none(self):
        from hearth.errors import RequiredActionError
        err = RequiredActionError(required_actions=["VERIFY_EMAIL"])
        assert err.redirect_uri is None

    def test_redirect_uri_can_be_set(self):
        from hearth.errors import RequiredActionError
        err = RequiredActionError(
            required_actions=["VERIFY_EMAIL"],
            redirect_uri="https://app.example.com/actions",
        )
        assert err.redirect_uri == "https://app.example.com/actions"

    def test_has_human_readable_message(self):
        from hearth.errors import RequiredActionError
        err = RequiredActionError(required_actions=["VERIFY_EMAIL"])
        assert "VERIFY_EMAIL" in str(err)

    def test_empty_required_actions(self):
        from hearth.errors import RequiredActionError
        err = RequiredActionError(required_actions=[])
        assert err.required_actions == []


# ---------------------------------------------------------------------------
# §6 Middleware — required_action token_type → 401
# ---------------------------------------------------------------------------

class TestWsgiRequiredAction:
    """WSGI middleware must return 401 (not 403) on required_action tokens."""

    def _client(self):
        from hearth.client import HearthClient
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

    def test_required_action_token_returns_401(self):
        from hearth.middleware import WsgiPermissionMiddleware
        from hearth.errors import RequiredActionError

        token = _make_jwt({
            "token_type": "required_action",
            "required_actions": ["VERIFY_EMAIL"],
            "permissions": ["docs.write"],
        })
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        sr = self._start_response()
        mw(self._environ(token), sr)
        assert sr.calls[0][0].startswith("401")
        inner.assert_not_called()

    def test_regular_access_token_not_affected(self):
        from hearth.middleware import WsgiPermissionMiddleware
        token = _make_jwt({
            "token_type": "access",
            "permissions": ["docs.write"],
        })
        inner = MagicMock(return_value=[b"ok"])
        mw = WsgiPermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        sr = self._start_response()
        mw(self._environ(token), sr)
        assert sr.calls == []  # inner was called — no auth failure
        inner.assert_called_once()


class TestAsgiRequiredAction:
    """ASGI middleware must return 401 (not 403) on required_action tokens."""

    def _client(self):
        from hearth.client import HearthClient
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
    async def test_required_action_token_returns_401(self):
        from hearth.middleware import RequirePermissionMiddleware
        token = _make_jwt({
            "token_type": "required_action",
            "required_actions": ["VERIFY_EMAIL"],
            "permissions": ["docs.write"],
        })

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        resp = await self._collect_response(mw, self._scope(token))
        assert resp["status"] == 401

    @pytest.mark.asyncio
    async def test_regular_access_token_not_affected(self):
        from hearth.middleware import RequirePermissionMiddleware
        token = _make_jwt({
            "token_type": "access",
            "permissions": ["docs.write"],
        })

        responses = []

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RequirePermissionMiddleware(
            inner, client=self._client(), permission="docs.write", mode="embedded"
        )
        resp = await self._collect_response(mw, self._scope(token))
        assert resp["status"] == 200


# ---------------------------------------------------------------------------
# §12 Admin — clients, roles, groups, org memberships
# ---------------------------------------------------------------------------

class TestAdminClients:
    def _admin(self):
        from hearth.admin import AdminClient
        return AdminClient("http://localhost:8420", "tok", "realm-1")

    def test_list_clients(self, respx_mock):
        respx_mock.get("http://localhost:8420/admin/clients").mock(
            return_value=httpx.Response(200, json={"items": [
                {"id": "c1", "name": "My App", "redirect_uris": [], "trust_level": "confidential"}
            ], "next_cursor": None})
        )
        result = self._admin().list_clients()
        assert len(result.items) == 1
        assert result.items[0].id == "c1"

    def test_get_client(self, respx_mock):
        respx_mock.get("http://localhost:8420/admin/clients/c1").mock(
            return_value=httpx.Response(200, json={
                "id": "c1", "name": "My App", "redirect_uris": [], "trust_level": "confidential"
            })
        )
        result = self._admin().get_client("c1")
        assert result.id == "c1"

    def test_create_client(self, respx_mock):
        from hearth.types import CreateClientRequest
        respx_mock.post("http://localhost:8420/admin/clients").mock(
            return_value=httpx.Response(201, json={
                "id": "c2", "name": "New App", "redirect_uris": ["https://app/cb"],
                "trust_level": "public"
            })
        )
        req = CreateClientRequest(name="New App", redirect_uris=["https://app/cb"], trust_level="public")
        result = self._admin().create_client(req)
        assert result.id == "c2"

    def test_update_client(self, respx_mock):
        from hearth.types import UpdateClientRequest
        respx_mock.put("http://localhost:8420/admin/clients/c1").mock(
            return_value=httpx.Response(200, json={
                "id": "c1", "name": "Updated App", "redirect_uris": [], "trust_level": "confidential"
            })
        )
        req = UpdateClientRequest(name="Updated App")
        result = self._admin().update_client("c1", req)
        assert result.name == "Updated App"

    def test_delete_client(self, respx_mock):
        respx_mock.delete("http://localhost:8420/admin/clients/c1").mock(
            return_value=httpx.Response(204)
        )
        self._admin().delete_client("c1")  # no error = success


class TestAdminRoles:
    def _admin(self):
        from hearth.admin import AdminClient
        return AdminClient("http://localhost:8420", "tok", "realm-1")

    def test_list_roles(self, respx_mock):
        respx_mock.get("http://localhost:8420/admin/roles").mock(
            return_value=httpx.Response(200, json={"items": [
                {"id": "r1", "name": "admin", "description": None}
            ], "next_cursor": None})
        )
        result = self._admin().list_roles()
        assert len(result.items) == 1
        assert result.items[0].name == "admin"

    def test_get_role(self, respx_mock):
        respx_mock.get("http://localhost:8420/admin/roles/r1").mock(
            return_value=httpx.Response(200, json={"id": "r1", "name": "admin", "description": None})
        )
        result = self._admin().get_role("r1")
        assert result.id == "r1"

    def test_create_role(self, respx_mock):
        from hearth.types import CreateRoleRequest
        respx_mock.post("http://localhost:8420/admin/roles").mock(
            return_value=httpx.Response(201, json={"id": "r2", "name": "editor", "description": "Can edit"})
        )
        req = CreateRoleRequest(name="editor", description="Can edit")
        result = self._admin().create_role(req)
        assert result.id == "r2"

    def test_update_role(self, respx_mock):
        from hearth.types import UpdateRoleRequest
        respx_mock.put("http://localhost:8420/admin/roles/r1").mock(
            return_value=httpx.Response(200, json={"id": "r1", "name": "superadmin", "description": None})
        )
        req = UpdateRoleRequest(name="superadmin")
        result = self._admin().update_role("r1", req)
        assert result.name == "superadmin"

    def test_delete_role(self, respx_mock):
        respx_mock.delete("http://localhost:8420/admin/roles/r1").mock(
            return_value=httpx.Response(204)
        )
        self._admin().delete_role("r1")


class TestAdminGroups:
    def _admin(self):
        from hearth.admin import AdminClient
        return AdminClient("http://localhost:8420", "tok", "realm-1")

    def test_list_groups(self, respx_mock):
        respx_mock.get("http://localhost:8420/admin/groups").mock(
            return_value=httpx.Response(200, json={"items": [
                {"id": "g1", "name": "engineering", "description": None}
            ], "next_cursor": None})
        )
        result = self._admin().list_groups()
        assert len(result.items) == 1
        assert result.items[0].name == "engineering"

    def test_get_group(self, respx_mock):
        respx_mock.get("http://localhost:8420/admin/groups/g1").mock(
            return_value=httpx.Response(200, json={"id": "g1", "name": "engineering", "description": None})
        )
        result = self._admin().get_group("g1")
        assert result.id == "g1"

    def test_create_group(self, respx_mock):
        from hearth.types import CreateGroupRequest
        respx_mock.post("http://localhost:8420/admin/groups").mock(
            return_value=httpx.Response(201, json={"id": "g2", "name": "design", "description": None})
        )
        req = CreateGroupRequest(name="design")
        result = self._admin().create_group(req)
        assert result.id == "g2"

    def test_update_group(self, respx_mock):
        from hearth.types import UpdateGroupRequest
        respx_mock.put("http://localhost:8420/admin/groups/g1").mock(
            return_value=httpx.Response(200, json={"id": "g1", "name": "infra", "description": "Infrastructure"})
        )
        req = UpdateGroupRequest(name="infra", description="Infrastructure")
        result = self._admin().update_group("g1", req)
        assert result.name == "infra"

    def test_delete_group(self, respx_mock):
        respx_mock.delete("http://localhost:8420/admin/groups/g1").mock(
            return_value=httpx.Response(204)
        )
        self._admin().delete_group("g1")


class TestAdminOrgMembers:
    def _admin(self):
        from hearth.admin import AdminClient
        return AdminClient("http://localhost:8420", "tok", "realm-1")

    def test_list_org_members(self, respx_mock):
        respx_mock.get("http://localhost:8420/admin/orgs/org_1/members").mock(
            return_value=httpx.Response(200, json={"items": [
                {"user_id": "u1", "org_id": "org_1", "role": "member"}
            ], "next_cursor": None})
        )
        result = self._admin().list_org_members("org_1")
        assert len(result.items) == 1
        assert result.items[0].user_id == "u1"

    def test_add_org_member(self, respx_mock):
        from hearth.types import AddOrgMemberRequest
        respx_mock.post("http://localhost:8420/admin/orgs/org_1/members").mock(
            return_value=httpx.Response(201, json={"user_id": "u2", "org_id": "org_1", "role": "admin"})
        )
        req = AddOrgMemberRequest(user_id="u2", role="admin")
        result = self._admin().add_org_member("org_1", req)
        assert result.user_id == "u2"
        assert result.role == "admin"

    def test_remove_org_member(self, respx_mock):
        respx_mock.delete("http://localhost:8420/admin/orgs/org_1/members/u1").mock(
            return_value=httpx.Response(204)
        )
        self._admin().remove_org_member("org_1", "u1")
