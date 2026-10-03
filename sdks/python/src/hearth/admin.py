"""AdminClient: Hearth admin API operations (requires an admin token).

The routes, methods, path and query parameters and request bodies come from
the client generated from ``docs/api/openapi.json`` (:mod:`hearth.generated.admin`,
see ``sdks/python/gen-admin.sh``). Success bodies are decoded by the generated
models, then returned as the SDK's pydantic types. This module keeps the
ergonomic method names, the auth headers and the SDK error taxonomy.

The generated ``sync`` parsers are not used: they call ``response.json()`` on
every status, so a ``204`` delete or a plain-text error would raise
``JSONDecodeError`` instead of :class:`HearthError`.
"""

from types import ModuleType
from typing import Any

import httpx

from .errors import HearthError
from .generated.admin import models as _gen
from .generated.admin.api.admin import (
    admin_add_additional_role,
    admin_create_group,
    admin_create_organization,
    admin_create_role,
    admin_delete_group,
    admin_delete_organization,
    admin_delete_role,
    admin_get_group,
    admin_get_organization,
    admin_get_role,
    admin_list_additional_roles,
    admin_list_groups,
    admin_list_organizations,
    admin_list_roles,
    admin_remove_additional_role,
    admin_update_group,
    admin_update_organization,
    admin_update_role,
)
from .generated.admin.api.application_admin_service import (
    application_admin_service_create_application as create_application,
)
from .generated.admin.api.application_admin_service import (
    application_admin_service_delete_application as delete_application,
)
from .generated.admin.api.application_admin_service import (
    application_admin_service_get_application as get_application,
)
from .generated.admin.api.application_admin_service import (
    application_admin_service_list_applications as list_applications,
)
from .generated.admin.api.application_admin_service import (
    application_admin_service_regenerate_application_secret as regenerate_secret,
)
from .generated.admin.api.application_admin_service import (
    application_admin_service_update_application as update_application,
)
from .generated.admin.api.identity_admin_service import (
    identity_admin_service_create_user,
    identity_admin_service_delete_realm,
    identity_admin_service_delete_user,
    identity_admin_service_get_realm,
    identity_admin_service_get_user,
    identity_admin_service_list_realms,
    identity_admin_service_list_users,
    identity_admin_service_update_user,
)
from .generated.admin.client import Client as _GeneratedClient
from .types import (
    CreateClientRequest,
    CreateGroupRequest,
    CreateOrganizationRequest,
    CreateRoleRequest,
    CreateUserRequest,
    Group,
    OAuthClient,
    Organization,
    PageResponse,
    Realm,
    Role,
    UpdateClientRequest,
    UpdateGroupRequest,
    UpdateOrganizationRequest,
    UpdateRoleRequest,
    UpdateUserRequest,
    User,
)

_OK = (200,)
_CREATED = (200, 201)
_NO_CONTENT = (200, 204)


class AdminClient:
    """Client for Hearth admin operations.

    Requires an admin access token obtained via ``/admin/bootstrap`` or
    from a user with the ``hearth.realm.admin`` permission.

    Attributes:
        base_url: The Hearth server base URL.
        admin_token: A Bearer access token with admin privileges.
        realm_id: The realm to operate on (sent as ``X-Realm-ID``).
    """

    def __init__(
        self, base_url: str, admin_token: str, realm_id: str, timeout: float = 30.0
    ):
        self._realm = realm_id
        self._generated = _GeneratedClient(
            base_url=base_url.rstrip("/"),
            headers={
                "X-Realm-ID": realm_id,
                "Authorization": f"Bearer {admin_token}",
            },
            timeout=httpx.Timeout(timeout),
        )
        self._http = self._generated.get_httpx_client()

    def _send(
        self, endpoint: ModuleType, ok: tuple[int, ...], **kwargs: Any
    ) -> httpx.Response:
        """Send the request the generated ``endpoint`` describes; raise on error."""
        # INVARIANT: `_get_kwargs` is the generated request builder (method,
        # URL, query, JSON body). It is internal to generated code we pin.
        resp = self._http.request(**endpoint._get_kwargs(**kwargs))
        if resp.status_code not in ok:
            raise HearthError(resp.status_code, resp.text)
        return resp

    @staticmethod
    def _decode(model: Any, resp: httpx.Response) -> dict[str, Any]:
        """Decode a success body through the generated ``model``."""
        return model.from_dict(resp.json()).to_dict()

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def create_user(self, req: CreateUserRequest) -> User:
        """Create a new user."""
        body = _gen.V1CreateUserRequest.from_dict(req.model_dump(exclude_none=True))
        resp = self._send(identity_admin_service_create_user, _CREATED, body=body)
        return User(**self._decode(_gen.V1User, resp))

    def list_users(
        self, cursor: str | None = None, limit: int = 50
    ) -> PageResponse[User]:
        """List users with cursor-based pagination."""
        resp = self._send(
            identity_admin_service_list_users, _OK, **_page(cursor, limit)
        )
        return PageResponse[User](**self._decode(_gen.V1UserPage, resp))

    def get_user(self, user_id: str) -> User:
        """Get a user by ID."""
        resp = self._send(identity_admin_service_get_user, _OK, id=user_id)
        return User(**self._decode(_gen.V1User, resp))

    def update_user(self, user_id: str, req: UpdateUserRequest) -> User:
        """Update an existing user."""
        body = _gen.V1UpdateUserRequest.from_dict(req.model_dump(exclude_none=True))
        resp = self._send(
            identity_admin_service_update_user, _OK, id=user_id, body=body
        )
        return User(**self._decode(_gen.V1User, resp))

    def delete_user(self, user_id: str) -> None:
        """Delete a user."""
        self._send(identity_admin_service_delete_user, _NO_CONTENT, id=user_id)

    # ------------------------------------------------------------------
    # Realms
    # ------------------------------------------------------------------

    # Realms are provisioned via hearth.yaml, not the admin API. There is no
    # ``create_realm`` and no ``update_realm`` method: the server returns 405
    # with "Realms are managed via hearth.yaml" for both POST /admin/realms and
    # PATCH /admin/realms/{id} (HEA-2171, audit 2026-08-28 §25.4). Only read
    # paths and deletion are exposed.

    def list_realms(self) -> list[Realm]:
        """List all realms."""
        resp = self._send(identity_admin_service_list_realms, _OK)
        data = self._decode(_gen.V1RealmPage, resp)
        return [Realm(**r) for r in data.get("items", data)]

    def get_realm(self, realm_id: str) -> Realm:
        """Get a realm by ID."""
        resp = self._send(identity_admin_service_get_realm, _OK, id=realm_id)
        return Realm(**self._decode(_gen.V1Realm, resp))

    def delete_realm(self, realm_id: str) -> None:
        """Delete a realm."""
        self._send(identity_admin_service_delete_realm, _NO_CONTENT, id=realm_id)

    # ------------------------------------------------------------------
    # OAuth Clients
    # ------------------------------------------------------------------

    def create_client(self, req: CreateClientRequest) -> OAuthClient:
        """Create a new OAuth client."""
        # by_alias: the wire key is `client_name`; the server 422s on `name`.
        body = _gen.V1RegisterClientRequest.from_dict(
            req.model_dump(exclude_none=True, by_alias=True)
        )
        resp = self._send(create_application, _CREATED, body=body)
        return OAuthClient(**self._decode(_gen.V1OAuthClient, resp))

    def list_clients(
        self, cursor: str | None = None, limit: int = 50
    ) -> PageResponse[OAuthClient]:
        """List OAuth clients with cursor-based pagination."""
        resp = self._send(list_applications, _OK, **_page(cursor, limit))
        return PageResponse[OAuthClient](**self._decode(_gen.V1OAuthClientPage, resp))

    def get_client(self, client_id: str) -> OAuthClient:
        """Get an OAuth client by ID."""
        resp = self._send(get_application, _OK, client_id=client_id)
        return OAuthClient(**self._decode(_gen.V1OAuthClient, resp))

    def update_client(self, client_id: str, req: UpdateClientRequest) -> OAuthClient:
        """Update an existing OAuth client."""
        # by_alias: the route reads `client_name` and silently ignores `name`.
        body = _gen.V1UpdateClientRequest.from_dict(
            req.model_dump(exclude_none=True, by_alias=True)
        )
        resp = self._send(update_application, _OK, client_id=client_id, body=body)
        return OAuthClient(**self._decode(_gen.V1OAuthClient, resp))

    def regenerate_client_secret(self, client_id: str) -> OAuthClient:
        """Replace a confidential client's secret.

        ``POST /admin/applications/{id}/regenerate-secret``. The returned
        client's ``secret`` is the new secret, returned once; the old secret
        stops working immediately.
        """
        resp = self._send(regenerate_secret, _OK, client_id=client_id)
        return OAuthClient.model_validate(self._decode(_gen.V1OAuthClient, resp))

    def delete_client(self, client_id: str) -> None:
        """Delete an OAuth client."""
        self._send(delete_application, _NO_CONTENT, client_id=client_id)

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    def create_role(self, req: CreateRoleRequest) -> Role:
        """Create a new realm-level role."""
        body = _gen.AdminCreateRoleRequest.from_dict(req.model_dump(exclude_none=True))
        resp = self._send(admin_create_role, _CREATED, body=body)
        return Role(**self._decode(_gen.AdminRole, resp))

    def list_roles(
        self, cursor: str | None = None, limit: int = 50
    ) -> PageResponse[Role]:
        """List realm-level roles with cursor-based pagination."""
        resp = self._send(admin_list_roles, _OK, **_page(cursor, limit))
        return PageResponse[Role](**self._decode(_gen.AdminRolePage, resp))

    def get_role(self, role_id: str) -> Role:
        """Get a role by ID."""
        resp = self._send(admin_get_role, _OK, id=role_id)
        return Role(**self._decode(_gen.AdminRole, resp))

    def update_role(self, role_id: str, req: UpdateRoleRequest) -> Role:
        """Update an existing role."""
        body = _gen.AdminUpdateRoleRequest.from_dict(req.model_dump(exclude_none=True))
        resp = self._send(admin_update_role, _OK, id=role_id, body=body)
        return Role(**self._decode(_gen.AdminRole, resp))

    def delete_role(self, role_id: str) -> None:
        """Delete a role."""
        self._send(admin_delete_role, _NO_CONTENT, id=role_id)

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def create_group(self, req: CreateGroupRequest) -> Group:
        """Create a new realm-level group."""
        body = _gen.AdminCreateGroupRequest.from_dict(req.model_dump(exclude_none=True))
        resp = self._send(admin_create_group, _CREATED, body=body)
        return Group(**self._decode(_gen.AdminGroup, resp))

    def list_groups(
        self, cursor: str | None = None, limit: int = 50
    ) -> PageResponse[Group]:
        """List realm-level groups with cursor-based pagination."""
        resp = self._send(admin_list_groups, _OK, **_page(cursor, limit))
        return PageResponse[Group](**self._decode(_gen.AdminGroupPage, resp))

    def get_group(self, group_id: str) -> Group:
        """Get a group by ID."""
        resp = self._send(admin_get_group, _OK, id=group_id)
        return Group(**self._decode(_gen.AdminGroup, resp))

    def update_group(self, group_id: str, req: UpdateGroupRequest) -> Group:
        """Update an existing group."""
        body = _gen.AdminUpdateGroupRequest.from_dict(req.model_dump(exclude_none=True))
        resp = self._send(admin_update_group, _OK, id=group_id, body=body)
        return Group(**self._decode(_gen.AdminGroup, resp))

    def delete_group(self, group_id: str) -> None:
        """Delete a group."""
        self._send(admin_delete_group, _NO_CONTENT, id=group_id)

    # ------------------------------------------------------------------
    # Organizations
    # ------------------------------------------------------------------

    def create_organization(self, req: CreateOrganizationRequest) -> Organization:
        """Create an organization. Refused in the system realm."""
        body = _gen.AdminCreateOrganizationRequest.from_dict(
            req.model_dump(exclude_none=True)
        )
        resp = self._send(admin_create_organization, _CREATED, body=body)
        return Organization(**self._decode(_gen.AdminOrganization, resp))

    def list_organizations(
        self, cursor: str | None = None, limit: int = 50
    ) -> PageResponse[Organization]:
        """List organizations; follow ``next_cursor`` until it is ``None``."""
        resp = self._send(admin_list_organizations, _OK, **_page(cursor, limit))
        return PageResponse[Organization](
            **self._decode(_gen.AdminOrganizationPage, resp)
        )

    def get_organization(self, org_id: str) -> Organization:
        """Get an organization by ID."""
        resp = self._send(admin_get_organization, _OK, id=org_id)
        return Organization(**self._decode(_gen.AdminOrganization, resp))

    def update_organization(
        self, org_id: str, req: UpdateOrganizationRequest
    ) -> Organization:
        """Update an organization; fields left as ``None`` keep their value."""
        body = _gen.AdminUpdateOrganizationRequest.from_dict(
            req.model_dump(exclude_none=True)
        )
        resp = self._send(admin_update_organization, _OK, id=org_id, body=body)
        return Organization(**self._decode(_gen.AdminOrganization, resp))

    def delete_organization(self, org_id: str) -> None:
        """Delete an organization."""
        self._send(admin_delete_organization, _NO_CONTENT, id=org_id)

    def list_member_roles(self, org_id: str, user_id: str) -> list[str]:
        """List a member's extra organization role names."""
        resp = self._send(admin_list_additional_roles, _OK, id=org_id, user_id=user_id)
        return list(self._decode(_gen.AdminRoleNameList, resp)["items"])

    def add_member_role(self, org_id: str, user_id: str, role_name: str) -> None:
        """Give an organization member an extra role.

        The user must already be a member (``409`` otherwise).
        """
        body = _gen.AdminAddAdditionalRoleRequest(role_name=role_name)
        self._send(
            admin_add_additional_role,
            _NO_CONTENT,
            id=org_id,
            user_id=user_id,
            body=body,
        )

    def remove_member_role(self, org_id: str, user_id: str, role_name: str) -> None:
        """Remove an extra role from an organization member."""
        self._send(
            admin_remove_additional_role,
            _NO_CONTENT,
            id=org_id,
            user_id=user_id,
            role_name=role_name,
        )

    def close(self):
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _page(cursor: str | None, limit: int) -> dict[str, Any]:
    """Query arguments for a cursor-paginated list."""
    args: dict[str, Any] = {"limit": limit}
    if cursor:
        args["cursor"] = cursor
    return args
