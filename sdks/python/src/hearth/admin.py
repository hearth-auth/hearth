"""AdminClient: user and realm CRUD operations (requires admin token)."""

from typing import Optional, List

import httpx

from .errors import HearthError
from .types import (
    User,
    CreateUserRequest,
    UpdateUserRequest,
    Realm,
    CreateRealmRequest,
    UpdateRealmRequest,
    PageResponse,
    OAuthClient,
    CreateClientRequest,
    UpdateClientRequest,
    Role,
    CreateRoleRequest,
    UpdateRoleRequest,
    Group,
    CreateGroupRequest,
    UpdateGroupRequest,
    OrgMember,
    AddOrgMemberRequest,
)


class AdminClient:
    """Client for Hearth admin operations (user and realm CRUD).

    Requires an admin access token obtained via ``/admin/bootstrap`` or
    from a user with the ``hearth.admin`` permission.

    Attributes:
        base_url: The Hearth server base URL.
        admin_token: A Bearer access token with admin privileges.
        realm_id: The realm to operate on.
    """

    def __init__(self, base_url: str, admin_token: str, realm_id: str, timeout: float = 30.0):
        self._base = base_url.rstrip("/")
        self._token = admin_token
        self._realm = realm_id
        self._http = httpx.Client(
            headers={
                "X-Realm-ID": realm_id,
                "Authorization": f"Bearer {admin_token}",
            },
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def create_user(self, req: CreateUserRequest) -> User:
        """Create a new user."""
        resp = self._http.post(
            f"{self._base}/admin/users", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return User(**resp.json())

    def list_users(
        self, cursor: Optional[str] = None, limit: int = 50
    ) -> PageResponse[User]:
        """List users with cursor-based pagination."""
        params = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        resp = self._http.get(f"{self._base}/admin/users", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return PageResponse[User](**data)

    def get_user(self, user_id: str) -> User:
        """Get a user by ID."""
        resp = self._http.get(f"{self._base}/admin/users/{user_id}")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return User(**resp.json())

    def update_user(self, user_id: str, req: UpdateUserRequest) -> User:
        """Update an existing user."""
        resp = self._http.put(
            f"{self._base}/admin/users/{user_id}",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return User(**resp.json())

    def delete_user(self, user_id: str) -> None:
        """Delete a user."""
        resp = self._http.delete(f"{self._base}/admin/users/{user_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # Realms
    # ------------------------------------------------------------------

    def create_realm(self, req: CreateRealmRequest) -> Realm:
        """Create a new realm."""
        resp = self._http.post(
            f"{self._base}/admin/realms", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return Realm(**resp.json())

    def list_realms(self) -> List[Realm]:
        """List all realms."""
        resp = self._http.get(f"{self._base}/admin/realms")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return [Realm(**r) for r in data.get("items", data)]

    def get_realm(self, realm_id: str) -> Realm:
        """Get a realm by ID."""
        resp = self._http.get(f"{self._base}/admin/realms/{realm_id}")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Realm(**resp.json())

    def update_realm(self, realm_id: str, req: UpdateRealmRequest) -> Realm:
        """Update an existing realm."""
        resp = self._http.put(
            f"{self._base}/admin/realms/{realm_id}",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Realm(**resp.json())

    def delete_realm(self, realm_id: str) -> None:
        """Delete a realm."""
        resp = self._http.delete(f"{self._base}/admin/realms/{realm_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # OAuth Clients
    # ------------------------------------------------------------------

    def create_client(self, req: CreateClientRequest) -> OAuthClient:
        """Create a new OAuth client."""
        resp = self._http.post(
            f"{self._base}/admin/clients", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return OAuthClient(**resp.json())

    def list_clients(
        self, cursor: Optional[str] = None, limit: int = 50
    ) -> PageResponse[OAuthClient]:
        """List OAuth clients with cursor-based pagination."""
        params = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        resp = self._http.get(f"{self._base}/admin/clients", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return PageResponse[OAuthClient](**data)

    def get_client(self, client_id: str) -> OAuthClient:
        """Get an OAuth client by ID."""
        resp = self._http.get(f"{self._base}/admin/clients/{client_id}")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return OAuthClient(**resp.json())

    def update_client(self, client_id: str, req: UpdateClientRequest) -> OAuthClient:
        """Update an existing OAuth client."""
        resp = self._http.put(
            f"{self._base}/admin/clients/{client_id}",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return OAuthClient(**resp.json())

    def delete_client(self, client_id: str) -> None:
        """Delete an OAuth client."""
        resp = self._http.delete(f"{self._base}/admin/clients/{client_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    def create_role(self, req: CreateRoleRequest) -> Role:
        """Create a new realm-level role."""
        resp = self._http.post(
            f"{self._base}/admin/roles", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return Role(**resp.json())

    def list_roles(
        self, cursor: Optional[str] = None, limit: int = 50
    ) -> PageResponse[Role]:
        """List realm-level roles with cursor-based pagination."""
        params = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        resp = self._http.get(f"{self._base}/admin/roles", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return PageResponse[Role](**data)

    def get_role(self, role_id: str) -> Role:
        """Get a role by ID."""
        resp = self._http.get(f"{self._base}/admin/roles/{role_id}")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Role(**resp.json())

    def update_role(self, role_id: str, req: UpdateRoleRequest) -> Role:
        """Update an existing role."""
        resp = self._http.put(
            f"{self._base}/admin/roles/{role_id}",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Role(**resp.json())

    def delete_role(self, role_id: str) -> None:
        """Delete a role."""
        resp = self._http.delete(f"{self._base}/admin/roles/{role_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def create_group(self, req: CreateGroupRequest) -> Group:
        """Create a new realm-level group."""
        resp = self._http.post(
            f"{self._base}/admin/groups", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return Group(**resp.json())

    def list_groups(
        self, cursor: Optional[str] = None, limit: int = 50
    ) -> PageResponse[Group]:
        """List realm-level groups with cursor-based pagination."""
        params = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        resp = self._http.get(f"{self._base}/admin/groups", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return PageResponse[Group](**data)

    def get_group(self, group_id: str) -> Group:
        """Get a group by ID."""
        resp = self._http.get(f"{self._base}/admin/groups/{group_id}")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Group(**resp.json())

    def update_group(self, group_id: str, req: UpdateGroupRequest) -> Group:
        """Update an existing group."""
        resp = self._http.put(
            f"{self._base}/admin/groups/{group_id}",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return Group(**resp.json())

    def delete_group(self, group_id: str) -> None:
        """Delete a group."""
        resp = self._http.delete(f"{self._base}/admin/groups/{group_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    # ------------------------------------------------------------------
    # Organization Memberships
    # ------------------------------------------------------------------

    def list_org_members(
        self, org_id: str, cursor: Optional[str] = None, limit: int = 50
    ) -> PageResponse[OrgMember]:
        """List members of an organization with cursor-based pagination."""
        params = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        resp = self._http.get(f"{self._base}/admin/orgs/{org_id}/members", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        data = resp.json()
        return PageResponse[OrgMember](**data)

    def add_org_member(self, org_id: str, req: AddOrgMemberRequest) -> OrgMember:
        """Add a user to an organization."""
        resp = self._http.post(
            f"{self._base}/admin/orgs/{org_id}/members",
            json=req.model_dump(exclude_none=True),
        )
        if resp.status_code not in (200, 201):
            raise HearthError(resp.status_code, resp.text)
        return OrgMember(**resp.json())

    def remove_org_member(self, org_id: str, user_id: str) -> None:
        """Remove a user from an organization."""
        resp = self._http.delete(f"{self._base}/admin/orgs/{org_id}/members/{user_id}")
        if resp.status_code not in (200, 204):
            raise HearthError(resp.status_code, resp.text)

    def close(self):
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
