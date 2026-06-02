"""Hearth API request and response types."""

from typing import Literal, Optional, List, Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")

#: Controls how the SDK and middleware verify permissions for a given resource-server client.
#: Must be configured explicitly — the middleware will NOT silently fall back from one mode
#: to another based on what claims happen to be present in the token.
AccessTokenAuthorizationMode = Literal["embedded", "introspection", "decision"]


class BootstrapResponse(BaseModel):
    admin_token: str
    realm_id: str
    user_id: str
    access_token: str
    refresh_token: str


class User(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    status: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CreateUserRequest(BaseModel):
    username: str
    email: Optional[str] = None
    password: Optional[str] = None
    attributes: Optional[dict] = None


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    attributes: Optional[dict] = None


class PageResponse(BaseModel, Generic[T]):
    items: List[T]
    next_cursor: Optional[str] = None
    total: Optional[int] = None


class Realm(BaseModel):
    id: str
    name: str
    status: str
    config: Optional[dict] = None
    created_at: Optional[str] = None


class CreateRealmRequest(BaseModel):
    name: str
    config: Optional[dict] = None


class UpdateRealmRequest(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    status: Optional[str] = None


class AuthorizeResponse(BaseModel):
    code: str
    state: str
    redirect_uri: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    scope: Optional[str] = None
    id_token: Optional[str] = None


class UserInfoResponse(BaseModel):
    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    permissions: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None


class MePermissionsResponse(BaseModel):
    permissions: List[str]
    roles: List[str]
    groups: List[str]


class OAuthClient(BaseModel):
    id: str
    name: str
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None
    secret: Optional[str] = None


class RegisterClientRequest(BaseModel):
    name: str
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None


class CreateClientRequest(BaseModel):
    """Request body for POST /admin/clients."""

    name: str
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None


class UpdateClientRequest(BaseModel):
    """Request body for PUT /admin/clients/{id}."""

    name: Optional[str] = None
    redirect_uris: Optional[List[str]] = None
    trust_level: Optional[str] = None


class Role(BaseModel):
    """A realm-level role definition."""

    id: str
    name: str
    description: Optional[str] = None


class CreateRoleRequest(BaseModel):
    """Request body for POST /admin/roles."""

    name: str
    description: Optional[str] = None


class UpdateRoleRequest(BaseModel):
    """Request body for PUT /admin/roles/{id}."""

    name: Optional[str] = None
    description: Optional[str] = None


class Group(BaseModel):
    """A realm-level group definition."""

    id: str
    name: str
    description: Optional[str] = None


class CreateGroupRequest(BaseModel):
    """Request body for POST /admin/groups."""

    name: str
    description: Optional[str] = None


class UpdateGroupRequest(BaseModel):
    """Request body for PUT /admin/groups/{id}."""

    name: Optional[str] = None
    description: Optional[str] = None


class OrgMember(BaseModel):
    """An organization membership record."""

    user_id: str
    org_id: str
    role: Optional[str] = None


class AddOrgMemberRequest(BaseModel):
    """Request body for POST /admin/orgs/{orgId}/members."""

    user_id: str
    role: Optional[str] = None


class Jwk(BaseModel):
    kty: str
    crv: str
    x: str
    kid: str
    use: str
    alg: str


class JwksDocument(BaseModel):
    keys: List[Jwk]


class IntrospectRequest(BaseModel):
    """Parameters for RFC 7662 token introspection (POST /realms/{realm_id}/introspect)."""

    token: str
    client_id: str
    client_secret: Optional[str] = None
    token_type_hint: Optional[str] = None


class IntrospectResponse(BaseModel):
    """RFC 7662 introspection response.

    The ``mode`` field echoes the ``access_token_authorization`` setting on the issuing
    OAuth client. Middleware MUST reject the token when ``mode`` differs from the
    configured ``expected_mode``.
    """

    active: bool
    sub: Optional[str] = None
    client_id: Optional[str] = None
    scope: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    token_type: Optional[str] = None
    iss: Optional[str] = None
    #: Access-token authorization mode echoed from the issuing client.
    mode: Optional[str] = None
    #: Live-resolved permission set (introspection/decision modes only).
    permissions: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None


class CheckPermissionRequest(BaseModel):
    """Parameters for POST /oauth/authorize (decision endpoint)."""

    permission: str
    organization_id: Optional[str] = None
    resource: Optional[str] = None


class CheckPermissionResponse(BaseModel):
    """Response from POST /oauth/authorize."""

    allowed: bool
    sub: Optional[str] = None
    permission: Optional[str] = None
