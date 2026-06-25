"""Hearth identity platform Python SDK.

Provides HearthClient (auth flows, RBAC predicates), AdminClient
(user/realm CRUD), mode-aware middleware, and all request/response types.
"""

from .client import HearthClient
from .admin import AdminClient
from .errors import (
    HearthError,
    HearthSdkError,
    ConfigurationError,
    DiscoveryError,
    JWKSFetchError,
    TokenExpiredError,
    TokenNotYetValidError,
    TokenInvalidError,
    TokenIssuerError,
    TokenAudienceError,
    IntrospectionError,
    RequiredActionError,
    AuthorizationModeMismatchError,
)
from .claims import Claims
from .middleware import RequirePermissionMiddleware, WsgiPermissionMiddleware
from .pkce import PkcePair, generate_pkce_pair
from .jwks import JwksCache
from .types import (
    AccessTokenAuthorizationMode,
    BootstrapResponse,
    User,
    CreateUserRequest,
    UpdateUserRequest,
    Realm,
    CreateRealmRequest,
    UpdateRealmRequest,
    PageResponse,
    AuthorizeResponse,
    TokenResponse,
    UserInfoResponse,
    MePermissionsResponse,
    OAuthClient,
    RegisterClientRequest,
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
    JwksDocument,
    IntrospectRequest,
    IntrospectResponse,
    CheckPermissionRequest,
    CheckPermissionResponse,
    DeviceAuthorizationResponse,
    SvDeltaEntry,
    SvDeltaResponse,
    SvSnapshotResponse,
)

__all__ = [
    # Clients
    "HearthClient",
    "AdminClient",
    # Middleware
    "RequirePermissionMiddleware",
    "WsgiPermissionMiddleware",
    # PKCE
    "PkcePair",
    "generate_pkce_pair",
    # JWKS cache
    "JwksCache",
    # Errors
    "HearthError",
    "HearthSdkError",
    "ConfigurationError",
    "DiscoveryError",
    "JWKSFetchError",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "TokenInvalidError",
    "TokenIssuerError",
    "TokenAudienceError",
    "IntrospectionError",
    "RequiredActionError",
    "AuthorizationModeMismatchError",
    # Claims
    "Claims",
    # Types
    "AccessTokenAuthorizationMode",
    "BootstrapResponse",
    "User",
    "CreateUserRequest",
    "UpdateUserRequest",
    "Realm",
    "CreateRealmRequest",
    "UpdateRealmRequest",
    "PageResponse",
    "AuthorizeResponse",
    "TokenResponse",
    "UserInfoResponse",
    "MePermissionsResponse",
    "OAuthClient",
    "RegisterClientRequest",
    "CreateClientRequest",
    "UpdateClientRequest",
    "Role",
    "CreateRoleRequest",
    "UpdateRoleRequest",
    "Group",
    "CreateGroupRequest",
    "UpdateGroupRequest",
    "OrgMember",
    "AddOrgMemberRequest",
    "JwksDocument",
    "IntrospectRequest",
    "IntrospectResponse",
    "CheckPermissionRequest",
    "CheckPermissionResponse",
    "DeviceAuthorizationResponse",
    "SvDeltaEntry",
    "SvDeltaResponse",
    "SvSnapshotResponse",
]
