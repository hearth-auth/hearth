"""Hearth identity platform Python SDK.

Provides HearthClient (auth flows, RBAC predicates), AdminClient
(user/realm CRUD), mode-aware middleware, and all request/response types.
"""

from .client import HearthClient
from .admin import AdminClient

# FastAPI adapter — only importable when fastapi/starlette are installed.
# Access via: from hearth.fastapi import HearthFastAPIDep, require_permission, ...
try:
    from .fastapi import HearthFastAPIDep, HearthSettings, VerifiedClaims, require_permission
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

# Django adapter — only importable when django is installed.
# Access via: from hearth.django import HearthDjangoMiddleware, require_permission
try:
    from .django import HearthDjangoMiddleware
    _DJANGO_AVAILABLE = True
except ImportError:
    _DJANGO_AVAILABLE = False
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
    LoginBeginResult,
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
    # Login helpers
    "LoginBeginResult",
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
