"""Hearth identity platform Python SDK.

Provides HearthClient (auth flows, RBAC predicates), AdminClient
(user/realm CRUD), mode-aware middleware, and all request/response types.
"""

from .admin import AdminClient
from .client import HearthClient

# FastAPI adapter — only importable when fastapi/starlette are installed.
# Access via: from hearth.fastapi import HearthFastAPIDep, require_permission, ...
try:
    # `X as X` marks these as deliberate re-exports (they stay out of __all__
    # because the optional extra may be missing).
    from .fastapi import HearthFastAPIDep as HearthFastAPIDep
    from .fastapi import HearthSettings as HearthSettings
    from .fastapi import VerifiedClaims as VerifiedClaims
    from .fastapi import require_permission as require_permission

    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

# Django adapter — only importable when django is installed.
# Access via: from hearth.django import HearthDjangoMiddleware, require_permission
try:
    from .django import HearthDjangoMiddleware as HearthDjangoMiddleware

    _DJANGO_AVAILABLE = True
except ImportError:
    _DJANGO_AVAILABLE = False
from .claims import Claims
from .errors import (
    AuthorizationModeMismatchError,
    ConfigurationError,
    DiscoveryError,
    HearthError,
    HearthSdkError,
    IntrospectionError,
    JWKSFetchError,
    RequiredActionError,
    TokenAudienceError,
    TokenExpiredError,
    TokenInvalidError,
    TokenIssuerError,
    TokenNotYetValidError,
)
from .jwks import JwksCache
from .middleware import RequirePermissionMiddleware, WsgiPermissionMiddleware
from .pkce import PkcePair, generate_pkce_pair
from .types import (
    AccessTokenAuthorizationMode,
    AuthorizeResponse,
    BootstrapResponse,
    CheckPermissionRequest,
    CheckPermissionResponse,
    CreateClientRequest,
    CreateGroupRequest,
    CreateOrganizationRequest,
    CreateRoleRequest,
    CreateUserRequest,
    DeviceAuthorizationResponse,
    Group,
    IntrospectRequest,
    IntrospectResponse,
    JwksDocument,
    LoginBeginResult,
    MePermissionsResponse,
    OAuthClient,
    Organization,
    PageResponse,
    Realm,
    RegisterClientRequest,
    Role,
    SvDeltaEntry,
    SvDeltaResponse,
    SvSnapshotResponse,
    TokenResponse,
    UpdateClientRequest,
    UpdateGroupRequest,
    UpdateOrganizationRequest,
    UpdateRealmRequest,
    UpdateRoleRequest,
    UpdateUserRequest,
    User,
    UserInfoResponse,
)

# Grouped by category (the comments below), not alphabetically.
__all__ = [  # noqa: RUF022
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
    "Organization",
    "CreateOrganizationRequest",
    "UpdateOrganizationRequest",
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
