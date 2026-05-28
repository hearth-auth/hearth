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
    AuthorizationModeMismatchError,
)
from .claims import Claims
from .middleware import RequirePermissionMiddleware, WsgiPermissionMiddleware
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
    JwksDocument,
    IntrospectRequest,
    IntrospectResponse,
    CheckPermissionRequest,
    CheckPermissionResponse,
)

__all__ = [
    # Clients
    "HearthClient",
    "AdminClient",
    # Middleware
    "RequirePermissionMiddleware",
    "WsgiPermissionMiddleware",
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
    "JwksDocument",
    "IntrospectRequest",
    "IntrospectResponse",
    "CheckPermissionRequest",
    "CheckPermissionResponse",
]
