// Primary entry point — recommended for all new integrations.
export { HearthClient } from "./hearth-client.js";

// PKCE browser utilities (RFC 7636).
export {
  generateCodeVerifier,
  generateCodeChallenge,
  buildAuthorizationUrl,
  startLogin,
} from "./pkce.js";
export type {
  BuildAuthorizationUrlOptions,
  AuthorizationUrlResult,
  StartLoginOptions,
  StartLoginResult,
} from "./pkce.js";
export type { HearthClientConfig } from "./hearth-client.js";

// Lower-level primitives (JWKS and introspection).
export { JwksClient } from "./jwks-client.js";
export type { JwksClientConfig } from "./jwks-client.js";
export { IntrospectionClient } from "./introspection-client.js";
export type {
  IntrospectionClientConfig,
  IntrospectionResult,
} from "./introspection-client.js";

// Error types (spec §5).
export {
  AuthorizationModeMismatchError,
  ConfigurationError,
  DiscoveryError,
  HearthSdkError,
  IntrospectionError,
  JWKSFetchError,
  RequiredActionError,
  SessionVersionCacheStaleError,
  SessionVersionRevokedError,
  TokenAudienceError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  TokenNotYetValidError,
} from "./errors.js";

// Mode-aware middleware (HEA-923).
export { requirePermission } from "./middleware.js";
export type { PermissionChecker, RequirePermissionOptions } from "./middleware.js";

// Claims API (spec §4).
export { Claims } from "./claims.js";

// Lower-level API client (kept for backwards-compatibility).
export { HearthApiClient, HearthError } from "./client.js";
export type { HearthApiClientConfig, HandleCallbackParams } from "./client.js";
export { AdminClient } from "./admin.js";
export { createHearth } from "./hearth.js";
export type {
  HearthFacade,
  HearthHttpClient,
  HearthOptions,
} from "./hearth.js";
export {
  HearthContext,
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
  useInOrg,
} from "./react.js";
export type { HearthProviderProps } from "./react.js";
export type {
  AccessTokenAuthorizationMode,
  AuthorizeParams,
  AuthorizePermissionOptions,
  AuthorizeResponse,
  BootstrapResponse,
  CreateRealmParams,
  CreateUserParams,
  JwksDocument,
  JsonWebKey,
  MePermissionsResponse,
  OAuthClient,
  PageResponse,
  RegisterClientParams,
  Realm,
  SessionVersionConfig,
  TokenExchangeParams,
  TokenResponse,
  UpdateRealmParams,
  UpdateUserParams,
  User,
  UserInfoResponse,
} from "./types.js";
export { SessionVersionCache } from "./session-version-cache.js";

// Browser auth: token store + PKCE login facade for SPAs.
export {
  getAccessToken,
  getRefreshToken,
  getIdToken,
  isAuthenticated,
  clearTokens,
  createHearthAuth,
} from "./browser-auth.js";
export type { AuthConfig, HearthBrowserAuth } from "./browser-auth.js";
