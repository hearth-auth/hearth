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
export type { HearthClientConfig, OidcConfiguration } from "./hearth-client.js";

// Lower-level primitives (JWKS and introspection).
export { JwksClient } from "./jwks-client.js";
export type { JwksClientConfig, VerifyOptions } from "./jwks-client.js";
export { IntrospectionClient } from "./introspection-client.js";
export type { IntrospectionClientConfig, IntrospectionResult } from "./introspection-client.js";

// Error types (spec §5).
export {
  AuthorizationModeMismatchError,
  ConfigurationError,
  DiscoveryError,
  HearthSdkError,
  IntrospectionError,
  JWKSFetchError,
  OAuthFlowError,
  RequiredActionError,
  SessionVersionCacheStaleError,
  SessionVersionRevokedError,
  TokenAudienceError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  TokenNotYetValidError,
  TokenVerificationError,
} from "./errors.js";

// Mode-aware permission checks and request middleware (HEA-923).
// Next.js helpers live at `@hearth-auth/sdk/nextjs` and `@hearth-auth/sdk/nextjs/edge`.
export {
  assertMiddlewareOptions,
  authenticateRequest,
  hearthFastifyHook,
  hearthMiddleware,
  requirePermission,
} from "./middleware.js";
export type {
  FastifyReplyLike,
  FastifyRequestLike,
  HearthAuthErrorBody,
  HearthAuthResult,
  HearthMiddlewareOptions,
  MiddlewareRequest,
  MiddlewareResponse,
  PermissionChecker,
  RequirePermissionOptions,
} from "./middleware.js";

// Claims API (spec §4).
export { Claims } from "./claims.js";

// Lower-level API client (kept for backwards-compatibility).
export { HearthApiClient, HearthError } from "./client.js";
export type { HearthApiClientConfig, HandleCallbackParams } from "./client.js";
export { AdminClient } from "./admin.js";
export type { CreateOrganizationParams, Organization, UpdateOrganizationParams } from "./admin.js";
export { createHearth } from "./hearth.js";
export type { HearthFacade, HearthHttpClient, HearthOptions } from "./hearth.js";
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
  CreateUserParams,
  ExchangeCodeOptions,
  JwksDocument,
  JsonWebKey,
  LoginBeginResult,
  MePermissionsResponse,
  OAuthClient,
  PageOptions,
  PageResponse,
  RegisterClientParams,
  Realm,
  SessionVersionConfig,
  StepUpAssertion,
  StepUpProof,
  SvDeltaEntry,
  SvDeltaResponse,
  SvSnapshotResponse,
  TokenExchangeParams,
  DeviceAuthorizationResponse,
  TokenResponse,
  UpdateRealmParams,
  UpdateUserParams,
  User,
  UserInfoResponse,
  WebAuthnAllowCredential,
  WebAuthnRegistrationBeginResponse,
  WebAuthnRegistrationCompleteRequest,
  WebAuthnRegistrationCompleteResponse,
  WebAuthnAuthenticationBeginResponse,
  WebAuthnAuthenticationCompleteRequest,
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
