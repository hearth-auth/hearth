/** @hearth-auth/node — server-side Hearth SDK for Node.js. Public API surface. */

// §1 — Configuration & unified client
export { HearthClient } from "./client.js";
export type { HearthConfig } from "./config.js";

// §2 — Token verification
export { JwksVerifier } from "./jwks.js";

// §3 — Token introspection
export { IntrospectionClient } from "./introspect.js";
export type { IntrospectionResult } from "./introspect.js";

// §4 — Claims API
export { VerifiedToken } from "./token.js";
export type { AccessTokenAuthorizationMode } from "./token.js";

// §4.5 — OAuth flows (client credentials, device flow, magic-link, exchangeCode)
export { OAuthFlowsClient } from "./flows.js";
export type {
  TokenResponse,
  DeviceAuthorizationResponse,
  UserInfoResponse,
  MePermissionsResponse,
  SvDeltaEntry,
  SvDeltaResponse,
  SvSnapshotResponse,
  ExchangeCodeOptions,
  LoginBeginResult,
} from "./flows.js";

// §PKCE — RFC 7636 code verifier + challenge generation
export { generatePkce } from "./pkce.js";
export type { PkcePair } from "./pkce.js";

// §5 — Error taxonomy
export {
  HearthError,
  ConfigurationError,
  DiscoveryError,
  JWKSFetchError,
  TokenVerificationError,
  TokenExpiredError,
  TokenNotYetValidError,
  TokenInvalidError,
  TokenIssuerError,
  TokenAudienceError,
  TokenClaimsError,
  IntrospectionError,
  MiddlewareError,
  AuthorizationModeError,
  AuthorizeError,
  RequiredActionError,
  AdminHttpError,
  OAuthFlowError,
  SessionVersionRevokedError,
  SessionVersionCacheStaleError,
} from "./errors.js";

// §8 — Managed session-version cache (C-20, RFC HEA-930)
export { SessionVersionCache } from "./session-version-cache.js";
export type { SessionVersionConfig } from "./session-version-cache.js";

// §6 — Middleware
export { hearthMiddleware, hearthFastifyHook } from "./middleware.js";
export type { MiddlewareOptions } from "./middleware.js";

// §7 — Decision client (POST /oauth/authorize)
export { AuthorizeClient } from "./authorize.js";
export type { AuthorizeOptions, AuthorizeResult } from "./authorize.js";

// §12 — Admin SDK
export { AdminClient } from "./admin.js";
export type { AdminClientConfig, PageOptions, PageResponse } from "./admin.js";
