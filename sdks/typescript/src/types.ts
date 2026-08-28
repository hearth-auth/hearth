/** Response from the dev bootstrap endpoint. */
export interface BootstrapResponse {
  realm_id: string;
  user_id: string;
  access_token: string;
  refresh_token: string;
}

/** Parameters for initiating an authorization code flow. */
export interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  responseType?: string;
  userId: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
}

/** Response from the authorize endpoint. */
export interface AuthorizeResponse {
  code: string;
  state: string;
}

/** Parameters for exchanging an authorization code. */
export interface TokenExchangeParams {
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
}

/** RFC 8628 device authorization response. */
export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  /** Pre-filled URI with user_code (when provided by server). */
  verification_uri_complete?: string;
  expires_in: number;
  /** Minimum polling interval in seconds. */
  interval: number;
}

/** Response from the token exchange endpoint. */
export interface TokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}

/** UserInfo response from the OIDC UserInfo endpoint. */
export interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
}

// ── WebAuthn / passkeys (C-21) ──────────────────────────────────────────────
// Wire shapes mirror the Go/Python/Rust SDKs so callers can move between SDKs
// without re-learning field names. The browser feeds `*BeginResponse` options
// into `navigator.credentials.create()/get()` and posts the result back via the
// `*CompleteRequest` shapes.

/** An entry in the `allow_credentials` list during a WebAuthn authentication ceremony. */
export interface WebAuthnAllowCredential {
  id: string;
  type: string;
}

/** `PublicKeyCredentialCreationOptions` returned by `/webauthn/register/begin`. */
export interface WebAuthnRegistrationBeginResponse {
  challenge: string;
  rp_id: string;
  rp_name: string;
  user_id: string;
  user_name: string;
  user_display_name: string;
  attestation: string;
  timeout: number;
}

/** Browser attestation posted to `/webauthn/register/complete`. */
export interface WebAuthnRegistrationCompleteRequest {
  client_data_json: string;
  attestation_object: string;
  origin: string;
  discoverable?: boolean;
}

/** Result of a successful passkey registration. */
export interface WebAuthnRegistrationCompleteResponse {
  credential_id: string;
  algorithm: number;
  discoverable: boolean;
}

/** `PublicKeyCredentialRequestOptions` returned by `/webauthn/auth/begin`. */
export interface WebAuthnAuthenticationBeginResponse {
  challenge: string;
  rp_id: string;
  allow_credentials: WebAuthnAllowCredential[];
  user_verification: string;
  timeout: number;
}

/** Browser-signed assertion posted to `/webauthn/auth/complete`. */
export interface WebAuthnAuthenticationCompleteRequest {
  credential_id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
  /** Present for discoverable-credential (resident-key) flows. */
  user_handle?: string;
  origin: string;
}

/** Parameters for creating a user. */
export interface CreateUserParams {
  email: string;
  displayName: string;
}

/** User record from the API. */
export interface User {
  id: string;
  email: string;
  display_name: string;
  status: string;
  created_at?: number;
  updated_at?: number;
}

/** Parameters for updating a user. */
export interface UpdateUserParams {
  email?: string;
  displayName?: string;
  status?: string;
}

/** Realm record from the API. */
export interface Realm {
  id: string;
  name: string;
  status: string;
  config: Record<string, unknown> | null;
  created_at?: number;
  updated_at?: number;
}

/** Parameters for updating a realm. */
export interface UpdateRealmParams {
  name?: string;
  status?: string;
  config?: Record<string, unknown>;
}

/** Paginated list response. */
export interface PageResponse<T> {
  items: T[];
  next_cursor: string | null;
}

/** Parameters for registering an OAuth client. */
export interface RegisterClientParams {
  clientName: string;
  redirectUris: string[];
}

/** OAuth client record from the API. */
export interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  created_at?: number;
}

/** JWKS document containing public keys. */
export interface JwksDocument {
  keys: JsonWebKey[];
}

/** A single JWK entry. */
export interface JsonWebKey {
  kty: string;
  crv?: string;
  x?: string;
  kid?: string;
  use?: string;
  alg?: string;
}

/**
 * Response from `GET /v1/me/permissions`.
 *
 * Returns the freshly-resolved RBAC claim set for the bearer-token user.
 */
export interface MePermissionsResponse {
  roles: string[];
  groups: string[];
  permissions: string[];
  scope: string;
}

/** The three permission delivery modes introduced in HEA-922. */
export type AccessTokenAuthorizationMode = "embedded" | "introspection" | "decision";

/** Options for a per-request permission decision call to `POST /oauth/authorize`. */
export interface AuthorizePermissionOptions {
  /** Constrain the decision to a specific organization. */
  organizationId?: string;
  /** Constrain the decision to a specific resource. */
  resource?: string;
}

/**
 * Configuration for the client-side session-version cache (RFC HEA-930 § 13).
 *
 * When enabled, the SDK fetches a snapshot of `{sessionId → minSv}` on startup,
 * polls `GET /oauth/session-versions` for deltas at `pollIntervalMs` intervals,
 * and validates the `sv` claim on every `hasPermission` / `hasRole` / `inGroup`
 * / `inOrg` call without any per-request network hop.
 */
export interface SessionVersionConfig {
  /** Whether session-version validation is enabled. */
  enabled: boolean;
  /** Delta feed poll interval in milliseconds. Recommended: 5 000. */
  pollIntervalMs: number;
  /**
   * Maximum cache age before the cache is considered stale, in milliseconds.
   * MUST be greater than `pollIntervalMs`. Recommended: `pollIntervalMs × 3`.
   */
  staleThresholdMs: number;
  /**
   * Action when the cache exceeds `staleThresholdMs`:
   * - `"reject"` — throw {@link SessionVersionCacheStaleError} (fail-closed).
   * - `"introspect"` — caller should catch {@link SessionVersionCacheStaleError}
   *   and fall back to the introspection endpoint.
   */
  onStale: "reject" | "introspect";
  /**
   * Service-to-service access token with `hearth.sv_feed` scope.
   * Required when `enabled` is `true`.
   */
  serviceToken: string;
}
