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

/**
 * Response from the token endpoint. `refresh_token` and `id_token` are present
 * only for grants that issue them (a client-credentials grant issues neither).
 */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/** UserInfo response from the OIDC UserInfo endpoint. */
export interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  /** Any other claim the server releases for the granted scopes. */
  [claim: string]: unknown;
}

/** Options for `HearthClient.exchangeCode()`. */
export interface ExchangeCodeOptions {
  /** PKCE code verifier. Required when the authorization request sent a `code_challenge`. */
  codeVerifier?: string;
}

/**
 * Result of `HearthClient.beginLogin()`. Store `state` and `codeVerifier` in
 * the server-side session, then redirect the browser to `authorizationUrl`.
 */
export interface LoginBeginResult {
  /** Full authorization URL to redirect the browser to. */
  authorizationUrl: string;
  /** CSRF value. Check it equals the `state` query parameter on the callback. */
  state: string;
  /** PKCE code verifier. Pass it to `completeLogin()` on the callback. */
  codeVerifier: string;
}

/** Response from `GET /oauth/session-versions/snapshot` (RFC HEA-930). */
export interface SvSnapshotResponse {
  realm: string;
  /** Sequence number to pass as `since` to the first delta call. */
  current_seq: number;
  /** Minimum accepted `sv` per session ID. */
  versions: Record<string, number>;
}

/** One session-version bump in the delta feed (RFC HEA-930). */
export interface SvDeltaEntry {
  seq: number;
  session_id: string;
  min_sv: number;
  bumped_at?: number;
}

/** Response from `GET /oauth/session-versions?since=<seq>` (RFC HEA-930). */
export interface SvDeltaResponse {
  realm: string;
  /** Sequence number to pass as `since` to the next call. */
  next_seq: number;
  deltas: SvDeltaEntry[];
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

/**
 * An assertion from an already-enrolled passkey, offered as a step-up proof.
 * Every field is base64url without padding.
 */
export interface StepUpAssertion {
  credential_id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
  user_handle?: string | null;
}

/**
 * Proof that the caller holds a credential the account already has.
 *
 * Passkey enrolment refuses a request that carries no proof: an access token
 * alone is one factor, and enrolling with it would turn a stolen token into a
 * permanent credential. Supply exactly one field.
 */
export type StepUpProof =
  { password: string } | { totp_code: string } | { assertion: StepUpAssertion };

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

/**
 * A user's lifecycle status, as `PATCH /admin/users/{id}` accepts it: the
 * proto enum name. The server refuses the short form (`"active"`).
 */
export type UserStatus =
  "USER_STATUS_ACTIVE" | "USER_STATUS_DISABLED" | "USER_STATUS_PENDING_VERIFICATION";

/** Parameters for updating a user. */
export interface UpdateUserParams {
  email?: string;
  displayName?: string;
  status?: UserStatus;
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
/**
 * Realm patch shape. No client method sends it: realms are provisioned from
 * `hearth.yaml` and `PATCH /admin/realms/{id}` answers 405 (audit
 * 2026-08-28 §25.4).
 */
export interface UpdateRealmParams {
  name?: string;
  status?: string;
  config?: Record<string, unknown>;
}

/** Pagination options for admin list calls. */
export interface PageOptions {
  /** Maximum number of items to return. */
  limit?: number;
  /** `next_cursor` from the previous page. */
  cursor?: string;
}

/** Paginated list response. */
export interface PageResponse<T> {
  items: T[];
  next_cursor: string | null;
}

/**
 * A client's trust level. `first_party` is an operator-owned client: it needs
 * no user consent and may receive the user's RBAC claims. `third_party` (the
 * server default) needs consent and never receives first-party-only claims.
 */
export type ClientTrustLevel = "first_party" | "third_party";

/** Parameters for registering an OAuth client. */
export interface RegisterClientParams {
  clientName: string;
  redirectUris: string[];
  /** Optional; when omitted the server default (`third_party`) applies. */
  trustLevel?: ClientTrustLevel;
  /**
   * Optional (RFC 7591 §2). `client_secret_basic` or `client_secret_post`
   * creates a confidential client: the server generates its secret and
   * returns it once, as `client_secret` on the created record. Omitted
   * registers a public client.
   */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
}

/** How a client authenticates at the token endpoint (RFC 7591 §2). */
export type TokenEndpointAuthMethod =
  "client_secret_basic" | "client_secret_post" | "private_key_jwt" | "none";

/** OAuth client record from the API. */
export interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  created_at?: number;
  /**
   * The generated secret — present only on the response that created a
   * confidential client, and never returned again. Store it on receipt.
   */
  client_secret?: string;
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
