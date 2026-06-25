/** §1 — HearthClient: unified entry point for the @hearth-auth/node SDK. */

import type { HearthConfig } from "./config.js";
import { resolveConfig } from "./config.js";
import { DiscoveryClient } from "./discovery.js";
import { JwksVerifier } from "./jwks.js";
import { IntrospectionClient } from "./introspect.js";
import type { IntrospectionResult } from "./introspect.js";
import { AuthorizeClient } from "./authorize.js";
import type { AuthorizeOptions, AuthorizeResult } from "./authorize.js";
import { OAuthFlowsClient } from "./flows.js";
import type {
  TokenResponse,
  DeviceAuthorizationResponse,
  UserInfoResponse,
  MePermissionsResponse,
  SvSnapshotResponse,
  SvDeltaResponse,
  ExchangeCodeOptions,
} from "./flows.js";
import type { VerifiedToken } from "./token.js";

export class HearthClient {
  private readonly verifier: JwksVerifier;
  private readonly introspectionClient: IntrospectionClient;
  private readonly authorizeClient: AuthorizeClient;
  private readonly discovery: DiscoveryClient;
  private readonly flows: OAuthFlowsClient;

  constructor(config: HearthConfig) {
    const resolved = resolveConfig(config);
    this.discovery = new DiscoveryClient(resolved.issuer_url, resolved.http_timeout);
    this.verifier = new JwksVerifier(resolved, this.discovery);
    this.introspectionClient = new IntrospectionClient(resolved, () => this.discovery.discover());
    this.authorizeClient = new AuthorizeClient(resolved);
    this.flows = new OAuthFlowsClient(resolved, () => this.discovery.discover());
  }

  /**
   * Verify a JWT using JWKS-backed EdDSA/Ed25519 local signature verification (spec §2).
   *
   * Performs all five mandatory validation steps: signature, exp, iss, aud, iat.
   * On key miss, re-fetches the JWKS once before failing (handles key rotation).
   * Returns typed `VerifiedToken` on success; throws a typed §5 error on failure.
   */
  async verifyToken(token: string): Promise<VerifiedToken> {
    return this.verifier.verifyToken(token);
  }

  /**
   * Introspect a token per RFC 7662.
   * Returns IntrospectionResult with active, sub, iss, aud, exp, iat, scope, extra.
   */
  async introspect(
    token: string,
    tokenTypeHint?: "access_token" | "refresh_token",
  ): Promise<IntrospectionResult> {
    return this.introspectionClient.introspect(token, tokenTypeHint);
  }

  /**
   * Per-request permission decision via `POST /oauth/authorize` (Decision mode).
   *
   * Fail-closed: returns `{ allowed: false }` on network errors.
   * Throws `AuthorizeError` when the endpoint is misconfigured.
   */
  async authorize(
    token: string,
    permission: string,
    opts?: AuthorizeOptions,
  ): Promise<AuthorizeResult> {
    return this.authorizeClient.decide(token, permission, opts);
  }

  /**
   * Force eviction of the JWKS and discovery caches.
   * Call this after receiving a 401 from a resource server protected by the same issuer.
   */
  invalidateCache(): void {
    this.verifier.invalidateCache();
  }

  // ── §4.5 OAuth Flows ───────────────────────────────────────────────────────

  /**
   * Exchange an authorization code for tokens (RFC 6749 §4.1.3).
   *
   * Discovers the token endpoint from OIDC discovery. Sends credentials as
   * `application/x-www-form-urlencoded` — never as query parameters.
   *
   * @param code - Authorization code from the callback URL.
   * @param redirectUri - Same redirect_uri used in the authorization request.
   * @param opts - Optional PKCE verifier (`codeVerifier`) for PKCE-protected flows.
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    opts?: ExchangeCodeOptions,
  ): Promise<TokenResponse> {
    return this.flows.exchangeCode(code, redirectUri, opts);
  }

  /**
   * Exchange a refresh token for a fresh access token (RFC 6749 §6).
   * The response may carry a rotated `refresh_token`; persist it when present.
   *
   * @param refreshToken - Refresh token previously issued to this client.
   * @param scope - Optional space-delimited scope string.
   */
  async refreshTokens(refreshToken: string, scope?: string): Promise<TokenResponse> {
    return this.flows.refreshTokens(refreshToken, scope);
  }

  /**
   * Obtain a token using the Client Credentials grant (RFC 6749 §4.4).
   * Required for M2M authentication (services, daemons, admin tooling).
   *
   * @param scope - Optional space-delimited scope string.
   */
  async clientCredentials(scope?: string): Promise<TokenResponse> {
    return this.flows.clientCredentials(scope);
  }

  /**
   * Begin a Device Authorization Flow (RFC 8628).
   *
   * Returns the `device_code`, `user_code`, `verification_uri`, and polling `interval`.
   * Pass `device_code` and `interval` to `pollDeviceToken()` to await user approval.
   *
   * @param scope - Optional space-delimited scope string.
   */
  async startDeviceFlow(scope?: string): Promise<DeviceAuthorizationResponse> {
    return this.flows.startDeviceFlow(scope);
  }

  /**
   * Poll the token endpoint until the device flow completes (RFC 8628 §3.5).
   *
   * Resolves with `TokenResponse` on user approval.
   * Throws `TokenExpiredError` when the device code expires.
   * Handles `authorization_pending` and `slow_down` internally — they are not surfaced.
   *
   * @param deviceCode - The `device_code` from `startDeviceFlow()`.
   * @param intervalSeconds - Initial polling interval from `startDeviceFlow().interval`.
   */
  async pollDeviceToken(deviceCode: string, intervalSeconds: number): Promise<TokenResponse> {
    return this.flows.pollDeviceToken(deviceCode, intervalSeconds);
  }

  /**
   * Send a magic-link email for passwordless sign-in (spec §4.5.3).
   *
   * Always succeeds on 202 — enumeration resistant (server returns 202 whether or not
   * the email is registered). HTTP 429 is surfaced as `OAuthFlowError`.
   *
   * Requires `realm_id` in `HearthConfig`.
   *
   * @param email - Email address to send the magic link to.
   */
  async requestMagicLink(email: string): Promise<void> {
    return this.flows.requestMagicLink(email);
  }

  // ── §4 UserInfo & Permissions ──────────────────────────────────────────────

  /**
   * Fetch the OIDC userinfo claims for the bearer token (discovered endpoint).
   *
   * @param token - Access token whose claims to retrieve.
   */
  async userinfo(token: string): Promise<UserInfoResponse> {
    return this.flows.userinfo(token);
  }

  /**
   * Fetch the current user's live RBAC state from `GET /v1/me/permissions`.
   *
   * Unlike JWT embedded claims (cached at issuance), this reflects current server-side
   * role and group assignments.
   *
   * @param token - Access token of the user whose permissions to retrieve.
   */
  async mePermissions(token: string): Promise<MePermissionsResponse> {
    return this.flows.mePermissions(token);
  }

  // ── §HEA-930 Session-version feed ─────────────────────────────────────────

  /**
   * Fetch the full session-version snapshot (HEA-930).
   * Returns all current `{sessionId → minSV}` pairs. Seed a local cache on startup.
   * Requires a token with the `hearth.sv_feed` scope.
   */
  async svSnapshot(token: string): Promise<SvSnapshotResponse> {
    return this.flows.svSnapshot(token);
  }

  /**
   * Fetch session-version deltas since sequence number `since` (HEA-930).
   * Returns `null` when there are no new deltas (HTTP 204 No Content).
   * Requires a token with the `hearth.sv_feed` scope.
   *
   * @param token - Service token with `hearth.sv_feed` scope.
   * @param since - Return only events with `seq > since`.
   * @param limit - Maximum number of deltas to return.
   */
  async svDelta(token: string, since: number, limit?: number): Promise<SvDeltaResponse | null> {
    return this.flows.svDelta(token, since, limit);
  }
}
