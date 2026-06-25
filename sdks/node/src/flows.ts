/**
 * §4.5 — OAuth flow helpers: exchangeCode, clientCredentials, device flow,
 * magic-link, userinfo, /me/permissions, and session-version feed.
 */

import { ConfigurationError, OAuthFlowError, TokenExpiredError } from "./errors.js";
import type { ResolvedConfig } from "./config.js";
import type { OidcDiscovery } from "./discovery.js";

// ── Response type definitions ─────────────────────────────────────────────────

/** Standard OAuth 2.0 token endpoint response. */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

/** RFC 8628 device authorization response. */
export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  /** Pre-filled URI (when provided by server). */
  verification_uri_complete?: string;
  expires_in: number;
  /** Minimum polling interval in seconds. */
  interval: number;
}

/** OIDC userinfo endpoint response. */
export interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  [key: string]: unknown;
}

/**
 * Live RBAC state from `GET /v1/me/permissions`.
 * Unlike JWT claims (which are cached), this reflects the server's current assignments.
 */
export interface MePermissionsResponse {
  roles: string[];
  groups: string[];
  permissions: string[];
  scope?: string;
}

/** A single session-version bump event (HEA-930). */
export interface SvDeltaEntry {
  seq: number;
  session_id: string;
  min_sv: number;
  bumped_at?: number;
}

/** Response from `GET /oauth/session-versions?since=<seq>` (HEA-930). */
export interface SvDeltaResponse {
  realm: string;
  next_seq: number;
  deltas: SvDeltaEntry[];
}

/** Response from `GET /oauth/session-versions/snapshot` (HEA-930). */
export interface SvSnapshotResponse {
  realm: string;
  current_seq: number;
  versions: Record<string, number>;
}

/** Options for the `exchangeCode` method. */
export interface ExchangeCodeOptions {
  /** PKCE verifier from `generatePkce()`. Required when the auth request included a code_challenge. */
  codeVerifier?: string;
}

// ── OAuthFlowsClient ──────────────────────────────────────────────────────────

/**
 * Handles OAuth 2.0 flows, userinfo, /me/permissions, and the session-version feed.
 * Discovers all endpoint URLs from OIDC discovery — no hard-coded paths.
 */
export class OAuthFlowsClient {
  private readonly config: ResolvedConfig;
  private readonly getDiscovery: () => Promise<OidcDiscovery>;
  private readonly timeout: number;

  constructor(config: ResolvedConfig, getDiscovery: () => Promise<OidcDiscovery>) {
    this.config = config;
    this.getDiscovery = getDiscovery;
    this.timeout = config.http_timeout;
  }

  // ── Discovery helpers ──────────────────────────────────────────────────────

  private async getTokenEndpoint(): Promise<string> {
    const doc = await this.getDiscovery();
    if (!doc.token_endpoint) {
      throw new ConfigurationError("token_endpoint not found in OIDC discovery document");
    }
    return doc.token_endpoint;
  }

  private async getDeviceAuthEndpoint(): Promise<string> {
    const doc = await this.getDiscovery();
    if (!doc.device_authorization_endpoint) {
      throw new ConfigurationError(
        "device_authorization_endpoint not found in OIDC discovery document",
      );
    }
    return doc.device_authorization_endpoint;
  }

  private async getUserInfoEndpoint(): Promise<string> {
    const doc = await this.getDiscovery();
    if (!doc.userinfo_endpoint) {
      throw new ConfigurationError("userinfo_endpoint not found in OIDC discovery document");
    }
    return doc.userinfo_endpoint;
  }

  // ── HTTP primitives ────────────────────────────────────────────────────────

  /** POST application/x-www-form-urlencoded; decode JSON response. */
  private async postForm<T>(endpoint: string, params: Record<string, string>): Promise<T> {
    const body = new URLSearchParams(params);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    let res: Response;
    try {
      res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
        signal: controller.signal,
      });
    } catch (err) {
      throw new OAuthFlowError(
        0,
        `Request failed: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      let message = `HTTP ${res.status}`;
      try {
        const json = (await res.json()) as Record<string, unknown>;
        if (typeof json.error === "string") {
          message = json.error;
          if (typeof json.error_description === "string") {
            message += `: ${json.error_description}`;
          }
        }
      } catch { /* ignore parse failure */ }
      throw new OAuthFlowError(res.status, message);
    }

    return res.json() as Promise<T>;
  }

  /** GET with Bearer token; returns null on 204 No Content. */
  private async getWithBearer<T>(
    endpoint: string,
    token: string,
    params?: Record<string, string>,
  ): Promise<T | null> {
    let url = endpoint;
    if (params) {
      const u = new URL(endpoint);
      for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
      url = u.toString();
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    let res: Response;
    try {
      res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      });
    } catch (err) {
      throw new OAuthFlowError(
        0,
        `Request failed: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 204) return null;

    if (!res.ok) {
      throw new OAuthFlowError(res.status, `HTTP ${res.status}`);
    }

    return res.json() as Promise<T>;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Exchange an authorization code for tokens (RFC 6749 §4.1.3).
   *
   * Discovers the token endpoint from OIDC discovery. Sends credentials as
   * `application/x-www-form-urlencoded` — never as query parameters.
   *
   * @param code - Authorization code from the callback URL.
   * @param redirectUri - The same redirect_uri used in the authorization request.
   * @param opts - Optional PKCE verifier (`codeVerifier`) for PKCE-protected flows.
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    opts?: ExchangeCodeOptions,
  ): Promise<TokenResponse> {
    const endpoint = await this.getTokenEndpoint();
    const params: Record<string, string> = {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: this.config.client_id,
      client_secret: this.config.client_secret,
    };
    if (opts?.codeVerifier) params.code_verifier = opts.codeVerifier;
    return this.postForm<TokenResponse>(endpoint, params);
  }

  /**
   * Exchange a refresh token for a fresh access token (RFC 6749 §6).
   *
   * Posts `grant_type=refresh_token` to the discovered token endpoint with the
   * confidential client's credentials in the body (never the URL). The server may
   * return a rotated `refresh_token` — callers must replace the stored token with
   * the one in the response when present.
   *
   * @param refreshToken - The refresh token previously issued to this client.
   * @param scope - Optional space-delimited scope string (must not widen the grant).
   */
  async refreshTokens(refreshToken: string, scope?: string): Promise<TokenResponse> {
    const endpoint = await this.getTokenEndpoint();
    const params: Record<string, string> = {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.client_id,
      client_secret: this.config.client_secret,
    };
    if (scope) params.scope = scope;
    return this.postForm<TokenResponse>(endpoint, params);
  }

  /**
   * Obtain a token using the Client Credentials grant (RFC 6749 §4.4).
   *
   * Required for M2M authentication (services, daemons, admin tooling acting as
   * their own principal). Credentials are sent in the POST body, never in the URL.
   *
   * @param scope - Optional space-delimited scope string.
   */
  async clientCredentials(scope?: string): Promise<TokenResponse> {
    const endpoint = await this.getTokenEndpoint();
    const params: Record<string, string> = {
      grant_type: "client_credentials",
      client_id: this.config.client_id,
      client_secret: this.config.client_secret,
    };
    if (scope) params.scope = scope;
    return this.postForm<TokenResponse>(endpoint, params);
  }

  /**
   * Begin a Device Authorization Flow (RFC 8628).
   *
   * Returns the `device_code`, `user_code`, `verification_uri`, and `interval`.
   * Present the `user_code` and `verification_uri` to the user, then call
   * `pollDeviceToken(device_code, interval)` to await approval.
   *
   * @param scope - Optional space-delimited scope string.
   */
  async startDeviceFlow(scope?: string): Promise<DeviceAuthorizationResponse> {
    const endpoint = await this.getDeviceAuthEndpoint();
    const params: Record<string, string> = { client_id: this.config.client_id };
    if (scope) params.scope = scope;
    return this.postForm<DeviceAuthorizationResponse>(endpoint, params);
  }

  /**
   * Poll the token endpoint until the device flow completes (RFC 8628 §3.5).
   *
   * Blocks until:
   * - User approves → resolves with `TokenResponse`.
   * - Device code expires → rejects with `TokenExpiredError`.
   * - Fatal error → rejects with `OAuthFlowError`.
   *
   * Handles `authorization_pending` by continuing to poll without surfacing
   * an error to the caller. Handles `slow_down` by increasing the interval
   * by 5 s per occurrence as required by RFC 8628 §3.5.
   *
   * @param deviceCode - The `device_code` from `startDeviceFlow()`.
   * @param intervalSeconds - Initial polling interval from `startDeviceFlow().interval`.
   */
  async pollDeviceToken(deviceCode: string, intervalSeconds: number): Promise<TokenResponse> {
    const endpoint = await this.getTokenEndpoint();
    let intervalMs = intervalSeconds * 1000;

    // eslint-disable-next-line no-constant-condition
    while (true) {
      await new Promise<void>((resolve) => setTimeout(resolve, intervalMs));

      const body = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: this.config.client_id,
      });

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);
      let res: Response;
      try {
        res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body,
          signal: controller.signal,
        });
      } catch (err) {
        throw new OAuthFlowError(
          0,
          `Device token poll failed: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      } finally {
        clearTimeout(timer);
      }

      if (res.ok) {
        return res.json() as Promise<TokenResponse>;
      }

      let errorCode = "";
      try {
        const json = (await res.json()) as Record<string, unknown>;
        errorCode = typeof json.error === "string" ? json.error : "";
      } catch { /* ignore */ }

      if (errorCode === "authorization_pending") {
        continue;
      }
      if (errorCode === "slow_down") {
        intervalMs += 5000;
        continue;
      }
      if (errorCode === "expired_token") {
        throw new TokenExpiredError(new Date(), { cause: new Error("device code expired") });
      }

      throw new OAuthFlowError(
        res.status,
        `Device token poll failed: ${errorCode || `HTTP ${res.status}`}`,
      );
    }
  }

  /**
   * Send a magic-link email for passwordless sign-in (spec §4.5.3).
   *
   * Per enumeration-resistance requirements, the server always returns 202
   * regardless of whether the email is registered. This method always
   * succeeds on 202 — it does NOT surface "user not found" errors.
   * HTTP 429 (Too Many Requests) is surfaced as `OAuthFlowError`.
   *
   * Requires `realm_id` in the HearthConfig.
   *
   * @param email - Email address to send the magic link to.
   */
  async requestMagicLink(email: string): Promise<void> {
    if (!this.config.realm_id) {
      throw new ConfigurationError(
        "realm_id is required for requestMagicLink — set it in HearthConfig",
      );
    }

    const url = `${this.config.issuer_url}/v1/${this.config.realm_id}/auth/magic-link`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
        signal: controller.signal,
      });
    } catch (err) {
      throw new OAuthFlowError(
        0,
        `Magic-link request failed: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 202) return;
    throw new OAuthFlowError(res.status, `Magic-link request returned HTTP ${res.status}`);
  }

  /**
   * Exchange a magic-link token for tokens (spec §4.5.3 / §7.2 C-12).
   *
   * Completes the passwordless flow started by {@link requestMagicLink}: posts
   * `grant_type=urn:hearth:grant-type:magic-link` with the opaque `token` from
   * the magic-link URL to the discovered token endpoint. The token is sent in
   * the body, never the URL.
   *
   * @param token - The opaque magic-link token from the email/redirect URL.
   */
  async exchangeMagicLink(token: string): Promise<TokenResponse> {
    const endpoint = await this.getTokenEndpoint();
    const params: Record<string, string> = {
      grant_type: "urn:hearth:grant-type:magic-link",
      token,
      client_id: this.config.client_id,
    };
    return this.postForm<TokenResponse>(endpoint, params);
  }

  /**
   * Fetch the OIDC userinfo claims for the bearer token (discovered endpoint).
   *
   * @param token - Access token whose claims to retrieve.
   */
  async userinfo(token: string): Promise<UserInfoResponse> {
    const endpoint = await this.getUserInfoEndpoint();
    const result = await this.getWithBearer<UserInfoResponse>(endpoint, token);
    if (!result) throw new OAuthFlowError(204, "userinfo returned 204 No Content");
    return result;
  }

  /**
   * Fetch the current user's live RBAC state from `GET /v1/me/permissions`.
   *
   * Unlike JWT embedded claims (cached at issuance), this reflects the server's
   * current role and group assignments.
   *
   * @param token - Access token of the user whose permissions to retrieve.
   */
  async mePermissions(token: string): Promise<MePermissionsResponse> {
    const url = `${this.config.issuer_url}/v1/me/permissions`;
    const result = await this.getWithBearer<MePermissionsResponse>(url, token);
    if (!result) throw new OAuthFlowError(204, "mePermissions returned 204 No Content");
    return result;
  }

  /**
   * Fetch the full session-version snapshot (HEA-930).
   *
   * Returns all current `{sessionId → minSV}` pairs. Used to seed a local
   * session-version cache on startup. Requires a token with `hearth.sv_feed` scope.
   *
   * @param token - Service token with `hearth.sv_feed` scope.
   */
  async svSnapshot(token: string): Promise<SvSnapshotResponse> {
    const url = `${this.config.issuer_url}/oauth/session-versions/snapshot`;
    const result = await this.getWithBearer<SvSnapshotResponse>(url, token);
    if (!result) throw new OAuthFlowError(204, "svSnapshot returned 204 No Content");
    return result;
  }

  /**
   * Fetch session-version deltas since sequence number `since` (HEA-930).
   *
   * Returns `null` when there are no new deltas (HTTP 204 No Content).
   * Requires a token with `hearth.sv_feed` scope.
   *
   * @param token - Service token with `hearth.sv_feed` scope.
   * @param since - Return only events with `seq > since`.
   * @param limit - Maximum number of deltas to return (server default applies when omitted).
   */
  async svDelta(
    token: string,
    since: number,
    limit?: number,
  ): Promise<SvDeltaResponse | null> {
    const url = `${this.config.issuer_url}/oauth/session-versions`;
    const params: Record<string, string> = { since: String(since) };
    if (limit !== undefined) params.limit = String(limit);
    return this.getWithBearer<SvDeltaResponse>(url, token, params);
  }
}
