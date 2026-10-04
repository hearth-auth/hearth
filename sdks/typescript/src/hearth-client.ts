import {
  AuthorizationModeMismatchError,
  ConfigurationError,
  DiscoveryError,
  OAuthFlowError,
  TokenExpiredError,
} from "./errors.js";
import { DEFAULT_AUDIENCE, JwksClient } from "./jwks-client.js";
import { IntrospectionClient, type IntrospectionResult } from "./introspection-client.js";
import type {
  AccessTokenAuthorizationMode,
  AuthorizePermissionOptions,
  DeviceAuthorizationResponse,
  ExchangeCodeOptions,
  LoginBeginResult,
  MePermissionsResponse,
  SvDeltaResponse,
  SvSnapshotResponse,
  TokenResponse,
  UserInfoResponse,
} from "./types.js";
import { Claims } from "./claims.js";
import { buildAuthorizationUrl, generateCodeChallenge, generateCodeVerifier } from "./pkce.js";

/** Configuration for {@link HearthClient}. */
export interface HearthClientConfig {
  /**
   * Root URL of the Hearth instance, e.g. `https://auth.example.com`.
   * Required. Must be a valid HTTPS URL.
   */
  issuerUrl: string;
  /**
   * OAuth 2.0 client ID.
   * Required for flows that need a client identity (e.g. introspection).
   */
  clientId?: string;
  /**
   * Expected `aud` of the access tokens {@link HearthClient.verifyToken}
   * accepts: the name of this API (RFC 9068 §4), not the client ID.
   * Default: `"hearth"`, the audience Hearth mints when a client names no
   * resource. An API registered as a protected resource sets its resource URI.
   * The check is always on.
   */
  audience?: string;
  /**
   * OAuth 2.0 client secret.
   * Required for confidential client flows (e.g. introspection).
   */
  clientSecret?: string;
  /**
   * Override JWKS cache TTL in milliseconds.
   * Default: respect `Cache-Control: max-age` from the JWKS endpoint,
   * falling back to 5 minutes.
   */
  jwksTtl?: number;
  /**
   * Override the introspection endpoint URL discovered via OIDC discovery.
   * When absent, the URL is taken from `introspection_endpoint` in the
   * OIDC discovery document.
   */
  introspectionEndpoint?: string;
  /**
   * Timeout for all outbound HTTP calls in milliseconds.
   * Default: 10 000 (10 seconds).
   */
  httpTimeout?: number;
  /**
   * Realm ID sent as `X-Realm-ID` on realm-scoped requests.
   * Required for `authorize()` and the `requirePermission()` middleware in
   * `decision` mode.
   */
  realmId?: string;
  /**
   * Expected access-token authorization mode for this resource server.
   *
   * When set, `introspect()` validates the `mode` field echoed in the
   * introspection response and throws {@link AuthorizationModeMismatchError}
   * if they differ.
   */
  expectedMode?: AccessTokenAuthorizationMode;
}

/** The OIDC discovery document fields the SDK reads. */
export interface OidcConfiguration {
  issuer: string;
  jwks_uri: string;
  introspection_endpoint?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  device_authorization_endpoint?: string;
  userinfo_endpoint?: string;
  [key: string]: unknown;
}

/** Discovery fields that hold an endpoint URL. */
type EndpointField =
  | "authorization_endpoint"
  | "token_endpoint"
  | "device_authorization_endpoint"
  | "userinfo_endpoint";

/**
 * Primary entry point for the Hearth SDK.
 *
 * Accepts a single configuration object, auto-discovers all endpoint URLs
 * from `{issuerUrl}/.well-known/openid-configuration` on first use, and
 * applies `httpTimeout` to every outbound fetch call.
 *
 * Lower-level access is available via {@link JwksClient} and
 * {@link IntrospectionClient}.
 */
export class HearthClient {
  /** Issuer URL, trailing slash removed. */
  readonly issuerUrl: string;
  readonly clientId: string | undefined;
  readonly clientSecret: string | undefined;
  /** Expected `aud` of verified access tokens. Default `"hearth"`. */
  readonly audience: string;
  readonly jwksTtl: number | undefined;
  readonly introspectionEndpointOverride: string | undefined;
  /** HTTP timeout in milliseconds applied to all outbound fetch calls. */
  readonly httpTimeout: number;
  /** Realm ID for realm-scoped endpoints (e.g. `/oauth/authorize`). */
  readonly realmId: string | undefined;
  /** Expected authorization mode; validated on `introspect()` when present. */
  readonly expectedMode: AccessTokenAuthorizationMode | undefined;

  private _discovery: OidcConfiguration | null = null;
  private _discoveryInFlight: Promise<OidcConfiguration> | null = null;
  private _jwksClient: JwksClient | null = null;
  private _introspectionClient: IntrospectionClient | null = null;

  constructor(config: HearthClientConfig) {
    if (!config.issuerUrl) {
      throw new ConfigurationError("issuerUrl is required");
    }
    try {
      new URL(config.issuerUrl);
    } catch {
      throw new ConfigurationError(`issuerUrl "${config.issuerUrl}" is not a valid URL`);
    }

    this.issuerUrl = config.issuerUrl.replace(/\/$/, "");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    if (config.audience === "") {
      throw new ConfigurationError(
        'audience must not be empty — leave it unset for the default "hearth"',
      );
    }
    this.audience = config.audience ?? DEFAULT_AUDIENCE;
    this.jwksTtl = config.jwksTtl;
    this.introspectionEndpointOverride = config.introspectionEndpoint;
    this.httpTimeout = config.httpTimeout ?? 10_000;
    this.realmId = config.realmId;
    this.expectedMode = config.expectedMode;
  }

  /**
   * Fetches and caches the OIDC discovery document from
   * `{issuerUrl}/.well-known/openid-configuration`.
   *
   * Concurrent callers share one request. A failed fetch is not cached.
   *
   * Throws {@link DiscoveryError} when the endpoint is unreachable,
   * returns a non-2xx status, or returns invalid JSON.
   */
  async discover(): Promise<OidcConfiguration> {
    if (this._discovery) return this._discovery;
    if (!this._discoveryInFlight) {
      this._discoveryInFlight = this.fetchDiscovery().finally(() => {
        this._discoveryInFlight = null;
      });
    }
    return this._discoveryInFlight;
  }

  /**
   * Drop the cached discovery document, JWKS key set and introspection client.
   * The next call fetches them again. Call it after the issuer rotates keys or
   * changes endpoints, or after a resource server answers 401 for a token you
   * believe is valid.
   */
  invalidateCache(): void {
    this._discovery = null;
    this._discoveryInFlight = null;
    this._jwksClient = null;
    this._introspectionClient = null;
  }

  private async fetchDiscovery(): Promise<OidcConfiguration> {
    const url = `${this.issuerUrl}/.well-known/openid-configuration`;
    let resp: Response;
    try {
      resp = await fetch(url, {
        signal: AbortSignal.timeout(this.httpTimeout),
      });
    } catch (err) {
      throw new DiscoveryError(`OIDC discovery endpoint unreachable: ${url}`, { cause: err });
    }

    if (!resp.ok) {
      throw new DiscoveryError(`OIDC discovery returned HTTP ${resp.status}`);
    }

    let doc: OidcConfiguration;
    try {
      doc = (await resp.json()) as OidcConfiguration;
    } catch (err) {
      throw new DiscoveryError(`OIDC discovery returned invalid JSON`, {
        cause: err,
      });
    }

    if (!doc.jwks_uri) {
      throw new DiscoveryError("OIDC discovery document is missing required field: jwks_uri");
    }

    this._discovery = doc;
    return doc;
  }

  /**
   * Returns a {@link JwksClient} bound to the `jwks_uri` discovered from
   * the OIDC configuration. The client is created once and reused.
   */
  async jwksClient(): Promise<JwksClient> {
    if (this._jwksClient) return this._jwksClient;
    const doc = await this.discover();
    this._jwksClient = new JwksClient({
      jwksUri: doc.jwks_uri,
      // Pin iss/aud on the client itself, so a caller who reaches for the
      // exported JwksClient still gets them checked.
      issuer: this.issuerUrl,
      audience: this.audience,
      ttl: this.jwksTtl,
      httpTimeout: this.httpTimeout,
    });
    return this._jwksClient;
  }

  /**
   * Returns an {@link IntrospectionClient} bound to the introspection
   * endpoint. The endpoint is taken from `introspectionEndpoint` config
   * (if provided) or from the OIDC discovery document.
   *
   * Throws {@link ConfigurationError} when:
   * - `clientId` or `clientSecret` are absent (required for introspection)
   * - No introspection endpoint is configured or discoverable
   */
  async introspectionClient(): Promise<IntrospectionClient> {
    if (this._introspectionClient) return this._introspectionClient;

    if (!this.clientId || !this.clientSecret) {
      throw new ConfigurationError(
        "clientId and clientSecret are required for token introspection",
      );
    }

    const endpoint =
      this.introspectionEndpointOverride ?? (await this.discover()).introspection_endpoint;

    if (!endpoint) {
      throw new ConfigurationError(
        "introspection_endpoint is not present in the OIDC discovery document " +
          "and no introspectionEndpoint override was provided in config",
      );
    }

    this._introspectionClient = new IntrospectionClient({
      introspectionEndpoint: endpoint,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      httpTimeout: this.httpTimeout,
    });
    return this._introspectionClient;
  }

  /**
   * Calls `POST {issuerUrl}/oauth/authorize` to get a per-request permission
   * decision for the given bearer token (Decision mode, HEA-922).
   *
   * Requires `realmId` in config. Fail-closed: returns `false` on any network
   * or server error so authorization cannot be accidentally granted.
   *
   * @throws {@link ConfigurationError} when `realmId` is not configured.
   */
  async authorize(
    token: string,
    permission: string,
    opts?: AuthorizePermissionOptions,
  ): Promise<boolean> {
    if (!this.realmId) {
      throw new ConfigurationError("realmId is required for authorize()");
    }
    const body: Record<string, string> = { permission };
    if (opts?.organizationId) body["organization_id"] = opts.organizationId;
    if (opts?.resource) body["resource"] = opts.resource;

    try {
      const resp = await fetch(`${this.issuerUrl}/oauth/authorize`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Realm-ID": this.realmId,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.httpTimeout),
      });
      if (!resp.ok) return false;
      const data = (await resp.json()) as { allowed?: boolean };
      return data.allowed === true;
    } catch {
      return false; // fail-closed on network/timeout errors
    }
  }

  /**
   * Introspects a token via RFC 7662 and optionally validates the echoed
   * `mode` field against `expectedMode` from config.
   *
   * Throws {@link AuthorizationModeMismatchError} when `expectedMode` is set
   * and the server echoes a different mode. This catches misconfigured
   * deployments where the resource server and the issuing client disagree on
   * the permission delivery strategy.
   *
   * @param tokenTypeHint - Optional RFC 7662 `token_type_hint`.
   * @throws {@link ConfigurationError} when `clientId`/`clientSecret` are absent.
   * @throws {@link IntrospectionError} when the introspection request fails.
   * @throws {@link AuthorizationModeMismatchError} on mode echo mismatch.
   */
  async introspect(
    token: string,
    tokenTypeHint?: "access_token" | "refresh_token",
  ): Promise<IntrospectionResult> {
    const ic = await this.introspectionClient();
    const result = await ic.introspect(token, tokenTypeHint);
    if (
      this.expectedMode !== undefined &&
      result.mode !== undefined &&
      result.mode !== this.expectedMode
    ) {
      throw new AuthorizationModeMismatchError(this.expectedMode, String(result.mode));
    }
    return result;
  }

  // ── §2 — Token Verification (EdDSA/Ed25519) ─────────────────────────────

  /**
   * Verify a JWT using JWKS-backed EdDSA/Ed25519 local signature verification (spec §2).
   *
   * Performs all mandatory validation steps in order:
   * 1. Signature against the JWKS endpoint (EdDSA/OKP/Ed25519 only). This
   *    verifies access tokens, which Hearth signs with EdDSA alone. A realm
   *    JWKS may also publish an RS256 key, but only for ID tokens of clients
   *    that registered `id_token_signed_response_alg: RS256`; RS256 (and ES256)
   *    tokens are refused here even when their key is published.
   * 2. `exp` claim (rejects expired tokens).
   * 3. `nbf` claim (rejects post-dated tokens).
   * 4. `iss` claim (must match configured `issuerUrl`).
   * 5. `aud` claim (must contain the configured `audience`, default `"hearth"`).
   * 6. `iat` claim (rejects a token issued in the future).
   *
   * `exp`, `nbf` and `iat` allow a 5-second clock skew.
   *
   * @throws {@link TokenExpiredError} — token is expired.
   * @throws {@link TokenNotYetValidError} — `nbf` or `iat` is in the future.
   * @throws {@link TokenInvalidError} — signature invalid or JWT malformed.
   * @throws {@link TokenIssuerError} — issuer does not match `issuerUrl`.
   * @throws {@link TokenAudienceError} — audience does not include `audience`.
   * @throws {@link JWKSFetchError} — JWKS endpoint unreachable.
   */
  async verifyToken(token: string): Promise<Claims> {
    const jc = await this.jwksClient();
    return jc.verify(token, {
      issuer: this.issuerUrl,
      audience: this.audience,
    });
  }

  // ── §4.5 — OAuth Flows ───────────────────────────────────────────────────

  /**
   * Begin an authorization-code login with PKCE.
   *
   * Generates a code verifier and a `state` value and builds the URL of the
   * discovered `authorization_endpoint`. Store `state` and `codeVerifier` in the
   * server-side session, redirect the browser to `authorizationUrl`, then call
   * {@link completeLogin} on the callback route.
   *
   * @param redirectUri - Callback URL registered for this client.
   * @param scope - Space-delimited scopes. Default: `"openid"`.
   * @throws {@link ConfigurationError} when `clientId` is absent or discovery has
   *   no `authorization_endpoint`.
   */
  async beginLogin(redirectUri: string, scope = "openid"): Promise<LoginBeginResult> {
    const clientId = this.requireClientId("beginLogin");
    const authorizationEndpoint = await this.endpoint("authorization_endpoint");
    const codeVerifier = generateCodeVerifier();
    const { url, state } = buildAuthorizationUrl({
      authorizationEndpoint,
      clientId,
      redirectUri,
      codeChallenge: await generateCodeChallenge(codeVerifier),
      scope,
    });
    return { authorizationUrl: url, state, codeVerifier };
  }

  /**
   * Complete an authorization-code login: exchange the callback `code` for
   * tokens. Check the callback's `state` against the stored one first.
   *
   * @param code - The `code` query parameter from the callback URL.
   * @param codeVerifier - The verifier returned by {@link beginLogin}.
   * @param redirectUri - The same redirect URI passed to {@link beginLogin}.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async completeLogin(
    code: string,
    codeVerifier: string,
    redirectUri: string,
  ): Promise<TokenResponse> {
    return this.exchangeCode(code, redirectUri, { codeVerifier });
  }

  /**
   * Exchange an authorization code for tokens (RFC 6749 §4.1.3).
   *
   * Posts to the discovered `token_endpoint` as
   * `application/x-www-form-urlencoded`. `client_secret` is sent only when
   * configured, so public clients use PKCE alone.
   *
   * @param code - Authorization code from the callback URL.
   * @param redirectUri - The redirect URI used in the authorization request.
   * @param opts - `codeVerifier` for PKCE-protected flows.
   * @throws {@link ConfigurationError} when `clientId` is absent.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    opts?: ExchangeCodeOptions,
  ): Promise<TokenResponse> {
    const params: Record<string, string> = {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      ...this.clientAuthParams("exchangeCode"),
    };
    if (opts?.codeVerifier) params.code_verifier = opts.codeVerifier;
    return this.postForm<TokenResponse>(await this.endpoint("token_endpoint"), params);
  }

  /**
   * Exchange a refresh token for new tokens (RFC 6749 §6).
   *
   * The response may carry a rotated `refresh_token`; store it in place of the
   * old one when present.
   *
   * @param refreshToken - Refresh token previously issued to this client.
   * @param scope - Optional space-delimited scopes (must not widen the grant).
   * @throws {@link ConfigurationError} when `clientId` is absent.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async refreshTokens(refreshToken: string, scope?: string): Promise<TokenResponse> {
    const params: Record<string, string> = {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      ...this.clientAuthParams("refreshTokens"),
    };
    if (scope !== undefined) params.scope = scope;
    return this.postForm<TokenResponse>(await this.endpoint("token_endpoint"), params);
  }

  /**
   * Obtain a token via the Client Credentials grant (RFC 6749 §4.4).
   *
   * Sends `client_id` and `client_secret` as `application/x-www-form-urlencoded`
   * body fields — NEVER as URL query parameters. The token endpoint is discovered
   * from the OIDC discovery document.
   *
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async clientCredentials(scope?: string): Promise<TokenResponse> {
    const params: Record<string, string> = {
      grant_type: "client_credentials",
      client_id: this.clientId ?? "",
      client_secret: this.clientSecret ?? "",
    };
    if (scope !== undefined) params.scope = scope;
    return this.postForm<TokenResponse>(await this.endpoint("token_endpoint"), params);
  }

  /**
   * Begin a Device Authorization Flow (RFC 8628 §3.1).
   *
   * Returns the `device_code`, `user_code`, `verification_uri`, and polling `interval`.
   * Pass the returned `device_code` and `interval` to `pollDeviceToken()` to await approval.
   *
   * @throws {@link ConfigurationError} when `device_authorization_endpoint` is absent.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async startDeviceFlow(scope?: string): Promise<DeviceAuthorizationResponse> {
    const params: Record<string, string> = { client_id: this.clientId ?? "" };
    if (scope !== undefined) params.scope = scope;
    return this.postForm<DeviceAuthorizationResponse>(
      await this.endpoint("device_authorization_endpoint"),
      params,
    );
  }

  /**
   * Poll the token endpoint until the device flow completes (RFC 8628 §3.5).
   *
   * Handles `authorization_pending` by continuing to poll transparently.
   * Handles `slow_down` by increasing the interval by 5 s per occurrence.
   * Throws `TokenExpiredError` when the device code expires (`expired_token`).
   *
   * @param deviceCode - The `device_code` from `startDeviceFlow()`.
   * @param intervalSeconds - Initial polling interval (from `startDeviceFlow().interval`).
   * @throws {@link TokenExpiredError} — device code has expired.
   * @throws {@link OAuthFlowError} — non-recoverable error from the server, or a network failure.
   */
  async pollDeviceToken(deviceCode: string, intervalSeconds: number): Promise<TokenResponse> {
    const tokenEndpoint = await this.endpoint("token_endpoint");
    let currentIntervalMs = intervalSeconds * 1000;

    // Use while(true) + await-setTimeout so Vitest fake timers can control polling in tests.
    while (true) {
      await new Promise<void>((res) => setTimeout(res, currentIntervalMs));

      try {
        return await this.postForm<TokenResponse>(tokenEndpoint, {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceCode,
          client_id: this.clientId ?? "",
        });
      } catch (err) {
        if (!(err instanceof OAuthFlowError)) throw err;
        if (err.errorCode === "authorization_pending") continue;
        if (err.errorCode === "slow_down") {
          currentIntervalMs += 5000;
          continue;
        }
        if (err.errorCode === "expired_token") throw new TokenExpiredError(new Date());
        throw err;
      }
    }
  }

  /**
   * Request a magic-link / passwordless authentication email (spec §4.5.3).
   *
   * Always resolves silently on HTTP 202 — per enumeration-resistance requirements,
   * the server always returns 202 whether or not the email is registered.
   * HTTP 429 (rate limit) and other non-2xx responses throw `OAuthFlowError`.
   *
   * Requires `realmId` in `HearthClientConfig`.
   *
   * @throws {@link ConfigurationError} when `realmId` is absent.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async requestMagicLink(email: string): Promise<void> {
    if (!this.realmId) {
      throw new ConfigurationError("realmId is required for requestMagicLink");
    }
    const resp = await this.send(`${this.issuerUrl}/v1/${this.realmId}/auth/magic-link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (!resp.ok) throw await oauthFlowError(resp);
  }

  /**
   * Exchange a magic-link token for tokens (spec §4.5.3 / §7.2 C-12).
   *
   * Completes the passwordless flow started by {@link requestMagicLink}: posts
   * `grant_type=urn:hearth:grant-type:magic-link` with the opaque `token` from
   * the magic-link URL to the discovered token endpoint. The `token` is sent in
   * the body, never the URL.
   *
   * @param token - The opaque magic-link token from the email/redirect URL.
   * @throws {@link OAuthFlowError} on any non-2xx response (e.g. expired/used token).
   */
  async exchangeMagicLink(token: string): Promise<TokenResponse> {
    const params: Record<string, string> = {
      grant_type: "urn:hearth:grant-type:magic-link",
      token,
    };
    if (this.clientId) params.client_id = this.clientId;
    return this.postForm<TokenResponse>(await this.endpoint("token_endpoint"), params);
  }

  // ── UserInfo, live permissions and the session-version feed ─────────────

  /**
   * Fetch the OIDC userinfo claims for an access token from the discovered
   * `userinfo_endpoint`. Sends `X-Realm-ID` when `realmId` is configured.
   *
   * @throws {@link ConfigurationError} when discovery has no `userinfo_endpoint`.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async userinfo(accessToken: string): Promise<UserInfoResponse> {
    const endpoint = await this.endpoint("userinfo_endpoint");
    return this.getRequired<UserInfoResponse>(endpoint, accessToken);
  }

  /**
   * Fetch the user's current roles, groups and permissions from
   * `GET /v1/me/permissions`. Unlike the claims in the JWT, which are fixed
   * when the token is issued, this reflects assignments made since.
   *
   * @throws {@link ConfigurationError} when `realmId` is absent.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async mePermissions(accessToken: string): Promise<MePermissionsResponse> {
    this.requireRealmId("mePermissions");
    const url = `${this.issuerUrl}/v1/me/permissions`;
    return this.getRequired<MePermissionsResponse>(url, accessToken);
  }

  /**
   * Fetch the full session-version snapshot (RFC HEA-930): every
   * `{sessionId → minSv}` pair in the realm. Use it to seed a cache, then
   * follow {@link svDelta} from `current_seq`. {@link SessionVersionCache} does
   * both for you.
   *
   * @param serviceToken - Token with the `hearth.sv_feed` scope.
   * @throws {@link ConfigurationError} when `realmId` is absent.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async svSnapshot(serviceToken: string): Promise<SvSnapshotResponse> {
    this.requireRealmId("svSnapshot");
    const url = `${this.issuerUrl}/oauth/session-versions/snapshot`;
    return this.getRequired<SvSnapshotResponse>(url, serviceToken);
  }

  /**
   * Fetch session-version changes with `seq > since` (RFC HEA-930).
   *
   * @param serviceToken - Token with the `hearth.sv_feed` scope.
   * @param since - Return only events after this sequence number.
   * @param limit - Maximum number of entries (server default when omitted).
   * @returns The deltas, or `null` when there are none (HTTP 204).
   * @throws {@link ConfigurationError} when `realmId` is absent.
   * @throws {@link OAuthFlowError} on a non-2xx response or a network failure.
   */
  async svDelta(
    serviceToken: string,
    since: number,
    limit?: number,
  ): Promise<SvDeltaResponse | null> {
    this.requireRealmId("svDelta");
    const url = new URL(`${this.issuerUrl}/oauth/session-versions`);
    url.searchParams.set("since", String(since));
    if (limit !== undefined) url.searchParams.set("limit", String(limit));
    return this.getWithBearer<SvDeltaResponse>(url.toString(), serviceToken);
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private requireClientId(method: string): string {
    if (!this.clientId) throw new ConfigurationError(`clientId is required for ${method}()`);
    return this.clientId;
  }

  private requireRealmId(method: string): string {
    if (!this.realmId) throw new ConfigurationError(`realmId is required for ${method}()`);
    return this.realmId;
  }

  /** `client_id`, plus `client_secret` when this is a confidential client. */
  private clientAuthParams(method: string): Record<string, string> {
    const params: Record<string, string> = { client_id: this.requireClientId(method) };
    if (this.clientSecret) params.client_secret = this.clientSecret;
    return params;
  }

  /** Read an endpoint URL from the discovery document. */
  private async endpoint(field: EndpointField): Promise<string> {
    const value = (await this.discover())[field];
    if (typeof value !== "string" || value === "") {
      throw new ConfigurationError(`${field} not found in OIDC discovery document`);
    }
    return value;
  }

  /** `fetch` with the configured timeout; a network failure becomes `OAuthFlowError(0)`. */
  private async send(url: string, init: RequestInit): Promise<Response> {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(this.httpTimeout) });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new OAuthFlowError(0, "request_failed", `Request to ${url} failed: ${detail}`);
    }
  }

  private async postForm<T>(endpoint: string, params: Record<string, string>): Promise<T> {
    const resp = await this.send(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params).toString(),
    });
    if (!resp.ok) throw await oauthFlowError(resp);
    return resp.json() as Promise<T>;
  }

  /** GET with a bearer token, for endpoints that must return a body. */
  private async getRequired<T>(url: string, token: string): Promise<T> {
    const result = await this.getWithBearer<T>(url, token);
    if (result === null) {
      throw new OAuthFlowError(204, "no_content", `${url} answered 204 No Content`);
    }
    return result;
  }

  /** GET with a bearer token; `null` on 204 No Content. */
  private async getWithBearer<T>(url: string, token: string): Promise<T | null> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
    if (this.realmId) headers["X-Realm-ID"] = this.realmId;
    const resp = await this.send(url, { headers });
    if (resp.status === 204) return null;
    if (!resp.ok) throw await oauthFlowError(resp);
    return resp.json() as Promise<T>;
  }
}

/**
 * Build an {@link OAuthFlowError} from a non-2xx response, taking `error` and
 * `error_description` from an RFC 6749 §5.2 JSON body when there is one.
 */
async function oauthFlowError(resp: Response): Promise<OAuthFlowError> {
  let errorCode = `HTTP ${resp.status}`;
  let description: string | undefined;
  try {
    const parsed = (await resp.json()) as Record<string, unknown>;
    if (typeof parsed["error"] === "string") errorCode = parsed["error"];
    if (typeof parsed["error_description"] === "string") {
      description = parsed["error_description"];
    }
  } catch {
    /* body is not JSON */
  }
  const message = `OAuth flow error ${resp.status}: ${errorCode}${description ? ` (${description})` : ""}`;
  return new OAuthFlowError(resp.status, errorCode, message);
}
