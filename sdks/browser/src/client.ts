import { generateCodeVerifier, generateCodeChallenge, generateState } from "./pkce.js";
import { sessionStorageAdapter, type TokenStorage } from "./storage.js";
import { isExpired, parseJwtPayload, type TokenSet, type OIDCDiscovery } from "./tokens.js";
import { JwksVerifier, type JwkSetFactory } from "./jwks.js";
import { IntrospectionClient, type IntrospectionResult } from "./introspect.js";
import { VerifiedToken } from "./verified-token.js";
import {
  ConfigurationError,
  DiscoveryError,
  TokenExpiredError,
  MiddlewareError,
} from "./errors.js";

/** §11 — Timing-safe string comparison via HMAC (Web Crypto). */
async function timingSafeStringEqual(a: string, b: string): Promise<boolean> {
  if (a.length !== b.length) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const [macA, macB] = await Promise.all([
    crypto.subtle.sign("HMAC", key, enc.encode(a)),
    crypto.subtle.sign("HMAC", key, enc.encode(b)),
  ]);
  const va = new Uint8Array(macA);
  const vb = new Uint8Array(macB);
  let diff = 0;
  for (let i = 0; i < va.length; i++) diff |= va[i] ^ vb[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Account-console types (kept for backward compat)
// ---------------------------------------------------------------------------

const DEFAULT_ACCOUNT_ENDPOINTS = {
  profile: "/account/profile",
  changePassword: "/account/password",
  sessions: "/account/sessions",
  sessionById: "/account/sessions/{sessionId}",
  mfaDevices: "/account/mfa/devices",
  mfaDeviceById: "/account/mfa/devices/{deviceId}",
  dataExports: "/account/data-exports",
  dataExportById: "/account/data-exports/{exportId}",
  dataExportDownload: "/account/data-exports/{exportId}/download",
} as const;

export interface AccountEndpoints {
  profile: string;
  changePassword: string;
  sessions: string;
  sessionById: string;
  mfaDevices: string;
  mfaDeviceById: string;
  dataExports: string;
  dataExportById: string;
  dataExportDownload: string;
}

export interface UserProfile {
  sub: string;
  email?: string;
  givenName?: string;
  familyName?: string;
  fullName?: string;
  locale?: string;
  zoneinfo?: string;
  attributes?: Record<string, unknown>;
}

export interface UpdateUserProfileRequest {
  email?: string;
  givenName?: string;
  familyName?: string;
  fullName?: string;
  locale?: string;
  zoneinfo?: string;
  attributes?: Record<string, unknown>;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  logoutOtherSessions?: boolean;
}

export interface AccountSession {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
  ipAddress?: string;
  userAgent?: string;
}

export interface MfaDevice {
  id: string;
  type: string;
  name?: string;
  createdAt?: string;
  lastUsedAt?: string;
}

export interface DataExportJob {
  id: string;
  status: "queued" | "processing" | "ready" | "failed";
  createdAt: string;
  expiresAt?: string;
  downloadUrl?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// §1 — Spec-compliant configuration
// ---------------------------------------------------------------------------

export interface HearthClientConfig {
  /** OIDC issuer URL — discovery is auto-fetched from {issuer_url}/.well-known/openid-configuration */
  issuer_url: string;
  /** OAuth2 client ID */
  client_id: string;
  /** OAuth2 redirect URI for the PKCE callback */
  redirectUri: string;
  /** Requested OAuth2 scopes (default: openid profile email) */
  scopes?: string[];
  /** JWKS cache TTL in milliseconds (default 5 min, hard cap 24h) */
  jwks_ttl?: number;
  /** HTTP request timeout in milliseconds (default 10 000) */
  http_timeout?: number;
  /** Clock skew tolerance in seconds for exp/iat validation (default 60) */
  clock_skew_seconds?: number;
  /** Optional accepted audience for token verification */
  audience?: string | string[];
  /** Token storage adapter (default sessionStorage) */
  storage?: TokenStorage;
  /** Prefix for all storage keys (default "hearth") */
  storageKeyPrefix?: string;
  /** Base URL for account API endpoints (defaults to issuer_url) */
  accountApiBaseUrl?: string;
  /** Override account endpoint path templates */
  accountEndpoints?: Partial<AccountEndpoints>;
  /** Called whenever tokens are refreshed or cleared */
  onTokenChange?: (tokens: TokenSet | null) => void;
  /**
   * How the Hearth server delivers tokens from the /token endpoint.
   *
   * - `'bearer'` (default): tokens are returned in the JSON response body and
   *   stored in JS storage for use as Authorization: Bearer headers.
   * - `'cookie'`: the server delivers access and refresh tokens via HttpOnly
   *   `Set-Cookie` headers. The SDK cannot read those tokens from JS; it stores
   *   only session metadata (expiry, id_token claims) and sends all token-
   *   endpoint and account-API requests with `credentials: 'include'` so the
   *   browser transmits the cookies automatically.
   *
   * Must match the `token_delivery` setting configured for this client in
   * `hearth.yaml`.
   */
  token_delivery?: "bearer" | "cookie";

  // -------------------------------------------------------------------------
  // Testability hooks
  // -------------------------------------------------------------------------
  /** Override the JWK set factory (e.g. createLocalJWKSet in tests) */
  _jwkSetFactory?: JwkSetFactory;
}

/** Resolved config with all required fields filled in. */
interface ResolvedConfig
  extends Required<Omit<HearthClientConfig, "audience" | "_jwkSetFactory" | "accountEndpoints">> {
  audience: string[];
  accountEndpoints: Partial<AccountEndpoints>;
}

function resolveConfig(cfg: HearthClientConfig): ResolvedConfig {
  if (!cfg.issuer_url) throw new ConfigurationError("issuer_url is required");
  if (!cfg.client_id) throw new ConfigurationError("client_id is required");
  if (!cfg.redirectUri) throw new ConfigurationError("redirectUri is required");

  const audience = cfg.audience
    ? Array.isArray(cfg.audience) ? cfg.audience : [cfg.audience]
    : [];

  return {
    issuer_url: cfg.issuer_url.replace(/\/$/, ""),
    client_id: cfg.client_id,
    redirectUri: cfg.redirectUri,
    scopes: cfg.scopes ?? ["openid", "profile", "email"],
    jwks_ttl: cfg.jwks_ttl ?? 5 * 60 * 1000,
    http_timeout: cfg.http_timeout ?? 10_000,
    clock_skew_seconds: cfg.clock_skew_seconds ?? 60,
    audience,
    storage: cfg.storage ?? sessionStorageAdapter,
    storageKeyPrefix: cfg.storageKeyPrefix ?? "hearth",
    accountApiBaseUrl: cfg.accountApiBaseUrl ?? cfg.issuer_url.replace(/\/$/, ""),
    accountEndpoints: cfg.accountEndpoints ?? {},
    onTokenChange: cfg.onTokenChange ?? (() => {}),
    token_delivery: cfg.token_delivery ?? "bearer",
  };
}

// ---------------------------------------------------------------------------
// HearthClient
// ---------------------------------------------------------------------------

type BroadcastMsg = { type: "logout" } | { type: "tokens"; tokens: TokenSet };

export class HearthClient {
  private readonly cfg: ResolvedConfig;
  private discovery: OIDCDiscovery | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly verifier: JwksVerifier;
  private readonly introspectClient: IntrospectionClient;
  private channel: BroadcastChannel | null = null;

  constructor(config: HearthClientConfig) {
    this.cfg = resolveConfig(config);

    this.verifier = new JwksVerifier(
      {
        issuer_url: this.cfg.issuer_url,
        jwks_ttl: this.cfg.jwks_ttl,
        clock_skew_seconds: this.cfg.clock_skew_seconds,
        audience: this.cfg.audience,
      },
      () => this.getDiscovery(),
      config._jwkSetFactory,
    );

    this.introspectClient = new IntrospectionClient(
      this.cfg.client_id,
      () => this.getDiscovery(),
      this.cfg.http_timeout,
    );

    // §7 — Cross-tab sync via BroadcastChannel (best-effort)
    if (typeof BroadcastChannel !== "undefined") {
      try {
        this.channel = new BroadcastChannel(`${this.cfg.storageKeyPrefix}:sync`);
        this.channel.onmessage = (ev: MessageEvent<BroadcastMsg>) => {
          if (ev.data?.type === "logout") {
            this.clearTokens();
            this.cfg.onTokenChange(null);
          } else if (ev.data?.type === "tokens") {
            this.storeTokens(ev.data.tokens, false);
          }
        };
      } catch {
        // BroadcastChannel unavailable in some workers — ignore
      }
    }
  }

  // -------------------------------------------------------------------------
  // Storage key helpers
  // -------------------------------------------------------------------------

  private key(name: string): string {
    return `${this.cfg.storageKeyPrefix}:${name}`;
  }

  // -------------------------------------------------------------------------
  // §1 — OIDC Discovery
  // -------------------------------------------------------------------------

  async getDiscovery(): Promise<OIDCDiscovery> {
    if (this.discovery) return this.discovery;
    const url = `${this.cfg.issuer_url}/.well-known/openid-configuration`;
    let res: Response;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), this.cfg.http_timeout);
      res = await fetch(url, { signal: ctrl.signal });
      clearTimeout(t);
    } catch (err) {
      throw new DiscoveryError(`Discovery request failed: ${url}`, { cause: err });
    }
    if (!res.ok) {
      throw new DiscoveryError(`Discovery returned HTTP ${res.status}`);
    }
    this.discovery = await res.json() as OIDCDiscovery;
    return this.discovery;
  }

  // -------------------------------------------------------------------------
  // §2 — Token verification
  // -------------------------------------------------------------------------

  /** Verify a JWT against the JWKS. Returns a VerifiedToken with typed accessors. */
  async verifyToken(token: string): Promise<VerifiedToken> {
    return this.verifier.verifyToken(token);
  }

  /** Invalidate JWKS cache (call after receiving a 401 from a resource server). */
  invalidateJwksCache(): void {
    this.verifier.invalidateCache();
  }

  // -------------------------------------------------------------------------
  // §3 — Introspection
  // -------------------------------------------------------------------------

  /** Introspect a token per RFC 7662. */
  async introspect(token: string, hint?: "access_token" | "refresh_token"): Promise<IntrospectionResult> {
    return this.introspectClient.introspect(token, hint);
  }

  // -------------------------------------------------------------------------
  // §7 — PKCE & Browser Auth Flows
  // -------------------------------------------------------------------------

  /** Begin PKCE authorization code flow — redirects the browser. */
  async login(options: { redirectUri?: string; scopes?: string[] } = {}): Promise<void> {
    const discovery = await this.getDiscovery();
    const verifier = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const state = generateState();

    this.cfg.storage.set(this.key("pkce_verifier"), verifier);
    this.cfg.storage.set(this.key("state"), state);

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.cfg.client_id,
      redirect_uri: options.redirectUri ?? this.cfg.redirectUri,
      scope: (options.scopes ?? this.cfg.scopes).join(" "),
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });

    window.location.assign(`${discovery.authorization_endpoint}?${params}`);
  }

  /** Handle the authorization code redirect callback. Returns a VerifiedToken. */
  async handleCallback(url: string = window.location.href): Promise<VerifiedToken> {
    const parsed = new URL(url);
    const code = parsed.searchParams.get("code");
    const returnedState = parsed.searchParams.get("state");
    const error = parsed.searchParams.get("error");

    if (error) {
      throw new MiddlewareError(
        `OAuth error: ${error} — ${parsed.searchParams.get("error_description") ?? ""}`,
      );
    }
    if (!code) throw new MiddlewareError("No authorization code in callback URL");

    const storedState = this.cfg.storage.get(this.key("state"));

    // §11 — timing-safe state comparison
    const stateOk = storedState !== null && returnedState !== null &&
      await timingSafeStringEqual(storedState, returnedState);
    if (!stateOk) throw new MiddlewareError("State mismatch — possible CSRF");

    const codeVerifier = this.cfg.storage.get(this.key("pkce_verifier"));
    if (!codeVerifier) throw new MiddlewareError("Missing PKCE verifier");

    const cookieMode = this.cfg.token_delivery === "cookie";
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.cfg.redirectUri,
      client_id: this.cfg.client_id,
      code_verifier: codeVerifier,
    });

    const res = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      // Cookie mode: tokens arrive as HttpOnly Set-Cookie; credentials: include
      // allows the browser to store and later transmit those cookies.
      ...(cookieMode ? { credentials: "include" as RequestCredentials } : {}),
      body,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new MiddlewareError(
        `Token exchange failed: ${(err as Record<string, string>).error ?? res.status}`,
      );
    }

    const data = await res.json();
    const tokens = this.parseTokenResponse(data, cookieMode);

    this.cfg.storage.remove(this.key("pkce_verifier"));
    this.cfg.storage.remove(this.key("state"));
    this.storeTokens(tokens, true);
    this.scheduleRefresh(tokens);

    if (tokens.idToken) {
      try {
        return await this.verifyToken(tokens.idToken);
      } catch {
        // If JWKS is unavailable, return a VerifiedToken from the raw payload
        const payload = parseJwtPayload(tokens.idToken);
        return new VerifiedToken(payload as Record<string, unknown>, {});
      }
    }
    if (!cookieMode) {
      // Bearer mode: fall back to access token if no id_token
      return this.verifyToken(tokens.accessToken);
    }
    // Cookie mode with no id_token: return a minimal VerifiedToken from expiry
    return new VerifiedToken({ exp: Math.floor(tokens.expiresAt / 1000) }, {});
  }

  /** Silent token refresh — throws TokenExpiredError if no refresh token is available. */
  async silentRefresh(): Promise<VerifiedToken> {
    const raw = this.cfg.storage.get(this.key("tokens"));
    if (!raw) throw new TokenExpiredError(new Date(0));

    const tokens: TokenSet = JSON.parse(raw);
    const cookieMode = this.cfg.token_delivery === "cookie";

    // Bearer mode requires the refresh token to be in JS storage.
    // Cookie mode: the refresh_token HttpOnly cookie (Path=/token) is sent
    // automatically; no refresh_token parameter is needed in the request body.
    if (!cookieMode && !tokens.refreshToken) throw new TokenExpiredError(new Date(tokens.expiresAt));

    const discovery = await this.getDiscovery();
    const bodyParams: Record<string, string> = {
      grant_type: "refresh_token",
      client_id: this.cfg.client_id,
    };
    if (!cookieMode) bodyParams.refresh_token = tokens.refreshToken!;

    const body = new URLSearchParams(bodyParams);

    const res = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      ...(cookieMode ? { credentials: "include" as RequestCredentials } : {}),
      body,
    });

    if (!res.ok) {
      this.clearTokens();
      this.cfg.onTokenChange(null);
      throw new TokenExpiredError(new Date(tokens.expiresAt));
    }

    const data = await res.json();
    const newTokens = this.parseTokenResponse(data, cookieMode);
    this.storeTokens(newTokens, true);
    this.scheduleRefresh(newTokens);

    if (newTokens.idToken) {
      try {
        return await this.verifyToken(newTokens.idToken);
      } catch {
        const payload = parseJwtPayload(newTokens.idToken);
        return new VerifiedToken(payload as Record<string, unknown>, {});
      }
    }
    if (!cookieMode) {
      return this.verifyToken(newTokens.accessToken);
    }
    return new VerifiedToken({ exp: Math.floor(newTokens.expiresAt / 1000) }, {});
  }

  /** Logout: clears local tokens, broadcasts to other tabs, redirects to end_session_endpoint. */
  async logout(options: { redirectUri?: string } = {}): Promise<void> {
    const stored = this.cfg.storage.get(this.key("tokens"));
    const tokens: TokenSet | null = stored ? JSON.parse(stored) : null;

    this.clearTokens();
    this.cfg.onTokenChange(null);
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    // Broadcast logout to other tabs
    this.channel?.postMessage({ type: "logout" } satisfies BroadcastMsg);

    const discovery = await this.getDiscovery().catch(() => null);
    if (discovery?.end_session_endpoint && tokens?.idToken) {
      const params = new URLSearchParams({ id_token_hint: tokens.idToken });
      if (options.redirectUri) params.set("post_logout_redirect_uri", options.redirectUri);
      window.location.assign(`${discovery.end_session_endpoint}?${params}`);
    }
  }

  // -------------------------------------------------------------------------
  // Token helpers
  // -------------------------------------------------------------------------

  async getTokens(): Promise<TokenSet | null> {
    const raw = this.cfg.storage.get(this.key("tokens"));
    if (!raw) return null;
    const tokens: TokenSet = JSON.parse(raw);
    if (isExpired(tokens)) {
      try {
        await this.silentRefresh();
      } catch {
        return null;
      }
      const refreshed = this.cfg.storage.get(this.key("tokens"));
      return refreshed ? JSON.parse(refreshed) : null;
    }
    return tokens;
  }

  /** @deprecated Use silentRefresh() instead */
  async refresh(): Promise<TokenSet | null> {
    try {
      const vt = await this.silentRefresh();
      const raw = this.cfg.storage.get(this.key("tokens"));
      return raw ? JSON.parse(raw) : { accessToken: vt.subject(), expiresAt: Date.now() + 3600_000 };
    } catch {
      return null;
    }
  }

  getIdTokenClaims(): Record<string, unknown> | null {
    const raw = this.cfg.storage.get(this.key("tokens"));
    if (!raw) return null;
    const tokens: TokenSet = JSON.parse(raw);
    if (!tokens.idToken) return null;
    return parseJwtPayload(tokens.idToken);
  }

  // -------------------------------------------------------------------------
  // Account API (unchanged from prior implementation)
  // -------------------------------------------------------------------------

  async getProfile(): Promise<UserProfile> {
    return this.accountRequest<UserProfile>("profile", { method: "GET" });
  }

  async updateProfile(payload: UpdateUserProfileRequest): Promise<UserProfile> {
    return this.accountRequest<UserProfile>("profile", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  async changePassword(payload: ChangePasswordRequest): Promise<void> {
    await this.accountRequest<void>("changePassword", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  async listSessions(): Promise<AccountSession[]> {
    return this.accountRequest<AccountSession[]>("sessions", { method: "GET" });
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.accountRequest<void>("sessionById", {
      method: "DELETE",
      pathParams: { sessionId },
    });
  }

  async revokeOtherSessions(): Promise<void> {
    await this.accountRequest<void>("sessions", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ allExceptCurrent: true }),
    });
  }

  async listMfaDevices(): Promise<MfaDevice[]> {
    return this.accountRequest<MfaDevice[]>("mfaDevices", { method: "GET" });
  }

  async removeMfaDevice(deviceId: string): Promise<void> {
    await this.accountRequest<void>("mfaDeviceById", {
      method: "DELETE",
      pathParams: { deviceId },
    });
  }

  async createDataExport(): Promise<DataExportJob> {
    return this.accountRequest<DataExportJob>("dataExports", { method: "POST" });
  }

  async getDataExport(exportId: string): Promise<DataExportJob> {
    return this.accountRequest<DataExportJob>("dataExportById", {
      method: "GET",
      pathParams: { exportId },
    });
  }

  async downloadDataExport(exportId: string): Promise<Blob> {
    const response = await this.accountRequest<Response>("dataExportDownload", {
      method: "GET",
      pathParams: { exportId },
      rawResponse: true,
    });
    return response.blob();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private parseTokenResponse(data: Record<string, unknown>, cookieMode: boolean): TokenSet {
    const expiresIn = typeof data.expires_in === "number" ? data.expires_in : 3600;
    if (cookieMode) {
      // access_token and refresh_token are in HttpOnly cookies — not readable from JS.
      // Store only session metadata so expiry tracking and auto-refresh still work.
      return {
        accessToken: "",
        refreshToken: undefined,
        idToken: data.id_token as string | undefined,
        expiresAt: Date.now() + expiresIn * 1000,
        scope: data.scope as string | undefined,
      };
    }
    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string | undefined,
      idToken: data.id_token as string | undefined,
      expiresAt: Date.now() + expiresIn * 1000,
      scope: data.scope as string | undefined,
    };
  }

  private storeTokens(tokens: TokenSet, broadcast: boolean): void {
    this.cfg.storage.set(this.key("tokens"), JSON.stringify(tokens));
    this.cfg.onTokenChange(tokens);
    if (broadcast) {
      this.channel?.postMessage({ type: "tokens", tokens } satisfies BroadcastMsg);
    }
  }

  private clearTokens(): void {
    this.cfg.storage.remove(this.key("tokens"));
  }

  private scheduleRefresh(tokens: TokenSet): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    // Cookie mode: refresh_token is in an HttpOnly cookie so it is not stored
    // in tokens.refreshToken; still schedule a proactive refresh.
    if (!tokens.refreshToken && this.cfg.token_delivery !== "cookie") return;
    const delay = Math.max(tokens.expiresAt - Date.now() - 60_000, 0);
    this.refreshTimer = setTimeout(() => {
      this.silentRefresh().catch(() => undefined);
    }, delay);
  }

  private resolveAccountEndpoint(
    key: keyof AccountEndpoints,
    pathParams: Record<string, string> = {},
  ): string {
    const template = this.cfg.accountEndpoints[key] ?? DEFAULT_ACCOUNT_ENDPOINTS[key];
    let path = template;
    for (const [param, value] of Object.entries(pathParams)) {
      path = path.split(`{${param}}`).join(encodeURIComponent(value));
    }
    if (/\{[^}]+\}/.test(path)) {
      throw new ConfigurationError(`Missing path params for endpoint: ${key}`);
    }
    return new URL(path, this.cfg.accountApiBaseUrl).toString();
  }

  private async accountRequest<T>(
    key: keyof AccountEndpoints,
    options: {
      method: string;
      headers?: Record<string, string>;
      body?: string;
      pathParams?: Record<string, string>;
      rawResponse?: boolean;
    },
  ): Promise<T> {
    const cookieMode = this.cfg.token_delivery === "cookie";
    const tokens = await this.getTokens();

    // Cookie mode: access token is in an HttpOnly cookie — no JS-accessible value.
    // Bearer mode: require a non-empty access token from JS storage.
    if (cookieMode ? !tokens : !tokens?.accessToken) {
      throw new MiddlewareError("Authentication required");
    }

    const url = this.resolveAccountEndpoint(key, options.pathParams);
    const fetchHeaders: Record<string, string> = { ...options.headers };
    if (!cookieMode) {
      fetchHeaders.Authorization = `Bearer ${tokens!.accessToken}`;
    }

    const response = await fetch(url, {
      method: options.method,
      headers: fetchHeaders,
      ...(cookieMode ? { credentials: "include" as RequestCredentials } : {}),
      body: options.body,
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      const reason = (err as Record<string, string>).error ?? response.status.toString();
      throw new MiddlewareError(`Account request failed: ${reason}`);
    }

    if (options.rawResponse) return response as T;
    if (response.status === 204) return undefined as T;
    return response.json() as Promise<T>;
  }
}
