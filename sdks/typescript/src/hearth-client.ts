import {
  AuthorizationModeMismatchError,
  ConfigurationError,
  DiscoveryError,
  OAuthFlowError,
  TokenExpiredError,
} from "./errors.js";
import { JwksClient } from "./jwks-client.js";
import {
  IntrospectionClient,
  type IntrospectionResult,
} from "./introspection-client.js";
import type {
  AccessTokenAuthorizationMode,
  AuthorizePermissionOptions,
  DeviceAuthorizationResponse,
  TokenResponse,
} from "./types.js";
import { Claims } from "./claims.js";

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

interface OidcConfiguration {
  issuer: string;
  jwks_uri: string;
  introspection_endpoint?: string;
  [key: string]: unknown;
}

/**
 * Primary entry point for the Hearth Node.js SDK.
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
  readonly jwksTtl: number | undefined;
  readonly introspectionEndpointOverride: string | undefined;
  /** HTTP timeout in milliseconds applied to all outbound fetch calls. */
  readonly httpTimeout: number;
  /** Realm ID for realm-scoped endpoints (e.g. `/oauth/authorize`). */
  readonly realmId: string | undefined;
  /** Expected authorization mode; validated on `introspect()` when present. */
  readonly expectedMode: AccessTokenAuthorizationMode | undefined;

  private _discovery: OidcConfiguration | null = null;
  private _jwksClient: JwksClient | null = null;
  private _introspectionClient: IntrospectionClient | null = null;

  constructor(config: HearthClientConfig) {
    if (!config.issuerUrl) {
      throw new ConfigurationError("issuerUrl is required");
    }
    try {
      new URL(config.issuerUrl);
    } catch {
      throw new ConfigurationError(
        `issuerUrl "${config.issuerUrl}" is not a valid URL`,
      );
    }

    this.issuerUrl = config.issuerUrl.replace(/\/$/, "");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
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
   * Throws {@link DiscoveryError} when the endpoint is unreachable,
   * returns a non-2xx status, or returns invalid JSON.
   */
  async discover(): Promise<OidcConfiguration> {
    if (this._discovery) return this._discovery;

    const url = `${this.issuerUrl}/.well-known/openid-configuration`;
    let resp: Response;
    try {
      resp = await fetch(url, {
        signal: AbortSignal.timeout(this.httpTimeout),
      });
    } catch (err) {
      throw new DiscoveryError(
        `OIDC discovery endpoint unreachable: ${url}`,
        { cause: err },
      );
    }

    if (!resp.ok) {
      throw new DiscoveryError(
        `OIDC discovery returned HTTP ${resp.status}`,
      );
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
      throw new DiscoveryError(
        "OIDC discovery document is missing required field: jwks_uri",
      );
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
      this.introspectionEndpointOverride ??
      (await this.discover()).introspection_endpoint;

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
   * @throws {@link ConfigurationError} when `clientId`/`clientSecret` are absent.
   * @throws {@link AuthorizationModeMismatchError} on mode echo mismatch.
   */
  async introspect(token: string): Promise<IntrospectionResult> {
    const ic = await this.introspectionClient();
    const result = await ic.introspect(token);
    if (
      this.expectedMode !== undefined &&
      result.mode !== undefined &&
      result.mode !== this.expectedMode
    ) {
      throw new AuthorizationModeMismatchError(
        this.expectedMode,
        String(result.mode),
      );
    }
    return result;
  }

  // ── §2 — Token Verification (EdDSA/Ed25519) ─────────────────────────────

  /**
   * Verify a JWT using JWKS-backed EdDSA/Ed25519 local signature verification (spec §2).
   *
   * Performs all five mandatory validation steps in order:
   * 1. Signature against the JWKS endpoint (EdDSA/OKP/Ed25519 required; RS256/ES256 accepted).
   * 2. `exp` claim (rejects expired tokens).
   * 3. `iss` claim (must match configured `issuerUrl`).
   * 4. `aud` claim (validated when `clientId` is set in config).
   * 5. `iat` claim (within 60-second clock skew tolerance).
   *
   * @throws {@link TokenExpiredError} — token is expired.
   * @throws {@link TokenInvalidError} — signature invalid or JWT malformed.
   * @throws {@link TokenIssuerError} — issuer does not match `issuerUrl`.
   * @throws {@link TokenAudienceError} — audience does not include `clientId`.
   * @throws {@link JWKSFetchError} — JWKS endpoint unreachable.
   */
  async verifyToken(token: string): Promise<Claims> {
    const jc = await this.jwksClient();
    return jc.verify(token, {
      issuer: this.issuerUrl,
      audience: this.clientId,
    });
  }

  // ── §4.5 — OAuth Flows ───────────────────────────────────────────────────

  /**
   * Obtain a token via the Client Credentials grant (RFC 6749 §4.4).
   *
   * Sends `client_id` and `client_secret` as `application/x-www-form-urlencoded`
   * body fields — NEVER as URL query parameters. The token endpoint is discovered
   * from the OIDC discovery document.
   *
   * @throws {@link OAuthFlowError} on any non-2xx response.
   */
  async clientCredentials(scope?: string): Promise<TokenResponse> {
    const doc = await this.discover();
    const tokenEndpoint = (doc as Record<string, unknown>)["token_endpoint"] as string | undefined;
    if (!tokenEndpoint) {
      throw new ConfigurationError("token_endpoint not found in OIDC discovery document");
    }
    const params: Record<string, string> = {
      grant_type: "client_credentials",
      client_id: this.clientId ?? "",
      client_secret: this.clientSecret ?? "",
    };
    if (scope !== undefined) params.scope = scope;
    return this.postForm<TokenResponse>(tokenEndpoint, params);
  }

  /**
   * Begin a Device Authorization Flow (RFC 8628 §3.1).
   *
   * Returns the `device_code`, `user_code`, `verification_uri`, and polling `interval`.
   * Pass the returned `device_code` and `interval` to `pollDeviceToken()` to await approval.
   *
   * @throws {@link ConfigurationError} when `device_authorization_endpoint` is absent.
   * @throws {@link OAuthFlowError} on any non-2xx response.
   */
  async startDeviceFlow(scope?: string): Promise<DeviceAuthorizationResponse> {
    const doc = await this.discover();
    const deviceEndpoint = (doc as Record<string, unknown>)["device_authorization_endpoint"] as string | undefined;
    if (!deviceEndpoint) {
      throw new ConfigurationError(
        "device_authorization_endpoint not found in OIDC discovery document",
      );
    }
    const params: Record<string, string> = { client_id: this.clientId ?? "" };
    if (scope !== undefined) params.scope = scope;
    return this.postForm<DeviceAuthorizationResponse>(deviceEndpoint, params);
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
   * @throws {@link OAuthFlowError} — non-recoverable error from the server.
   */
  async pollDeviceToken(deviceCode: string, intervalSeconds: number): Promise<TokenResponse> {
    const doc = await this.discover();
    const tokenEndpoint = (doc as Record<string, unknown>)["token_endpoint"] as string | undefined;
    if (!tokenEndpoint) {
      throw new ConfigurationError("token_endpoint not found in OIDC discovery document");
    }
    let currentIntervalMs = intervalSeconds * 1000;

    // Use while(true) + await-setTimeout so Vitest fake timers can control polling in tests.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      await new Promise<void>((res) => setTimeout(res, currentIntervalMs));

      const body = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: this.clientId ?? "",
      }).toString();

      const resp = await fetch(tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });

      if (resp.ok) {
        return resp.json() as Promise<TokenResponse>;
      }

      let errorCode = "unknown";
      try {
        const parsed = (await resp.json()) as Record<string, unknown>;
        errorCode = typeof parsed["error"] === "string" ? parsed["error"] : "unknown";
      } catch { /* ignore parse failures */ }

      if (errorCode === "authorization_pending") {
        continue;
      } else if (errorCode === "slow_down") {
        currentIntervalMs += 5000;
        continue;
      } else if (errorCode === "expired_token") {
        throw new TokenExpiredError(new Date());
      } else {
        throw new OAuthFlowError(resp.status, errorCode);
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
   * @throws {@link OAuthFlowError} on non-2xx response.
   */
  async requestMagicLink(email: string): Promise<void> {
    if (!this.realmId) {
      throw new ConfigurationError("realmId is required for requestMagicLink");
    }
    const url = `${this.issuerUrl}/v1/${this.realmId}/auth/magic-link`;
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
      signal: AbortSignal.timeout(this.httpTimeout),
    });
    if (resp.status === 202) return;
    if (!resp.ok) {
      throw new OAuthFlowError(resp.status, `HTTP ${resp.status}`);
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private async postForm<T>(endpoint: string, params: Record<string, string>): Promise<T> {
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params).toString(),
      signal: AbortSignal.timeout(this.httpTimeout),
    });
    if (!resp.ok) {
      let errorCode = `HTTP ${resp.status}`;
      try {
        const parsed = (await resp.json()) as Record<string, unknown>;
        if (typeof parsed["error"] === "string") errorCode = parsed["error"];
      } catch { /* ignore */ }
      throw new OAuthFlowError(resp.status, errorCode);
    }
    return resp.json() as Promise<T>;
  }
}
