import { decodeJwt } from "jose";
import { RequiredActionError } from "./errors.js";
import type {
  AuthorizeParams,
  AuthorizeResponse,
  BootstrapResponse,
  JwksDocument,
  MePermissionsResponse,
  RegisterClientParams,
  OAuthClient,
  TokenExchangeParams,
  TokenResponse,
  UserInfoResponse,
  WebAuthnRegistrationBeginResponse,
  WebAuthnRegistrationCompleteRequest,
  WebAuthnRegistrationCompleteResponse,
  WebAuthnAuthenticationBeginResponse,
  WebAuthnAuthenticationCompleteRequest,
} from "./types.js";

/** Parameters for the PKCE authorization-code callback handler (spec §7). */
export interface HandleCallbackParams {
  /** Full callback URL including query parameters (`code`, `state`, etc.). */
  callbackUrl: string;
  /** OAuth 2.0 client ID. */
  clientId: string;
  /** Redirect URI registered for this client. */
  redirectUri: string;
  /** PKCE code verifier generated during `login()` (RFC 7636). */
  codeVerifier?: string;
}

/** Error thrown when the Hearth API returns an error. */
export class HearthError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(`Hearth API error ${status}: ${JSON.stringify(body)}`);
    this.name = "HearthError";
  }
}

/** Configuration for HearthApiClient. */
export interface HearthApiClientConfig {
  baseUrl: string;
  realmId: string;
}

/**
 * Low-level Hearth HTTP API client for auth code flows, token management,
 * JWKS retrieval, and live RBAC claim resolution.
 *
 * @deprecated Use {@link HearthClient} from `hearth-client.js` as the
 * recommended entry point. This class is kept as a lower-level primitive.
 */
export class HearthApiClient {
  private readonly baseUrl: string;
  private readonly realmId: string;

  constructor(config: HearthApiClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.realmId = config.realmId;
  }

  /** POST /admin/bootstrap — create realm, admin user, tokens (dev mode only). */
  static async bootstrap(baseUrl: string): Promise<BootstrapResponse> {
    const url = `${baseUrl.replace(/\/$/, "")}/admin/bootstrap`;
    const resp = await fetch(url, { method: "POST" });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<BootstrapResponse>;
  }

  /** POST /clients — register an OAuth 2.0 client. */
  async registerClient(params: RegisterClientParams): Promise<OAuthClient> {
    return this.post("/clients", {
      client_name: params.clientName,
      redirect_uris: params.redirectUris,
    });
  }

  /** POST /authorize — initiate an authorization code flow. */
  async authorize(params: AuthorizeParams): Promise<AuthorizeResponse> {
    return this.post("/authorize", {
      client_id: params.clientId,
      redirect_uri: params.redirectUri,
      scope: params.scope,
      state: params.state,
      response_type: params.responseType ?? "code",
      user_id: params.userId,
      code_challenge: params.codeChallenge,
      code_challenge_method: params.codeChallengeMethod,
      nonce: params.nonce,
    });
  }

  /** POST /token — exchange an authorization code for tokens. */
  async exchangeCode(params: TokenExchangeParams): Promise<TokenResponse> {
    return this.post("/token", {
      client_id: params.clientId,
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    });
  }

  /**
   * Handle a PKCE authorization-code callback (spec §7).
   *
   * Extracts the `code` from `callbackUrl`, exchanges it for tokens, then
   * inspects the JWT's `token_type` claim before returning:
   *
   * - If `token_type === "required_action"`: throws {@link RequiredActionError}
   *   with `requiredActions` populated from the JWT's `required_actions` claim.
   * - If the callback URL contains `required_action_redirect_uri`: throws
   *   {@link RequiredActionError} with `redirectUri` set to that value.
   * - Otherwise: returns the token response normally.
   */
  async handleCallback(params: HandleCallbackParams): Promise<TokenResponse> {
    const url = new URL(params.callbackUrl);
    const code = url.searchParams.get("code");
    const requiredActionRedirectUri = url.searchParams.get(
      "required_action_redirect_uri",
    );

    if (!code) {
      throw new Error("handleCallback: no authorization code found in callback URL");
    }

    const tokens = await this.exchangeCode({
      clientId: params.clientId,
      code,
      redirectUri: params.redirectUri,
      codeVerifier: params.codeVerifier,
    });

    // Decode the access token to read Hearth-specific claims.
    let jwtPayload: Record<string, unknown> = {};
    try {
      jwtPayload = decodeJwt(tokens.access_token) as Record<string, unknown>;
    } catch {
      // Non-JWT access tokens (opaque) skip required-action detection.
    }

    const tokenType = jwtPayload["token_type"];
    const requiredActions = Array.isArray(jwtPayload["required_actions"])
      ? (jwtPayload["required_actions"] as string[])
      : [];

    if (tokenType === "required_action") {
      throw new RequiredActionError(
        requiredActions,
        requiredActionRedirectUri ?? undefined,
      );
    }

    if (requiredActionRedirectUri !== null) {
      throw new RequiredActionError([], requiredActionRedirectUri);
    }

    return tokens;
  }

  /** POST /token — refresh tokens using a refresh token. */
  async refreshTokens(
    clientId: string,
    refreshToken: string,
  ): Promise<TokenResponse> {
    return this.post("/token", {
      client_id: clientId,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
  }

  /**
   * GET /v1/me/permissions — fetch the freshly-resolved RBAC claim set
   * for the bearer-token user.
   *
   * Unlike `hasPermission()` on a `createHearth()` client (which reads
   * the cached set from the JWT), this call queries the server and
   * reflects any role/group assignments made since the token was issued.
   */
  async permissions(accessToken: string): Promise<MePermissionsResponse> {
    const resp = await fetch(`${this.baseUrl}/v1/me/permissions`, {
      headers: {
        "X-Realm-ID": this.realmId,
        Authorization: `Bearer ${accessToken}`,
      },
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<MePermissionsResponse>;
  }

  /** GET /userinfo — retrieve user claims using an access token. */
  async userinfo(accessToken: string): Promise<UserInfoResponse> {
    const resp = await fetch(`${this.baseUrl}/userinfo`, {
      headers: {
        "X-Realm-ID": this.realmId,
        Authorization: `Bearer ${accessToken}`,
      },
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<UserInfoResponse>;
  }

  /** GET /jwks — retrieve the JWKS document. */
  async jwks(): Promise<JwksDocument> {
    const resp = await fetch(`${this.baseUrl}/jwks`);
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<JwksDocument>;
  }

  /** GET /.well-known/openid-configuration — OIDC discovery document. */
  async discovery(): Promise<Record<string, unknown>> {
    const resp = await fetch(
      `${this.baseUrl}/.well-known/openid-configuration`,
    );
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<Record<string, unknown>>;
  }

  /** Creates an AdminClient using the given access token. */
  admin(accessToken: string): AdminClient {
    return new AdminClient(this.baseUrl, this.realmId, accessToken);
  }

  // ── WebAuthn / passkeys (C-21) ──────────────────────────────────────────
  // The begin/complete round-trips below are the portable primitive; the
  // browser glue (`navigator.credentials.create()/get()`) wraps them. The
  // browser SDK is the natural home for these ceremonies.

  /**
   * Begin a WebAuthn passkey registration ceremony.
   * Returns `PublicKeyCredentialCreationOptions` for
   * `navigator.credentials.create()`. `accessToken` is the authenticated
   * user's bearer token so the server knows who is registering the credential.
   */
  async startWebAuthnRegistration(
    accessToken: string,
  ): Promise<WebAuthnRegistrationBeginResponse> {
    return this.post("/webauthn/register/begin", {}, accessToken);
  }

  /**
   * Complete a WebAuthn passkey registration ceremony. Send the attestation
   * produced by `navigator.credentials.create()`. `accessToken` must be the
   * same token used to begin the ceremony.
   */
  async finishWebAuthnRegistration(
    accessToken: string,
    request: WebAuthnRegistrationCompleteRequest,
  ): Promise<WebAuthnRegistrationCompleteResponse> {
    return this.post("/webauthn/register/complete", request, accessToken);
  }

  /**
   * Begin a WebAuthn passkey authentication ceremony. Returns
   * `PublicKeyCredentialRequestOptions` for `navigator.credentials.get()`.
   * Omit `userId` for a discoverable-credential (resident-key) flow; when
   * provided, the server constrains `allow_credentials` to that user's passkeys.
   */
  async startWebAuthnAuthentication(
    userId?: string,
  ): Promise<WebAuthnAuthenticationBeginResponse> {
    const body = userId ? { user_id: userId } : {};
    return this.post("/webauthn/auth/begin", body);
  }

  /**
   * Complete a WebAuthn passkey authentication ceremony. Send the assertion
   * produced by `navigator.credentials.get()`. Returns a full token response on
   * success.
   */
  async finishWebAuthnAuthentication(
    request: WebAuthnAuthenticationCompleteRequest,
  ): Promise<TokenResponse> {
    return this.post("/webauthn/auth/complete", request);
  }

  private async post<T>(
    path: string,
    body: unknown,
    accessToken?: string,
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Realm-ID": this.realmId,
    };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<T>;
  }
}

// AdminClient is imported here to avoid circular deps — it's re-exported from index.
import { AdminClient } from "./admin.js";
