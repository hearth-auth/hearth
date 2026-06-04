import { generateCodeVerifier, generateCodeChallenge } from "./pkce.js";
import {
  setTokens,
  clearTokens,
  getRefreshToken,
  getIdToken,
  scheduleSilentRefresh,
  type TokenSet,
} from "./session.js";

const VERIFIER_KEY = "hearth_pkce_verifier";
const STATE_KEY = "hearth_oauth_state";

export interface HearthClientConfig {
  hearthUrl: string;
  realmSlug: string;
  clientId: string;
  redirectUri: string;
}

interface OidcEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  endSessionEndpoint: string;
}

/** Auth client handling the PKCE authorization-code flow against Hearth. */
export class HearthAuthClient {
  private readonly config: HearthClientConfig;
  /** Lazily resolved; cached after first successful fetch. */
  private endpointsPromise: Promise<OidcEndpoints> | null = null;

  constructor(config: HearthClientConfig) {
    this.config = config;
  }

  private endpoints(): Promise<OidcEndpoints> {
    if (!this.endpointsPromise) {
      this.endpointsPromise = this.fetchEndpoints().catch((err) => {
        // Reset so the next call retries.
        this.endpointsPromise = null;
        throw err;
      });
    }
    return this.endpointsPromise;
  }

  private async fetchEndpoints(): Promise<OidcEndpoints> {
    const url = `${this.config.hearthUrl}/${this.config.realmSlug}/.well-known/openid-configuration`;
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`OIDC discovery failed (${resp.status}): ${url}`);
    }
    const doc = (await resp.json()) as Record<string, unknown>;
    const fallback = `${this.config.hearthUrl}/${this.config.realmSlug}/oidc/logout`;
    return {
      authorizationEndpoint: doc.authorization_endpoint as string,
      tokenEndpoint: doc.token_endpoint as string,
      endSessionEndpoint: (doc.end_session_endpoint as string | undefined) ?? fallback,
    };
  }

  /** Redirect the browser to Hearth's authorization endpoint with PKCE. */
  async startLogin(): Promise<void> {
    const endpoints = await this.endpoints();

    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    // Random state value guards against CSRF on the callback.
    const state = generateCodeVerifier();

    sessionStorage.setItem(VERIFIER_KEY, verifier);
    sessionStorage.setItem(STATE_KEY, state);

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: "openid profile email",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });

    window.location.href = `${endpoints.authorizationEndpoint}?${params.toString()}`;
  }

  /** Exchange the authorization code received on the callback for tokens. */
  async handleCallback(code: string, state: string): Promise<void> {
    const storedState = sessionStorage.getItem(STATE_KEY);
    const verifier = sessionStorage.getItem(VERIFIER_KEY);

    sessionStorage.removeItem(STATE_KEY);
    sessionStorage.removeItem(VERIFIER_KEY);

    if (!verifier) throw new Error("Missing PKCE verifier — possible replay");
    if (storedState !== state) throw new Error("State mismatch — possible CSRF");

    const endpoints = await this.endpoints();

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: verifier,
    });

    const resp = await fetch(endpoints.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!resp.ok) {
      const detail = await resp.text();
      throw new Error(`Token exchange failed (${resp.status}): ${detail}`);
    }

    const tokens = (await resp.json()) as TokenSet;
    setTokens({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token,
      expires_in: tokens.expires_in ?? 3600,
    });

    scheduleSilentRefresh(tokens.expires_in ?? 3600, () =>
      this.refreshAccessToken(),
    );
  }

  /** Use the stored refresh token to obtain a new access token silently. */
  async refreshAccessToken(): Promise<void> {
    const refreshToken = getRefreshToken();
    if (!refreshToken) throw new Error("No refresh token stored");

    const endpoints = await this.endpoints();

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });

    const resp = await fetch(endpoints.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!resp.ok) {
      clearTokens();
      throw new Error("Silent refresh failed — re-authentication required");
    }

    const tokens = (await resp.json()) as TokenSet;
    setTokens({
      access_token: tokens.access_token,
      // Rotation: server may issue a new refresh token; fall back to the old one.
      refresh_token: tokens.refresh_token ?? refreshToken,
      id_token: tokens.id_token,
      expires_in: tokens.expires_in ?? 3600,
    });

    scheduleSilentRefresh(tokens.expires_in ?? 3600, () =>
      this.refreshAccessToken(),
    );
  }

  /**
   * RP-initiated logout (OIDC Core §5).
   * Clears local tokens then redirects to Hearth's end_session_endpoint with
   * `id_token_hint` so Hearth can terminate the server-side session.
   */
  async logout(): Promise<void> {
    const idToken = getIdToken();
    clearTokens();

    const endpoints = await this.endpoints().catch(
      () =>
        ({
          endSessionEndpoint: `${this.config.hearthUrl}/${this.config.realmSlug}/oidc/logout`,
        }) as OidcEndpoints,
    );

    const params = new URLSearchParams({
      post_logout_redirect_uri: window.location.origin,
    });
    if (idToken) {
      params.set("id_token_hint", idToken);
    }

    window.location.href = `${endpoints.endSessionEndpoint}?${params.toString()}`;
  }
}
