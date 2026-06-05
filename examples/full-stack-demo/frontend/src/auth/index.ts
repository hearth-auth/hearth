import { HearthApiClient, startLogin as sdkStartLogin } from "@hearth/sdk";
import {
  setTokens,
  clearTokens,
  getRefreshToken,
  getIdToken,
  scheduleSilentRefresh,
} from "./session.js";

const VERIFIER_KEY = "hearth_pkce_verifier";
const STATE_KEY = "hearth_oauth_state";

export interface AuthConfig {
  clientId: string;
  redirectUri: string;
  hearthUrl: string;
  realmSlug: string;
}

/**
 * Create the Hearth auth facade used by the demo app.
 *
 * Every auth operation delegates to @hearth/sdk — no custom crypto or
 * OIDC endpoint logic. The only app-level code here is session storage
 * (where to persist the tokens) and the CSRF state check.
 */
export function createHearthAuth(client: HearthApiClient, config: AuthConfig) {
  async function refreshAccessToken(): Promise<void> {
    const refreshToken = getRefreshToken();
    if (!refreshToken) throw new Error("No refresh token stored");

    const tokens = await client.refreshTokens(config.clientId, refreshToken);

    setTokens({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token ?? refreshToken,
      id_token: tokens.id_token,
      expires_in: tokens.expires_in ?? 3600,
    });

    scheduleSilentRefresh(tokens.expires_in ?? 3600, refreshAccessToken);
  }

  return {
    /** Redirect the browser to Hearth's authorization endpoint via PKCE. */
    async startLogin(): Promise<void> {
      const { url, state, codeVerifier } = await sdkStartLogin(client, {
        clientId: config.clientId,
        redirectUri: config.redirectUri,
      });
      sessionStorage.setItem(VERIFIER_KEY, codeVerifier);
      sessionStorage.setItem(STATE_KEY, state);
      window.location.href = url;
    },

    /** Exchange the authorization code for tokens; validate CSRF state. */
    async handleCallback(_code: string, state: string): Promise<void> {
      const storedState = sessionStorage.getItem(STATE_KEY);
      const codeVerifier = sessionStorage.getItem(VERIFIER_KEY) ?? undefined;

      sessionStorage.removeItem(STATE_KEY);
      sessionStorage.removeItem(VERIFIER_KEY);

      if (storedState !== state) throw new Error("State mismatch — possible CSRF");

      const tokens = await client.handleCallback({
        callbackUrl: window.location.href,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        codeVerifier,
      });

      setTokens({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        id_token: tokens.id_token,
        expires_in: tokens.expires_in ?? 3600,
      });

      scheduleSilentRefresh(tokens.expires_in ?? 3600, refreshAccessToken);
    },

    refreshAccessToken,

    /** RP-initiated logout — clear tokens and redirect to Hearth's end_session_endpoint. */
    async logout(): Promise<void> {
      const idToken = getIdToken();
      clearTokens();

      const doc = await client.discovery().catch(() => null);
      const endSessionEndpoint =
        (doc?.["end_session_endpoint"] as string | undefined) ??
        `${config.hearthUrl}/${config.realmSlug}/oidc/logout`;

      const params = new URLSearchParams({
        post_logout_redirect_uri: window.location.origin,
      });
      if (idToken) params.set("id_token_hint", idToken);

      window.location.href = `${endSessionEndpoint}?${params.toString()}`;
    },
  };
}
