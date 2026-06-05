import { HearthApiClient } from "./client.js";
import { startLogin } from "./pkce.js";
import type { TokenResponse } from "./types.js";

// ── Token store ─────────────────────────────────────────────────────────────
// Access token lives in memory only. Refresh + ID tokens survive page reloads
// via localStorage. For stricter XSS safety, swap for an HttpOnly-cookie BFF.

const REFRESH_KEY = "hearth_refresh_token";
const ID_KEY = "hearth_id_token";

let _accessToken: string | null = null;
let _expiresAt: number | null = null;
let _refreshTimer: ReturnType<typeof setTimeout> | null = null;

export function getAccessToken(): string | null { return _accessToken; }
export function getRefreshToken(): string | null { return localStorage.getItem(REFRESH_KEY); }
export function getIdToken(): string | null { return localStorage.getItem(ID_KEY); }

/** True iff an access token is present and not yet expired. */
export function isAuthenticated(): boolean {
  return _accessToken !== null && _expiresAt !== null && Date.now() / 1000 < _expiresAt;
}

export function clearTokens(): void {
  _accessToken = null;
  _expiresAt = null;
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(ID_KEY);
  if (_refreshTimer !== null) { clearTimeout(_refreshTimer); _refreshTimer = null; }
}

function storeTokens(tokens: TokenResponse, fallbackRefresh?: string): void {
  _accessToken = tokens.access_token;
  _expiresAt = Date.now() / 1000 + (tokens.expires_in ?? 3600);
  const rt = tokens.refresh_token ?? fallbackRefresh;
  if (rt) localStorage.setItem(REFRESH_KEY, rt);
  if (tokens.id_token) localStorage.setItem(ID_KEY, tokens.id_token);
}

function scheduleRefresh(expiresIn: number, doRefresh: () => Promise<void>): void {
  if (_refreshTimer !== null) clearTimeout(_refreshTimer);
  const delayMs = Math.max(expiresIn * 0.8, expiresIn - 60) * 1000;
  _refreshTimer = setTimeout(() => { void doRefresh().catch(() => { /* re-auth on next action */ }); }, delayMs);
}

// ── Auth config ──────────────────────────────────────────────────────────────

/** Configuration for {@link createHearthAuth}. */
export interface AuthConfig {
  /** OAuth 2.0 client ID. */
  clientId: string;
  /** Redirect URI registered for this client. */
  redirectUri: string;
  /** Hearth server base URL, e.g. `http://localhost:8420`. */
  hearthUrl: string;
  /** Realm name (slug), e.g. `"demo"`. */
  realmSlug: string;
}

/** Auth facade returned by {@link createHearthAuth}. */
export interface HearthBrowserAuth {
  startLogin(): Promise<void>;
  handleCallback(code: string, state: string): Promise<void>;
  refreshAccessToken(): Promise<void>;
  logout(): Promise<void>;
}

const VERIFIER_KEY = "hearth_pkce_verifier";
const STATE_KEY = "hearth_oauth_state";

/**
 * Create a browser-side Hearth auth facade backed entirely by the SDK.
 *
 * Handles the full PKCE login flow, token storage, silent refresh, and
 * RP-initiated logout. No custom crypto or OIDC endpoint logic required.
 */
export function createHearthAuth(
  client: HearthApiClient,
  config: AuthConfig,
): HearthBrowserAuth {
  async function refreshAccessToken(): Promise<void> {
    const rt = getRefreshToken();
    if (!rt) throw new Error("No refresh token stored");
    const tokens = await client.refreshTokens(config.clientId, rt);
    storeTokens(tokens, rt);
    scheduleRefresh(tokens.expires_in ?? 3600, refreshAccessToken);
  }

  return {
    async startLogin(): Promise<void> {
      const { url, state, codeVerifier } = await startLogin(client, {
        clientId: config.clientId,
        redirectUri: config.redirectUri,
      });
      sessionStorage.setItem(VERIFIER_KEY, codeVerifier);
      sessionStorage.setItem(STATE_KEY, state);
      window.location.href = url;
    },

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
      storeTokens(tokens);
      scheduleRefresh(tokens.expires_in ?? 3600, refreshAccessToken);
    },

    refreshAccessToken,

    async logout(): Promise<void> {
      const idToken = getIdToken();
      clearTokens();
      const doc = await client.discovery().catch(() => null);
      const end = (doc?.["end_session_endpoint"] as string | undefined)
        ?? `${config.hearthUrl}/${config.realmSlug}/oidc/logout`;
      const params = new URLSearchParams({ post_logout_redirect_uri: window.location.origin });
      if (idToken) params.set("id_token_hint", idToken);
      window.location.href = `${end}?${params}`;
    },
  };
}
