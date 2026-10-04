import type { HearthApiClient } from "./client.js";
import { startLogin } from "./pkce.js";
import type { TokenResponse } from "./types.js";

// ── Token storage ───────────────────────────────────────────────────────────
// The access token lives in memory only. The refresh token, ID token and the
// in-flight PKCE verifier and `state` live in the configured store: by default
// `sessionStorage`, which is scoped to one tab and cleared when it closes.
// For stricter XSS isolation, keep tokens out of the page entirely with an
// HttpOnly-cookie backend-for-frontend.

/** A key/value store for the SDK's browser state. `Storage` satisfies it. */
export interface TokenStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/**
 * Where {@link createHearthAuth} keeps its state: `"sessionStorage"`
 * (default), `"localStorage"` (survives the tab closing; readable by any
 * script on the origin), `"memory"` (lost on reload or redirect), or a custom
 * {@link TokenStorage}.
 */
export type AuthStorage = "sessionStorage" | "localStorage" | "memory" | TokenStorage;

/** Default prefix of every storage key the SDK writes. */
const DEFAULT_PREFIX = "hearth_";

/** Keys earlier SDK releases wrote to `localStorage`, removed at init. */
const LEGACY_LOCAL_STORAGE_KEYS = ["hearth_refresh_token", "hearth_id_token"];

function memoryStorage(): TokenStorage {
  const data = new Map<string, string>();
  return {
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => {
      data.set(key, value);
    },
    removeItem: (key) => {
      data.delete(key);
    },
  };
}

function resolveStorage(option: AuthStorage | undefined): TokenStorage {
  if (option === undefined || option === "sessionStorage") return sessionStorage;
  if (option === "localStorage") return localStorage;
  if (option === "memory") return memoryStorage();
  return option;
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
  /**
   * Where to keep the refresh token, ID token and in-flight login state.
   * Default `"sessionStorage"`. `"memory"` does not survive the login
   * redirect, so use it only with a custom flow that stays on the page.
   */
  storage?: AuthStorage;
  /** Prefix of every storage key the SDK writes. Default `"hearth_"`. */
  storageKeyPrefix?: string;
}

/** Auth facade returned by {@link createHearthAuth}. */
export interface HearthBrowserAuth {
  /** Redirect to the authorization endpoint with a fresh PKCE challenge. */
  startLogin(): Promise<void>;
  /** Check `state`, then exchange the callback's code for tokens. */
  handleCallback(code: string, state: string): Promise<void>;
  /** Exchange the stored refresh token for a new access token. */
  refreshAccessToken(): Promise<void>;
  /** Clear the local session and redirect to the realm's end-session endpoint. */
  logout(): Promise<void>;
  /** The current access token (held in memory), or `null`. */
  getAccessToken(): string | null;
  /** The stored refresh token, or `null`. */
  getRefreshToken(): string | null;
  /** The stored ID token, or `null`. */
  getIdToken(): string | null;
  /** True iff an access token is present and not yet expired. */
  isAuthenticated(): boolean;
  /** Drop every token, and cancel the scheduled refresh. */
  clearTokens(): void;
}

/**
 * Create a browser-side Hearth auth facade backed entirely by the SDK.
 *
 * Handles the full PKCE login flow, token storage, silent refresh, and
 * RP-initiated logout. No custom crypto or OIDC endpoint logic required.
 *
 * At creation it removes the refresh and ID tokens earlier SDK releases kept
 * in `localStorage`, unless `localStorage` is the configured store and those
 * are its own keys.
 */
export function createHearthAuth(client: HearthApiClient, config: AuthConfig): HearthBrowserAuth {
  const store = resolveStorage(config.storage);
  const prefix = config.storageKeyPrefix ?? DEFAULT_PREFIX;
  const key = {
    refresh: `${prefix}refresh_token`,
    id: `${prefix}id_token`,
    verifier: `${prefix}pkce_verifier`,
    state: `${prefix}oauth_state`,
  };

  if (typeof localStorage !== "undefined") {
    const ownKeys: string[] = store === localStorage ? [key.refresh, key.id] : [];
    for (const legacy of LEGACY_LOCAL_STORAGE_KEYS) {
      if (!ownKeys.includes(legacy)) localStorage.removeItem(legacy);
    }
  }

  let accessToken: string | null = null;
  let expiresAt: number | null = null;
  let refreshTimer: ReturnType<typeof setTimeout> | null = null;

  function getRefreshToken(): string | null {
    return store.getItem(key.refresh);
  }

  function getIdToken(): string | null {
    return store.getItem(key.id);
  }

  function clearTokens(): void {
    accessToken = null;
    expiresAt = null;
    store.removeItem(key.refresh);
    store.removeItem(key.id);
    if (refreshTimer !== null) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
  }

  function storeTokens(tokens: TokenResponse, fallbackRefresh?: string): void {
    accessToken = tokens.access_token;
    expiresAt = Date.now() / 1000 + (tokens.expires_in ?? 3600);
    const rt = tokens.refresh_token ?? fallbackRefresh;
    if (rt) store.setItem(key.refresh, rt);
    if (tokens.id_token) store.setItem(key.id, tokens.id_token);
  }

  function scheduleRefresh(expiresIn: number): void {
    if (refreshTimer !== null) clearTimeout(refreshTimer);
    const delayMs = Math.max(expiresIn * 0.8, expiresIn - 60) * 1000;
    refreshTimer = setTimeout(() => {
      void refreshAccessToken().catch(() => {
        /* re-auth on next action */
      });
    }, delayMs);
  }

  async function refreshAccessToken(): Promise<void> {
    const rt = getRefreshToken();
    if (!rt) throw new Error("No refresh token stored");
    const tokens = await client.refreshTokens(config.clientId, rt);
    storeTokens(tokens, rt);
    scheduleRefresh(tokens.expires_in ?? 3600);
  }

  return {
    async startLogin(): Promise<void> {
      const { url, state, codeVerifier } = await startLogin(client, {
        clientId: config.clientId,
        redirectUri: config.redirectUri,
      });
      store.setItem(key.verifier, codeVerifier);
      store.setItem(key.state, state);
      window.location.href = url;
    },

    async handleCallback(_code: string, state: string): Promise<void> {
      const storedState = store.getItem(key.state);
      const codeVerifier = store.getItem(key.verifier) ?? undefined;
      store.removeItem(key.state);
      store.removeItem(key.verifier);
      if (storedState !== state) throw new Error("State mismatch — possible CSRF");
      const tokens = await client.handleCallback({
        callbackUrl: window.location.href,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        codeVerifier,
      });
      storeTokens(tokens);
      scheduleRefresh(tokens.expires_in ?? 3600);
    },

    refreshAccessToken,

    async logout(): Promise<void> {
      const idToken = getIdToken();
      clearTokens();
      const doc = await client.discovery().catch(() => null);
      const end =
        (doc?.["end_session_endpoint"] as string | undefined) ??
        `${config.hearthUrl}/realms/${config.realmSlug}/end_session`;
      const params = new URLSearchParams({ post_logout_redirect_uri: window.location.origin });
      if (idToken) params.set("id_token_hint", idToken);
      window.location.href = `${end}?${params}`;
    },

    getAccessToken: () => accessToken,
    getRefreshToken,
    getIdToken,
    isAuthenticated: () =>
      accessToken !== null && expiresAt !== null && Date.now() / 1000 < expiresAt,
    clearTokens,
  };
}
