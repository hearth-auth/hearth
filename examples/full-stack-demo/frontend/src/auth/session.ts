// Token storage: access token in memory, refresh/id tokens in localStorage.
//
// Production note: for stricter XSS safety, replace localStorage with an
// HttpOnly-cookie BFF (Backend-For-Frontend) pattern so refresh tokens are
// never accessible to JavaScript at all.

const REFRESH_TOKEN_KEY = "hearth_refresh_token";
const ID_TOKEN_KEY = "hearth_id_token";

let _accessToken: string | null = null;
let _expiresAt: number | null = null; // Unix seconds
let _silentRefreshTimer: ReturnType<typeof setTimeout> | null = null;

export function getAccessToken(): string | null {
  return _accessToken;
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function getIdToken(): string | null {
  return localStorage.getItem(ID_TOKEN_KEY);
}

export interface TokenSet {
  access_token: string;
  refresh_token?: string | null;
  id_token?: string | null;
  expires_in: number;
}

export function setTokens(tokens: TokenSet): void {
  _accessToken = tokens.access_token;
  _expiresAt = Math.floor(Date.now() / 1000) + tokens.expires_in;

  if (tokens.refresh_token) {
    localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
  }
  if (tokens.id_token) {
    localStorage.setItem(ID_TOKEN_KEY, tokens.id_token);
  }
}

export function clearTokens(): void {
  _accessToken = null;
  _expiresAt = null;
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(ID_TOKEN_KEY);

  if (_silentRefreshTimer !== null) {
    clearTimeout(_silentRefreshTimer);
    _silentRefreshTimer = null;
  }
}

/** True iff an access token is present and not yet expired. */
export function isAuthenticated(): boolean {
  return (
    _accessToken !== null &&
    _expiresAt !== null &&
    Math.floor(Date.now() / 1000) < _expiresAt
  );
}

/**
 * Schedule a silent token refresh.
 * Fires at 80% of the token lifetime (or 60 s before expiry, whichever
 * gives more lead time).
 */
export function scheduleSilentRefresh(
  expiresIn: number,
  doRefresh: () => Promise<void>,
): void {
  if (_silentRefreshTimer !== null) {
    clearTimeout(_silentRefreshTimer);
  }
  const delayMs = Math.max(expiresIn * 0.8, expiresIn - 60) * 1000;
  _silentRefreshTimer = setTimeout(() => {
    doRefresh().catch(() => {
      // Refresh failed — user will be redirected to login on next protected action.
    });
  }, delayMs);
}
