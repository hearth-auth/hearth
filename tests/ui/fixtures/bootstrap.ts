import * as fs from 'fs';
import * as path from 'path';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const CREDENTIALS_PATH = path.join(__dirname, '..', '.auth', 'credentials.json');

export interface Credentials {
  realm_id: string;
  user_id: string;
  access_token: string;
  refresh_token: string;
}

/**
 * Injectable dependencies — real globals by default, overridable in unit tests.
 */
export interface BootstrapDeps {
  fetchFn?: typeof fetch;
  readCache?: () => Credentials | null;
  writeCache?: (creds: Credentials) => void;
}

function defaultReadCache(): Credentials | null {
  if (!fs.existsSync(CREDENTIALS_PATH)) return null;
  try {
    return JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf-8')) as Credentials;
  } catch {
    return null;
  }
}

function defaultWriteCache(creds: Credentials): void {
  fs.mkdirSync(path.dirname(CREDENTIALS_PATH), { recursive: true });
  fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(creds, null, 2));
}

/** POST /admin/bootstrap, optionally presenting a Bearer token for re-bootstrap. */
async function callBootstrap(fetchFn: typeof fetch, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  return fetchFn(`${BASE_URL}/admin/bootstrap`, { method: 'POST', headers });
}

/**
 * Exchanges a bootstrap session refresh token for a fresh access token via the
 * clientless session-refresh arm of POST /token (grant_type=refresh_token with
 * an empty client_id — the "legacy session refresh" path preserved by HEA-1755).
 * Returns the fresh access token, or null if the refresh token is also expired.
 */
async function refreshAccessToken(
  fetchFn: typeof fetch,
  cached: Credentials,
): Promise<string | null> {
  const resp = await fetchFn(`${BASE_URL}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Realm-ID': cached.realm_id,
    },
    body: JSON.stringify({
      client_id: '',
      grant_type: 'refresh_token',
      refresh_token: cached.refresh_token,
    }),
  });
  if (!resp.ok) return null;
  const tokens = (await resp.json()) as { access_token?: string };
  return tokens.access_token ?? null;
}

/**
 * Calls POST /admin/bootstrap (dev-only) to create — or refresh tokens for —
 * the dev-realm + admin user. Returns API credentials cached to
 * .auth/credentials.json. Only available when the server is started with --dev.
 *
 * Since HEA-1670 the server requires a valid Bearer token to re-bootstrap an
 * existing dev-realm; it returns HTTP 401 (not 409) when the header is absent
 * or the presented token has expired. This fixture therefore:
 *   1. presents the cached access token (if any) so an in-TTL re-bootstrap
 *      succeeds directly, then
 *   2. on 401, mints a fresh access token from the cached refresh token via the
 *      clientless session-refresh arm of /token and retries once.
 */
export async function bootstrap(deps: BootstrapDeps = {}): Promise<Credentials> {
  const fetchFn = deps.fetchFn ?? fetch;
  const readCache = deps.readCache ?? defaultReadCache;
  const writeCache = deps.writeCache ?? defaultWriteCache;

  const cached = readCache();

  // First attempt. On a fresh dev-realm the server ignores the header and
  // returns 200; on an existing realm a still-valid cached token yields 200.
  let resp = await callBootstrap(fetchFn, cached?.access_token);
  if (resp.ok) {
    const creds = (await resp.json()) as Credentials;
    writeCache(creds);
    return creds;
  }

  // 401: the realm exists but we lack a valid Bearer token. Recover by
  // refreshing the cached session and retrying re-bootstrap exactly once.
  if (resp.status === 401 && cached?.refresh_token) {
    const freshAccess = await refreshAccessToken(fetchFn, cached);
    if (!freshAccess) {
      throw new Error(
        '[bootstrap] re-bootstrap returned 401 and the cached refresh token is ' +
          'expired/invalid. Delete tests/ui/.auth/credentials.json and restart ' +
          '`make dev` (or wipe the dev data dir) to re-bootstrap the dev-realm.',
      );
    }
    resp = await callBootstrap(fetchFn, freshAccess);
    if (resp.ok) {
      const creds = (await resp.json()) as Credentials;
      writeCache(creds);
      return creds;
    }
  }

  const body = await resp.text();
  throw new Error(`Bootstrap failed: HTTP ${resp.status} — ${body}`);
}
