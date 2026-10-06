import * as fs from 'fs';
import * as path from 'path';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const CREDENTIALS_PATH = path.join(__dirname, '..', '.auth', 'credentials.json');

export interface Credentials {
  realm_id: string;
  user_id: string;
  access_token: string;
  refresh_token: string;
  /** Base32 TOTP secret of `admin@dev.local`; returned by the first bootstrap only. */
  totp_secret?: string;
  /** Base32 TOTP secret of `admin@hearth.test`; returned by the first bootstrap only. */
  admin_totp_secret?: string;
}

/**
 * The server returns the TOTP secrets on the first bootstrap only (every realm
 * requires MFA by default). A re-bootstrap answers them empty, so keep the
 * cached ones.
 */
function keepSecrets(fresh: Credentials, cached: Credentials | null): Credentials {
  return {
    ...fresh,
    totp_secret: fresh.totp_secret || cached?.totp_secret || '',
    admin_totp_secret: fresh.admin_totp_secret || cached?.admin_totp_secret || '',
  };
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
 *      clientless session-refresh arm of /token and retries once;
 *   3. when there is no usable cache — the accounts were set up by a visit to
 *      the dev console (`/dev`), not by a first bootstrap — reads them from the
 *      dev console's JSON twin, `GET /dev/credentials`.
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
    const creds = keepSecrets((await resp.json()) as Credentials, cached);
    writeCache(creds);
    return creds;
  }

  // 401: the realm exists but we lack a valid Bearer token. Recover by
  // refreshing the cached session and retrying re-bootstrap exactly once.
  if (resp.status === 401 && cached?.refresh_token) {
    const freshAccess = await refreshAccessToken(fetchFn, cached);
    if (freshAccess) {
      resp = await callBootstrap(fetchFn, freshAccess);
      if (resp.ok) {
        const creds = keepSecrets((await resp.json()) as Credentials, cached);
        writeCache(creds);
        return creds;
      }
    }
  }

  // Still 401 with nothing usable cached: the dev console set the accounts up.
  if (resp.status === 401) {
    const dev = await fetchFn(`${BASE_URL}/dev/credentials`, { method: 'GET' });
    if (dev.ok) {
      const creds = keepSecrets((await dev.json()) as Credentials, cached);
      writeCache(creds);
      return creds;
    }
    throw new Error(
      '[bootstrap] re-bootstrap returned 401, nothing usable is cached, and ' +
        `${BASE_URL}/dev/credentials answered HTTP ${dev.status}. Run ` +
        '`make dev-reset`, restart `make dev`, and retry.',
    );
  }

  const body = await resp.text();
  throw new Error(`Bootstrap failed: HTTP ${resp.status} — ${body}`);
}
