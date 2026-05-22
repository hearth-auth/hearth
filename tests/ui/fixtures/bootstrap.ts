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
 * Calls POST /admin/bootstrap (dev-only) to create the dev-realm + admin user.
 *
 * Returns API credentials saved to .auth/credentials.json.
 * Handles 409 (realm already exists) by returning the previously saved creds.
 * Only available when the server is started with --dev.
 */
export async function bootstrap(): Promise<Credentials> {
  fs.mkdirSync(path.dirname(CREDENTIALS_PATH), { recursive: true });

  // Always call bootstrap first — on servers that have the idempotent fix
  // (http.rs DuplicateRealmName path) this returns 200 with fresh tokens.
  const resp = await fetch(`${BASE_URL}/admin/bootstrap`, { method: 'POST' });

  if (resp.ok) {
    const creds = (await resp.json()) as Credentials;
    fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(creds, null, 2));
    return creds;
  }

  // 409: realm already exists and the server does not yet have the idempotent
  // bootstrap fix. Fall back to cached credentials — the token may be stale,
  // but seed.ts handles 401 gracefully (writes empty seed and warns).
  if (resp.status === 409 && fs.existsSync(CREDENTIALS_PATH)) {
    console.warn(
      '[bootstrap] server returned 409 (pre-idempotent build). ' +
      'Using cached credentials — seed may fail. Restart `make dev` after rebuilding to get fresh tokens.',
    );
    return JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf-8')) as Credentials;
  }

  const body = await resp.text();
  throw new Error(`Bootstrap failed: HTTP ${resp.status} — ${body}`);
}
