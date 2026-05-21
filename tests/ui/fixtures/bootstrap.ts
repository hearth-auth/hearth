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

  const resp = await fetch(`${BASE_URL}/admin/bootstrap`, { method: 'POST' });

  if (resp.ok) {
    const creds = (await resp.json()) as Credentials;
    fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(creds, null, 2));
    return creds;
  }

  // 409 means the dev-realm already exists from a previous run — re-use stored creds
  if (resp.status === 409 && fs.existsSync(CREDENTIALS_PATH)) {
    return JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf-8')) as Credentials;
  }

  const body = await resp.text();
  throw new Error(`Bootstrap failed: HTTP ${resp.status} — ${body}`);
}
