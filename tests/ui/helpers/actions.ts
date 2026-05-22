import * as fs from 'fs';
import * as path from 'path';

export const AUTH_DIR = path.join(__dirname, '..', '.auth');

/** Marks a read-only, side-effect-free test. Runs in the parallel project. */
export const SAFE = '@safe';

/** Marks a test that creates or destroys real data.
 *  The `destructive` Playwright project runs these sequentially (workers: 1)
 *  to prevent fixture races.
 */
export const DESTRUCTIVE = '@destructive';

/** Absolute path to the admin browser session storageState. */
export function adminStorageState(): string {
  return path.join(AUTH_DIR, 'admin.json');
}

export interface Credentials {
  realm_id: string;
  user_id: string;
  access_token: string;
  refresh_token: string;
}

/** Read API credentials written by globalSetup (bootstrap.ts). */
export function loadCredentials(): Credentials {
  const p = path.join(AUTH_DIR, 'credentials.json');
  if (!fs.existsSync(p)) {
    throw new Error(`credentials.json not found at ${p}. Did globalSetup run?`);
  }
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as Credentials;
}
