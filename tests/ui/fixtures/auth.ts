import * as fs from 'fs';
import * as path from 'path';
import { chromium } from '@playwright/test';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

// The repo root is 3 levels up from tests/ui/fixtures/
const REPO_ROOT = path.resolve(__dirname, '../../..');
const DEV_DATA_DIR =
  process.env.HEARTH_DEV_DATA_DIR ?? path.join(REPO_ROOT, 'data', 'dev');
const AUTH_DIR = path.join(__dirname, '..', '.auth');

// Fixed credentials used for every test run — stable across restarts once set up
export const ADMIN_EMAIL = 'admin@hearth.test';
export const ADMIN_PASSWORD = 'HearthTest123!';

/**
 * Performs first-time admin setup if the setup token is present, then logs in
 * via the browser form at /ui/admin/login and saves storageState to
 * .auth/admin.json so tests can reuse the session without re-authenticating.
 */
export async function setupAdminAuth(): Promise<void> {
  fs.mkdirSync(AUTH_DIR, { recursive: true });

  // Attempt one-time setup if the token file still exists (fresh dev server)
  const tokenPath = path.join(DEV_DATA_DIR, '.setup_token');
  if (fs.existsSync(tokenPath)) {
    const token = fs.readFileSync(tokenPath, 'utf-8').trim();
    try {
      const setupResp = await fetch(`${BASE_URL}/ui/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token,
          admin_email: ADMIN_EMAIL,
          admin_display_name: 'Test Admin',
          admin_password: ADMIN_PASSWORD,
        }),
        redirect: 'manual',
      });
      // 303 = success redirect; 4xx = already configured or invalid token — both OK
      if (
        setupResp.status !== 303 &&
        setupResp.status !== 302 &&
        setupResp.status >= 500
      ) {
        throw new Error(
          `Setup failed unexpectedly: HTTP ${setupResp.status}`,
        );
      }
    } catch (err) {
      if (!(err instanceof Error && err.message.includes('fetch'))) throw err;
      // Network-level error — likely server not ready yet
      throw err;
    }
  }

  // Browser login — captures the session cookies as storageState
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(`${BASE_URL}/ui/admin/login`);
  await page.fill('input[name="email"]', ADMIN_EMAIL);
  await page.fill('input[name="password"]', ADMIN_PASSWORD);

  await Promise.all([
    page.waitForURL(/\/ui(?:\/|$)/, { timeout: 15_000 }),
    page.click('button[type="submit"]'),
  ]);

  await context.storageState({ path: path.join(AUTH_DIR, 'admin.json') });
  await browser.close();
}
